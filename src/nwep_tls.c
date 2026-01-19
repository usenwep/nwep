/*
 * nwep
 *
 * Copyright (c) 2026 nwep contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "nwep_internal.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * ALPN protocol identifier for WEB/1 (wire format: length byte + protocol)
 */
static const unsigned char nwep_alpn_wire[] = "\x05WEB/1";
#define NWEP_ALPN_WIRE_LEN (sizeof(nwep_alpn_wire) - 1)

/*
 * Certificate validity period: 1 year
 */
#define NWEP_CERT_VALIDITY_DAYS 365

/*
 * Certificate expiry warning threshold: 30 days
 */
#define NWEP_CERT_EXPIRY_WARNING_DAYS 30

/*
 * Clock skew tolerance: 5 minutes
 */
#define NWEP_CLOCK_SKEW_SECONDS (5 * 60)

/*
 * Internal TLS context structure
 */
typedef struct nwep_tls_ctx {
  SSL_CTX *ssl_ctx;
  EVP_PKEY *pkey;
  X509 *cert;
  nwep_keypair *keypair;
  nwep_nodeid local_nodeid;
  int is_server;
} nwep_tls_ctx;

/*
 * Convert nwep_keypair to EVP_PKEY
 */
static EVP_PKEY *keypair_to_evp_pkey(const nwep_keypair *keypair) {
  EVP_PKEY *pkey = NULL;

  if (keypair == NULL) {
    return NULL;
  }

  /*
   * Create EVP_PKEY from Ed25519 private key seed.
   * The keypair stores the 32-byte seed + 32-byte public key in privkey.
   * Ed25519 seed is always 32 bytes.
   */
  pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, keypair->privkey,
                                      32);
  if (pkey == NULL) {
    return NULL;
  }

  return pkey;
}

/*
 * Generate self-signed X.509 certificate with Ed25519 key
 */
static X509 *generate_self_signed_cert(EVP_PKEY *pkey,
                                       const nwep_nodeid *nodeid) {
  X509 *cert = NULL;
  X509_NAME *name = NULL;
  ASN1_INTEGER *serial = NULL;
  char cn[128];
  unsigned char nodeid_b58[64];
  size_t nodeid_b58_len;
  int rv;

  cert = X509_new();
  if (cert == NULL) {
    goto fail;
  }

  /* Set version to X509v3 */
  if (X509_set_version(cert, 2) != 1) {
    goto fail;
  }

  /* Set serial number (random) */
  serial = ASN1_INTEGER_new();
  if (serial == NULL) {
    goto fail;
  }

  {
    unsigned char serial_bytes[16];
    if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) {
      ASN1_INTEGER_free(serial);
      goto fail;
    }
    /* Ensure positive by clearing high bit */
    serial_bytes[0] &= 0x7F;
    BIGNUM *bn = BN_bin2bn(serial_bytes, sizeof(serial_bytes), NULL);
    if (bn == NULL) {
      ASN1_INTEGER_free(serial);
      goto fail;
    }
    BN_to_ASN1_INTEGER(bn, serial);
    BN_free(bn);
  }

  if (X509_set_serialNumber(cert, serial) != 1) {
    ASN1_INTEGER_free(serial);
    goto fail;
  }
  ASN1_INTEGER_free(serial);

  /* Set validity period */
  /* Not before: now - clock skew tolerance */
  if (X509_gmtime_adj(X509_getm_notBefore(cert), -NWEP_CLOCK_SKEW_SECONDS) ==
      NULL) {
    goto fail;
  }

  /* Not after: now + validity period */
  if (X509_gmtime_adj(X509_getm_notAfter(cert),
                      (long)NWEP_CERT_VALIDITY_DAYS * 24 * 60 * 60) == NULL) {
    goto fail;
  }

  /* Set subject and issuer (self-signed, so same) */
  name = X509_NAME_new();
  if (name == NULL) {
    goto fail;
  }

  /* Encode NodeID as Base58 for CN */
  nodeid_b58_len = sizeof(nodeid_b58);
  rv = nwep_base58_encode((char *)nodeid_b58, nodeid_b58_len, nodeid->data,
                          NWEP_NODEID_LEN);
  if (rv == 0) {
    X509_NAME_free(name);
    goto fail;
  }

  /* CN = NodeID in Base58 */
  snprintf(cn, sizeof(cn), "WEB/1 Node %s", nodeid_b58);

  if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)cn,
                                 -1, -1, 0) != 1) {
    X509_NAME_free(name);
    goto fail;
  }

  if (X509_set_subject_name(cert, name) != 1) {
    X509_NAME_free(name);
    goto fail;
  }

  if (X509_set_issuer_name(cert, name) != 1) {
    X509_NAME_free(name);
    goto fail;
  }

  X509_NAME_free(name);

  /* Set public key */
  if (X509_set_pubkey(cert, pkey) != 1) {
    goto fail;
  }

  /* Sign the certificate with our private key (Ed25519) */
  if (X509_sign(cert, pkey, NULL) == 0) {
    goto fail;
  }

  return cert;

fail:
  if (cert != NULL) {
    X509_free(cert);
  }
  return NULL;
}

/*
 * ALPN selection callback (server-side)
 */
static int alpn_select_cb(SSL *ssl, const unsigned char **out,
                          unsigned char *outlen, const unsigned char *in,
                          unsigned int inlen, void *arg) {
  (void)ssl;
  (void)arg;

  /*
   * Look for "WEB/1" in the client's ALPN list
   */
  if (SSL_select_next_proto((unsigned char **)out, outlen, nwep_alpn_wire,
                            NWEP_ALPN_WIRE_LEN, in, inlen) !=
      OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  return SSL_TLSEXT_ERR_OK;
}

/*
 * Certificate verification callback
 * We use this to extract the peer's public key for NodeID verification
 */
static int cert_verify_cb(int preverify_ok, X509_STORE_CTX *ctx) {
  /*
   * We don't rely on traditional PKI verification.
   * Instead, we verify the certificate's public key matches the expected NodeID
   * during the CONNECT/AUTHENTICATE handshake (triple-layer verification).
   *
   * For now, accept the certificate and defer to application-level verification.
   */
  (void)preverify_ok;
  (void)ctx;
  return 1;
}

/*
 * Public API: Create TLS context for server
 */
int nwep_tls_ctx_server_new(nwep_tls_ctx **pctx, nwep_keypair *keypair) {
  nwep_tls_ctx *ctx = NULL;
  int rv;

  if (pctx == NULL || keypair == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  ctx = (nwep_tls_ctx *)calloc(1, sizeof(*ctx));
  if (ctx == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  ctx->is_server = 1;
  ctx->keypair = keypair;

  /* Compute local NodeID */
  rv = nwep_nodeid_from_pubkey(&ctx->local_nodeid, keypair->pubkey);
  if (rv != 0) {
    free(ctx);
    return rv;
  }

  /* Create SSL_CTX */
  ctx->ssl_ctx = SSL_CTX_new(TLS_server_method());
  if (ctx->ssl_ctx == NULL) {
    free(ctx);
    return NWEP_ERR_NETWORK_TLS;
  }

  /* Configure for QUIC */
  rv = ngtcp2_crypto_quictls_configure_server_context(ctx->ssl_ctx);
  if (rv != 0) {
    SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
    return NWEP_ERR_NETWORK_TLS;
  }

  /* Convert keypair to EVP_PKEY */
  ctx->pkey = keypair_to_evp_pkey(keypair);
  if (ctx->pkey == NULL) {
    SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
    return NWEP_ERR_CRYPTO_INVALID_KEY;
  }

  /* Generate self-signed certificate */
  ctx->cert = generate_self_signed_cert(ctx->pkey, &ctx->local_nodeid);
  if (ctx->cert == NULL) {
    EVP_PKEY_free(ctx->pkey);
    SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
    return NWEP_ERR_CRYPTO_CERT_ERROR;
  }

  /* Set certificate and private key */
  if (SSL_CTX_use_certificate(ctx->ssl_ctx, ctx->cert) != 1) {
    X509_free(ctx->cert);
    EVP_PKEY_free(ctx->pkey);
    SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
    return NWEP_ERR_CRYPTO_CERT_ERROR;
  }

  if (SSL_CTX_use_PrivateKey(ctx->ssl_ctx, ctx->pkey) != 1) {
    X509_free(ctx->cert);
    EVP_PKEY_free(ctx->pkey);
    SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
    return NWEP_ERR_CRYPTO_INVALID_KEY;
  }

  /* Set ALPN callback */
  SSL_CTX_set_alpn_select_cb(ctx->ssl_ctx, alpn_select_cb, NULL);

  /* Set certificate verification callback (permissive) */
  SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, cert_verify_cb);

  *pctx = ctx;
  return 0;
}

/*
 * Public API: Create TLS context for client
 */
int nwep_tls_ctx_client_new(nwep_tls_ctx **pctx, nwep_keypair *keypair) {
  nwep_tls_ctx *ctx = NULL;
  int rv;

  if (pctx == NULL || keypair == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  ctx = (nwep_tls_ctx *)calloc(1, sizeof(*ctx));
  if (ctx == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  ctx->is_server = 0;
  ctx->keypair = keypair;

  /* Compute local NodeID */
  rv = nwep_nodeid_from_pubkey(&ctx->local_nodeid, keypair->pubkey);
  if (rv != 0) {
    free(ctx);
    return rv;
  }

  /* Create SSL_CTX */
  ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (ctx->ssl_ctx == NULL) {
    free(ctx);
    return NWEP_ERR_NETWORK_TLS;
  }

  /* Configure for QUIC */
  rv = ngtcp2_crypto_quictls_configure_client_context(ctx->ssl_ctx);
  if (rv != 0) {
    SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
    return NWEP_ERR_NETWORK_TLS;
  }

  /* Convert keypair to EVP_PKEY */
  ctx->pkey = keypair_to_evp_pkey(keypair);
  if (ctx->pkey == NULL) {
    SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
    return NWEP_ERR_CRYPTO_INVALID_KEY;
  }

  /* Generate self-signed certificate for client authentication */
  ctx->cert = generate_self_signed_cert(ctx->pkey, &ctx->local_nodeid);
  if (ctx->cert == NULL) {
    EVP_PKEY_free(ctx->pkey);
    SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
    return NWEP_ERR_CRYPTO_CERT_ERROR;
  }

  /* Set certificate and private key */
  if (SSL_CTX_use_certificate(ctx->ssl_ctx, ctx->cert) != 1) {
    X509_free(ctx->cert);
    EVP_PKEY_free(ctx->pkey);
    SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
    return NWEP_ERR_CRYPTO_CERT_ERROR;
  }

  if (SSL_CTX_use_PrivateKey(ctx->ssl_ctx, ctx->pkey) != 1) {
    X509_free(ctx->cert);
    EVP_PKEY_free(ctx->pkey);
    SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
    return NWEP_ERR_CRYPTO_INVALID_KEY;
  }

  /* Set ALPN */
  if (SSL_CTX_set_alpn_protos(ctx->ssl_ctx, nwep_alpn_wire,
                              NWEP_ALPN_WIRE_LEN) != 0) {
    X509_free(ctx->cert);
    EVP_PKEY_free(ctx->pkey);
    SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
    return NWEP_ERR_NETWORK_TLS;
  }

  /* Set certificate verification callback (permissive) */
  SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, cert_verify_cb);

  *pctx = ctx;
  return 0;
}

/*
 * Public API: Free TLS context
 */
void nwep_tls_ctx_free(nwep_tls_ctx *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->cert != NULL) {
    X509_free(ctx->cert);
  }

  if (ctx->pkey != NULL) {
    EVP_PKEY_free(ctx->pkey);
  }

  if (ctx->ssl_ctx != NULL) {
    SSL_CTX_free(ctx->ssl_ctx);
  }

  free(ctx);
}

/*
 * Public API: Get SSL_CTX from TLS context
 */
SSL_CTX *nwep_tls_ctx_get_ssl_ctx(nwep_tls_ctx *ctx) {
  if (ctx == NULL) {
    return NULL;
  }
  return ctx->ssl_ctx;
}

/*
 * Public API: Create SSL session from TLS context
 */
SSL *nwep_tls_new_ssl(nwep_tls_ctx *ctx) {
  SSL *ssl;

  if (ctx == NULL || ctx->ssl_ctx == NULL) {
    return NULL;
  }

  ssl = SSL_new(ctx->ssl_ctx);
  if (ssl == NULL) {
    return NULL;
  }

  return ssl;
}

/*
 * Certificate validation functions
 */

int nwep_cert_extract_pubkey(uint8_t *pubkey, size_t pubkey_len, X509 *cert) {
  EVP_PKEY *pkey = NULL;
  size_t len;

  if (pubkey == NULL || cert == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (pubkey_len < NWEP_ED25519_PUBKEY_LEN) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }

  pkey = X509_get_pubkey(cert);
  if (pkey == NULL) {
    return NWEP_ERR_CRYPTO_CERT_ERROR;
  }

  /* Verify it's an Ed25519 key */
  if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
    EVP_PKEY_free(pkey);
    return NWEP_ERR_CRYPTO_INVALID_KEY;
  }

  /* Extract raw public key */
  len = pubkey_len;
  if (EVP_PKEY_get_raw_public_key(pkey, pubkey, &len) != 1) {
    EVP_PKEY_free(pkey);
    return NWEP_ERR_CRYPTO_CERT_ERROR;
  }

  if (len != NWEP_ED25519_PUBKEY_LEN) {
    EVP_PKEY_free(pkey);
    return NWEP_ERR_CRYPTO_INVALID_KEY;
  }

  EVP_PKEY_free(pkey);
  return 0;
}

int nwep_cert_extract_pubkey_from_ssl(uint8_t *pubkey, size_t pubkey_len,
                                      SSL *ssl) {
  X509 *cert;
  int rv;

  if (ssl == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL) {
    return NWEP_ERR_CRYPTO_CERT_ERROR;
  }

  rv = nwep_cert_extract_pubkey(pubkey, pubkey_len, cert);
  X509_free(cert);

  return rv;
}

int nwep_cert_check_expiry(X509 *cert, int *days_until_expiry) {
  const ASN1_TIME *not_after;
  int day, sec;
  time_t now;

  if (cert == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  not_after = X509_get0_notAfter(cert);
  if (not_after == NULL) {
    return NWEP_ERR_CRYPTO_CERT_ERROR;
  }

  /* Check if already expired (with clock skew tolerance) */
  now = time(NULL);
  if (X509_cmp_time(not_after, &now) <= 0) {
    if (days_until_expiry != NULL) {
      *days_until_expiry = 0;
    }
    return NWEP_ERR_CRYPTO_CERT_ERROR;
  }

  /* Calculate days until expiry */
  if (days_until_expiry != NULL) {
    if (ASN1_TIME_diff(&day, &sec, NULL, not_after) == 0) {
      *days_until_expiry = -1;
    } else {
      *days_until_expiry = day;
    }
  }

  return 0;
}

int nwep_cert_needs_renewal(X509 *cert) {
  int days;
  int rv;

  rv = nwep_cert_check_expiry(cert, &days);
  if (rv != 0) {
    return 1; /* Expired or error, needs renewal */
  }

  return days <= NWEP_CERT_EXPIRY_WARNING_DAYS;
}

/*
 * Get ngtcp2_conn from SSL via app data
 */
static ngtcp2_conn *get_conn_from_ssl(ngtcp2_crypto_conn_ref *ref) {
  nwep_conn *conn = (nwep_conn *)ref->user_data;
  return conn->qconn;
}

/*
 * Initialize ngtcp2_crypto_conn_ref for a connection
 */
void nwep_tls_conn_ref_init(ngtcp2_crypto_conn_ref *ref, nwep_conn *conn) {
  if (ref == NULL || conn == NULL) {
    return;
  }
  ref->get_conn = get_conn_from_ssl;
  ref->user_data = conn;
}

/*
 * Initialize ngtcp2 crypto library
 */
int nwep_tls_init(void) {
  return ngtcp2_crypto_quictls_init();
}

/*
 * Public initialization function
 */
int nwep_init(void) {
  return nwep_tls_init();
}

/*
 * Get ngtcp2 callbacks for crypto operations
 */
void nwep_tls_set_callbacks(ngtcp2_callbacks *callbacks) {
  if (callbacks == NULL) {
    return;
  }

  callbacks->client_initial = ngtcp2_crypto_client_initial_cb;
  callbacks->recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
  callbacks->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  callbacks->encrypt = ngtcp2_crypto_encrypt_cb;
  callbacks->decrypt = ngtcp2_crypto_decrypt_cb;
  callbacks->hp_mask = ngtcp2_crypto_hp_mask_cb;
  callbacks->recv_retry = ngtcp2_crypto_recv_retry_cb;
  callbacks->update_key = ngtcp2_crypto_update_key_cb;
  callbacks->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  callbacks->delete_crypto_cipher_ctx =
      ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  callbacks->get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
  callbacks->version_negotiation = ngtcp2_crypto_version_negotiation_cb;
}
