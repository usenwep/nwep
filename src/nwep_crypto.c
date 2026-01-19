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
#include <nwep/nwep.h>

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

int nwep_random_bytes(uint8_t *dest, size_t len) {
  if (dest == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (RAND_bytes(dest, (int)len) != 1) {
    return NWEP_ERR_CRYPTO_KEY_GEN_FAILED;
  }

  return 0;
}

int nwep_keypair_generate(nwep_keypair *kp) {
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  size_t pubkey_len = NWEP_ED25519_PUBKEY_LEN;
  size_t privkey_len = 64;
  int rv = 0;

  if (kp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(kp, 0, sizeof(*kp));

  /* Create key generation context */
  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
  if (ctx == NULL) {
    return NWEP_ERR_CRYPTO_KEY_GEN_FAILED;
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    rv = NWEP_ERR_CRYPTO_KEY_GEN_FAILED;
    goto cleanup;
  }

  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    rv = NWEP_ERR_CRYPTO_KEY_GEN_FAILED;
    goto cleanup;
  }

  /* Extract public key */
  if (EVP_PKEY_get_raw_public_key(pkey, kp->pubkey, &pubkey_len) != 1) {
    rv = NWEP_ERR_CRYPTO_KEY_GEN_FAILED;
    goto cleanup;
  }

  /* Extract private key */
  if (EVP_PKEY_get_raw_private_key(pkey, kp->privkey, &privkey_len) != 1) {
    rv = NWEP_ERR_CRYPTO_KEY_GEN_FAILED;
    goto cleanup;
  }

  /* Copy pubkey to latter half of privkey (standard Ed25519 format) */
  memcpy(kp->privkey + 32, kp->pubkey, 32);

cleanup:
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);

  if (rv != 0) {
    memset(kp, 0, sizeof(*kp));
  }

  return rv;
}

int nwep_keypair_from_seed(nwep_keypair *kp, const uint8_t seed[32]) {
  EVP_PKEY *pkey = NULL;
  size_t pubkey_len = NWEP_ED25519_PUBKEY_LEN;
  int rv = 0;

  if (kp == NULL || seed == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(kp, 0, sizeof(*kp));

  /* Create key from seed (private key) */
  pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
  if (pkey == NULL) {
    return NWEP_ERR_CRYPTO_KEY_GEN_FAILED;
  }

  /* Extract public key */
  if (EVP_PKEY_get_raw_public_key(pkey, kp->pubkey, &pubkey_len) != 1) {
    rv = NWEP_ERR_CRYPTO_KEY_GEN_FAILED;
    goto cleanup;
  }

  /* Store seed in first 32 bytes, pubkey in last 32 */
  memcpy(kp->privkey, seed, 32);
  memcpy(kp->privkey + 32, kp->pubkey, 32);

cleanup:
  EVP_PKEY_free(pkey);

  if (rv != 0) {
    memset(kp, 0, sizeof(*kp));
  }

  return rv;
}

int nwep_keypair_from_privkey(nwep_keypair *kp, const uint8_t privkey[64]) {
  EVP_PKEY *pkey = NULL;
  size_t pubkey_len = NWEP_ED25519_PUBKEY_LEN;
  int rv = 0;

  if (kp == NULL || privkey == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(kp, 0, sizeof(*kp));

  /* Create key from seed (first 32 bytes of privkey) */
  pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, privkey, 32);
  if (pkey == NULL) {
    return NWEP_ERR_CRYPTO_KEY_LOAD_FAILED;
  }

  /* Extract public key */
  if (EVP_PKEY_get_raw_public_key(pkey, kp->pubkey, &pubkey_len) != 1) {
    rv = NWEP_ERR_CRYPTO_KEY_LOAD_FAILED;
    goto cleanup;
  }

  /* Verify that derived pubkey matches stored pubkey */
  if (memcmp(kp->pubkey, privkey + 32, 32) != 0) {
    rv = NWEP_ERR_CRYPTO_INVALID_KEY;
    goto cleanup;
  }

  /* Copy full privkey */
  memcpy(kp->privkey, privkey, 64);

cleanup:
  EVP_PKEY_free(pkey);

  if (rv != 0) {
    memset(kp, 0, sizeof(*kp));
  }

  return rv;
}

void nwep_keypair_clear(nwep_keypair *kp) {
  if (kp == NULL) {
    return;
  }
  OPENSSL_cleanse(kp, sizeof(*kp));
}

int nwep_sign(uint8_t sig[64], const uint8_t *msg, size_t msglen,
              const nwep_keypair *kp) {
  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  size_t siglen = 64;
  int rv = 0;

  if (sig == NULL || msg == NULL || kp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Create key from seed */
  pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, kp->privkey, 32);
  if (pkey == NULL) {
    return NWEP_ERR_CRYPTO_SIGN_FAILED;
  }

  md_ctx = EVP_MD_CTX_new();
  if (md_ctx == NULL) {
    rv = NWEP_ERR_CRYPTO_SIGN_FAILED;
    goto cleanup;
  }

  if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) != 1) {
    rv = NWEP_ERR_CRYPTO_SIGN_FAILED;
    goto cleanup;
  }

  if (EVP_DigestSign(md_ctx, sig, &siglen, msg, msglen) != 1) {
    rv = NWEP_ERR_CRYPTO_SIGN_FAILED;
    goto cleanup;
  }

cleanup:
  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pkey);

  return rv;
}

int nwep_verify(const uint8_t sig[64], const uint8_t *msg, size_t msglen,
                const uint8_t pubkey[32]) {
  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  int rv = 0;

  if (sig == NULL || msg == NULL || pubkey == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Create public key */
  pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey, 32);
  if (pkey == NULL) {
    return NWEP_ERR_CRYPTO_VERIFY_FAILED;
  }

  md_ctx = EVP_MD_CTX_new();
  if (md_ctx == NULL) {
    rv = NWEP_ERR_CRYPTO_VERIFY_FAILED;
    goto cleanup;
  }

  if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) != 1) {
    rv = NWEP_ERR_CRYPTO_VERIFY_FAILED;
    goto cleanup;
  }

  if (EVP_DigestVerify(md_ctx, sig, 64, msg, msglen) != 1) {
    rv = NWEP_ERR_CRYPTO_INVALID_SIG;
    goto cleanup;
  }

cleanup:
  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pkey);

  return rv;
}

int nwep_challenge_generate(uint8_t challenge[32]) {
  if (challenge == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  return nwep_random_bytes(challenge, 32);
}

int nwep_challenge_sign(uint8_t response[64], const uint8_t challenge[32],
                        const nwep_keypair *kp) {
  if (response == NULL || challenge == NULL || kp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  return nwep_sign(response, challenge, 32, kp);
}

int nwep_challenge_verify(const uint8_t response[64],
                          const uint8_t challenge[32],
                          const uint8_t pubkey[32]) {
  int rv;

  if (response == NULL || challenge == NULL || pubkey == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  rv = nwep_verify(response, challenge, 32, pubkey);
  if (rv == NWEP_ERR_CRYPTO_INVALID_SIG) {
    return NWEP_ERR_CRYPTO_CHALLENGE_FAILED;
  }

  return rv;
}

/*
 * NodeID computation
 */

int nwep_nodeid_from_pubkey(nwep_nodeid *nodeid, const uint8_t pubkey[32]) {
  EVP_MD_CTX *ctx = NULL;
  static const char suffix[] = "WEB/1";
  unsigned int hash_len = NWEP_NODEID_LEN;
  int rv = 0;

  if (nodeid == NULL || pubkey == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    return NWEP_ERR_CRYPTO_HASH_FAILED;
  }

  if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
    rv = NWEP_ERR_CRYPTO_HASH_FAILED;
    goto cleanup;
  }

  if (EVP_DigestUpdate(ctx, pubkey, 32) != 1) {
    rv = NWEP_ERR_CRYPTO_HASH_FAILED;
    goto cleanup;
  }

  if (EVP_DigestUpdate(ctx, suffix, 5) != 1) {
    rv = NWEP_ERR_CRYPTO_HASH_FAILED;
    goto cleanup;
  }

  if (EVP_DigestFinal_ex(ctx, nodeid->data, &hash_len) != 1) {
    rv = NWEP_ERR_CRYPTO_HASH_FAILED;
    goto cleanup;
  }

cleanup:
  EVP_MD_CTX_free(ctx);
  return rv;
}

int nwep_nodeid_from_keypair(nwep_nodeid *nodeid, const nwep_keypair *kp) {
  if (nodeid == NULL || kp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  return nwep_nodeid_from_pubkey(nodeid, kp->pubkey);
}

int nwep_nodeid_eq(const nwep_nodeid *a, const nwep_nodeid *b) {
  if (a == NULL || b == NULL) {
    return 0;
  }

  return memcmp(a->data, b->data, NWEP_NODEID_LEN) == 0;
}

int nwep_nodeid_is_zero(const nwep_nodeid *nodeid) {
  size_t i;

  if (nodeid == NULL) {
    return 1;
  }

  for (i = 0; i < NWEP_NODEID_LEN; i++) {
    if (nodeid->data[i] != 0) {
      return 0;
    }
  }

  return 1;
}
