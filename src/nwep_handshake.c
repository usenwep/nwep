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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

/* Default transcript buffer size */
#define TRANSCRIPT_INITIAL_SIZE 1024

/*
 * State string helpers
 */

const char *nwep_client_state_str(nwep_client_state state) {
  switch (state) {
  case NWEP_CLIENT_STATE_INITIAL:
    return "initial";
  case NWEP_CLIENT_STATE_TLS_HANDSHAKE:
    return "tls_handshake";
  case NWEP_CLIENT_STATE_SEND_CONNECT:
    return "send_connect";
  case NWEP_CLIENT_STATE_WAIT_CONNECT_RESP:
    return "wait_connect_resp";
  case NWEP_CLIENT_STATE_SEND_AUTHENTICATE:
    return "send_authenticate";
  case NWEP_CLIENT_STATE_WAIT_AUTH_RESP:
    return "wait_auth_resp";
  case NWEP_CLIENT_STATE_CONNECTED:
    return "connected";
  case NWEP_CLIENT_STATE_ERROR:
    return "error";
  default:
    return "unknown";
  }
}

const char *nwep_server_state_str(nwep_server_state state) {
  switch (state) {
  case NWEP_SERVER_STATE_INITIAL:
    return "initial";
  case NWEP_SERVER_STATE_TLS_HANDSHAKE:
    return "tls_handshake";
  case NWEP_SERVER_STATE_AWAITING_CONNECT:
    return "awaiting_connect";
  case NWEP_SERVER_STATE_AWAITING_CLIENT_AUTH:
    return "awaiting_client_auth";
  case NWEP_SERVER_STATE_CONNECTED:
    return "connected";
  case NWEP_SERVER_STATE_ERROR:
    return "error";
  default:
    return "unknown";
  }
}

/*
 * Handshake initialization
 */

int nwep_handshake_client_init(nwep_handshake *hs, nwep_keypair *keypair,
                               const nwep_nodeid *expected_server) {
  int rv;

  if (hs == NULL || keypair == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(hs, 0, sizeof(*hs));

  hs->local_keypair = keypair;
  hs->is_server = 0;
  hs->state.client = NWEP_CLIENT_STATE_INITIAL;

  /* Compute our NodeID */
  rv = nwep_nodeid_from_keypair(&hs->local_nodeid, keypair);
  if (rv != 0) {
    return rv;
  }

  /* Store expected server NodeID for verification */
  if (expected_server != NULL) {
    memcpy(&hs->expected_peer_nodeid, expected_server, sizeof(nwep_nodeid));
  }

  /* Generate client challenge */
  rv = nwep_challenge_generate(hs->local_challenge);
  if (rv != 0) {
    return rv;
  }

  /* Set default parameters */
  hs->local_params.max_streams = NWEP_DEFAULT_MAX_STREAMS;
  hs->local_params.max_message_size = NWEP_DEFAULT_MAX_MESSAGE_SIZE;
  hs->local_params.compression = "none";
  hs->local_params.role = NULL;

  return 0;
}

int nwep_handshake_server_init(nwep_handshake *hs, nwep_keypair *keypair) {
  int rv;

  if (hs == NULL || keypair == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(hs, 0, sizeof(*hs));

  hs->local_keypair = keypair;
  hs->is_server = 1;
  hs->state.server = NWEP_SERVER_STATE_INITIAL;

  /* Compute our NodeID */
  rv = nwep_nodeid_from_keypair(&hs->local_nodeid, keypair);
  if (rv != 0) {
    return rv;
  }

  /* Generate server challenge (will be sent in CONNECT response) */
  rv = nwep_challenge_generate(hs->local_challenge);
  if (rv != 0) {
    return rv;
  }

  /* Set default parameters */
  hs->local_params.max_streams = NWEP_DEFAULT_MAX_STREAMS;
  hs->local_params.max_message_size = NWEP_DEFAULT_MAX_MESSAGE_SIZE;
  hs->local_params.compression = "none";
  hs->local_params.role = "regular_node";

  return 0;
}

void nwep_handshake_free(nwep_handshake *hs) {
  if (hs == NULL) {
    return;
  }

  if (hs->transcript != NULL) {
    free(hs->transcript);
    hs->transcript = NULL;
  }

  hs->transcript_len = 0;
  hs->transcript_cap = 0;
}

void nwep_handshake_set_params(nwep_handshake *hs,
                               const nwep_handshake_params *params) {
  if (hs == NULL || params == NULL) {
    return;
  }

  hs->local_params = *params;
}

/*
 * Transcript building
 */

int nwep_transcript_init(nwep_handshake *hs) {
  if (hs == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (hs->transcript != NULL) {
    free(hs->transcript);
  }

  hs->transcript = (uint8_t *)malloc(TRANSCRIPT_INITIAL_SIZE);
  if (hs->transcript == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  hs->transcript_len = 0;
  hs->transcript_cap = TRANSCRIPT_INITIAL_SIZE;

  return 0;
}

static int transcript_ensure_space(nwep_handshake *hs, size_t needed) {
  size_t new_cap;
  uint8_t *new_buf;

  if (hs->transcript_len + needed <= hs->transcript_cap) {
    return 0;
  }

  new_cap = hs->transcript_cap * 2;
  while (new_cap < hs->transcript_len + needed) {
    new_cap *= 2;
  }

  new_buf = (uint8_t *)realloc(hs->transcript, new_cap);
  if (new_buf == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  hs->transcript = new_buf;
  hs->transcript_cap = new_cap;

  return 0;
}

static int transcript_write_bytes(nwep_handshake *hs, const uint8_t *data,
                                  size_t len) {
  int rv;

  rv = transcript_ensure_space(hs, len);
  if (rv != 0) {
    return rv;
  }

  memcpy(hs->transcript + hs->transcript_len, data, len);
  hs->transcript_len += len;

  return 0;
}

static int transcript_write_byte(nwep_handshake *hs, uint8_t b) {
  return transcript_write_bytes(hs, &b, 1);
}

static int transcript_write_uint32(nwep_handshake *hs, uint32_t n) {
  uint8_t buf[4];
  nwep_put_uint32be(buf, n);
  return transcript_write_bytes(hs, buf, 4);
}

static int transcript_write_string(nwep_handshake *hs, const char *s) {
  size_t len = s ? strlen(s) : 0;
  int rv;

  rv = transcript_write_uint32(hs, (uint32_t)len);
  if (rv != 0) {
    return rv;
  }

  if (len > 0) {
    rv = transcript_write_bytes(hs, (const uint8_t *)s, len);
  }

  return rv;
}

int nwep_transcript_add_connect_request(nwep_handshake *hs) {
  int rv;
  const uint8_t *pubkey;

  if (hs == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (hs->transcript == NULL) {
    rv = nwep_transcript_init(hs);
    if (rv != 0) {
      return rv;
    }
  }

  /* Request marker */
  rv = transcript_write_byte(hs, 0x01);
  if (rv != 0) {
    return rv;
  }

  /* Version */
  rv = transcript_write_string(hs, "WEB/1");
  if (rv != 0) {
    return rv;
  }

  /* Client pubkey (from whoever sent the request) */
  if (hs->is_server) {
    pubkey = hs->peer_pubkey;
  } else {
    pubkey = hs->local_keypair->pubkey;
  }

  rv = transcript_write_uint32(hs, NWEP_ED25519_PUBKEY_LEN);
  if (rv != 0) {
    return rv;
  }
  rv = transcript_write_bytes(hs, pubkey, NWEP_ED25519_PUBKEY_LEN);
  if (rv != 0) {
    return rv;
  }

  /* Client challenge (raw, no length prefix) */
  if (hs->is_server) {
    rv = transcript_write_bytes(hs, hs->peer_challenge, NWEP_CHALLENGE_LEN);
  } else {
    rv = transcript_write_bytes(hs, hs->local_challenge, NWEP_CHALLENGE_LEN);
  }
  if (rv != 0) {
    return rv;
  }

  /*
   * For the CONNECT request part of the transcript, we need to use the
   * CLIENT's params (not our local params if we're the server).
   * - On server: use peer_params (client's original request)
   * - On client: use local_params (what we sent)
   */
  const nwep_handshake_params *req_params =
      hs->is_server ? &hs->peer_params : &hs->local_params;

  /* max_streams */
  rv = transcript_write_uint32(hs, req_params->max_streams);
  if (rv != 0) {
    return rv;
  }

  /* max_message_size */
  rv = transcript_write_uint32(hs, req_params->max_message_size);
  if (rv != 0) {
    return rv;
  }

  /* compression */
  rv = transcript_write_string(hs, req_params->compression);
  if (rv != 0) {
    return rv;
  }

  /* extensions (empty for now) */
  rv = transcript_write_string(hs, "");
  if (rv != 0) {
    return rv;
  }

  /* role: flag + optional role string */
  if (req_params->role != NULL) {
    rv = transcript_write_byte(hs, 0x01);
    if (rv != 0) {
      return rv;
    }
    rv = transcript_write_string(hs, req_params->role);
  } else {
    rv = transcript_write_byte(hs, 0x00);
  }

  return rv;
}

int nwep_transcript_add_connect_response(nwep_handshake *hs) {
  int rv;
  const uint8_t *pubkey;

  if (hs == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Response marker */
  rv = transcript_write_byte(hs, 0x02);
  if (rv != 0) {
    return rv;
  }

  /* Status (1 byte: 0 = ok) */
  rv = transcript_write_byte(hs, 0x00);
  if (rv != 0) {
    return rv;
  }

  /* Server pubkey */
  if (hs->is_server) {
    pubkey = hs->local_keypair->pubkey;
  } else {
    pubkey = hs->peer_pubkey;
  }

  rv = transcript_write_uint32(hs, NWEP_ED25519_PUBKEY_LEN);
  if (rv != 0) {
    return rv;
  }
  rv = transcript_write_bytes(hs, pubkey, NWEP_ED25519_PUBKEY_LEN);
  if (rv != 0) {
    return rv;
  }

  /* Server challenge (raw, no length prefix) */
  if (hs->is_server) {
    rv = transcript_write_bytes(hs, hs->local_challenge, NWEP_CHALLENGE_LEN);
  } else {
    rv = transcript_write_bytes(hs, hs->peer_challenge, NWEP_CHALLENGE_LEN);
  }
  if (rv != 0) {
    return rv;
  }

  /* Negotiated values */
  rv = transcript_write_uint32(hs, hs->negotiated_params.max_streams);
  if (rv != 0) {
    return rv;
  }

  rv = transcript_write_uint32(hs, hs->negotiated_params.max_message_size);
  if (rv != 0) {
    return rv;
  }

  rv = transcript_write_string(hs, hs->negotiated_params.compression);
  if (rv != 0) {
    return rv;
  }

  /* extensions */
  rv = transcript_write_string(hs, "");
  if (rv != 0) {
    return rv;
  }

  /* role */
  if (hs->negotiated_params.role != NULL) {
    rv = transcript_write_byte(hs, 0x01);
    if (rv != 0) {
      return rv;
    }
    rv = transcript_write_string(hs, hs->negotiated_params.role);
  } else {
    rv = transcript_write_byte(hs, 0x00);
  }

  return rv;
}

int nwep_transcript_sign(uint8_t signature[64], const nwep_handshake *hs) {
  EVP_MD_CTX *ctx = NULL;
  uint8_t hash[32];
  unsigned int hash_len = 32;
  int rv = 0;

  if (signature == NULL || hs == NULL || hs->transcript == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Hash the transcript: SHA-256(transcript_bytes) */
  ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    return NWEP_ERR_CRYPTO_HASH_FAILED;
  }

  if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(ctx, hs->transcript, hs->transcript_len) != 1 ||
      EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
    rv = NWEP_ERR_CRYPTO_HASH_FAILED;
    goto cleanup;
  }

  /* Sign the hash */
  rv = nwep_sign(signature, hash, 32, hs->local_keypair);

cleanup:
  EVP_MD_CTX_free(ctx);
  return rv;
}

int nwep_transcript_verify(const nwep_handshake *hs,
                           const uint8_t signature[64]) {
  EVP_MD_CTX *ctx = NULL;
  uint8_t hash[32];
  unsigned int hash_len = 32;
  int rv = 0;

  if (hs == NULL || signature == NULL || hs->transcript == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Hash the transcript */
  ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    return NWEP_ERR_CRYPTO_HASH_FAILED;
  }

  if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(ctx, hs->transcript, hs->transcript_len) != 1 ||
      EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
    rv = NWEP_ERR_CRYPTO_HASH_FAILED;
    goto cleanup;
  }

  /* Verify the signature */
  rv = nwep_verify(signature, hash, 32, hs->peer_pubkey);

cleanup:
  EVP_MD_CTX_free(ctx);
  return rv;
}

/*
 * Triple-layer verification
 */

int nwep_verify_layer1(const nwep_handshake *hs, const uint8_t tls_pubkey[32]) {
  if (hs == NULL || tls_pubkey == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (memcmp(hs->peer_pubkey, tls_pubkey, 32) != 0) {
    return NWEP_ERR_CRYPTO_PUBKEY_MISMATCH;
  }

  return 0;
}

int nwep_verify_layer2(const nwep_handshake *hs) {
  nwep_nodeid derived;
  int rv;

  if (hs == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Derive NodeID from peer pubkey */
  rv = nwep_nodeid_from_pubkey(&derived, hs->peer_pubkey);
  if (rv != 0) {
    return rv;
  }

  /* Check against expected NodeID (from address) */
  if (!nwep_nodeid_is_zero(&hs->expected_peer_nodeid)) {
    if (!nwep_nodeid_eq(&derived, &hs->expected_peer_nodeid)) {
      return NWEP_ERR_CRYPTO_NODEID_MISMATCH;
    }
  }

  /* Store derived NodeID */
  memcpy((void *)&hs->peer_nodeid, &derived, sizeof(nwep_nodeid));

  return 0;
}

int nwep_verify_layer3(const nwep_handshake *hs, const uint8_t signature[64]) {
  if (hs == NULL || signature == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  return nwep_challenge_verify(signature, hs->local_challenge, hs->peer_pubkey);
}

int nwep_verify_all_layers(const nwep_handshake *hs,
                           const uint8_t tls_pubkey[32],
                           const uint8_t signature[64]) {
  int rv;

  rv = nwep_verify_layer1(hs, tls_pubkey);
  if (rv != 0) {
    return rv;
  }

  rv = nwep_verify_layer2(hs);
  if (rv != 0) {
    return rv;
  }

  rv = nwep_verify_layer3(hs, signature);
  if (rv != 0) {
    return rv;
  }

  return 0;
}

/*
 * Helper to write Base64-encoded value to buffer and set header
 */
static size_t write_base64_header(uint8_t *buf, size_t buflen, size_t *offset,
                                  nwep_header *hdr, const char *name,
                                  const uint8_t *data, size_t data_len) {
  size_t b64_len;
  char *dest;

  b64_len = nwep_base64_encode_len(data_len);
  if (*offset + b64_len > buflen) {
    return 0;
  }

  dest = (char *)(buf + *offset);
  b64_len = nwep_base64_encode(dest, buflen - *offset, data, data_len);
  if (b64_len == 0) {
    return 0;
  }

  nwep_header_set(hdr, name, dest);
  *offset += b64_len + 1; /* +1 for null terminator */

  return b64_len;
}

/*
 * CONNECT request building and parsing
 */

int nwep_connect_request_build(nwep_msg *msg, nwep_header *headers,
                               size_t max_headers, uint8_t *header_buf,
                               size_t header_buf_len, nwep_handshake *hs) {
  size_t offset = 0;
  size_t hdr_idx = 0;
  char streams_buf[16];

  if (msg == NULL || headers == NULL || header_buf == NULL || hs == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (max_headers < 6) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }

  nwep_msg_init(msg, NWEP_MSG_REQUEST);
  msg->headers = headers;

  /* :method = "connect" */
  nwep_header_set(&headers[hdr_idx++], NWEP_HDR_METHOD, NWEP_METHOD_CONNECT);

  /* :path = "/" */
  nwep_header_set(&headers[hdr_idx++], NWEP_HDR_PATH, "/");

  /* :version = "WEB/1" */
  nwep_header_set(&headers[hdr_idx++], NWEP_HDR_VERSION, NWEP_PROTO_VER);

  /* client-id = Base64(pubkey) */
  if (write_base64_header(header_buf, header_buf_len, &offset,
                          &headers[hdr_idx++], NWEP_HDR_CLIENT_ID,
                          hs->local_keypair->pubkey,
                          NWEP_ED25519_PUBKEY_LEN) == 0) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }

  /* challenge = Base64(nonce) */
  if (write_base64_header(header_buf, header_buf_len, &offset,
                          &headers[hdr_idx++], NWEP_HDR_CHALLENGE,
                          hs->local_challenge, NWEP_CHALLENGE_LEN) == 0) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }

  /* max-streams */
  snprintf(streams_buf, sizeof(streams_buf), "%u", hs->local_params.max_streams);
  /* Copy to header_buf so it persists */
  if (offset + strlen(streams_buf) + 1 > header_buf_len) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }
  strcpy((char *)(header_buf + offset), streams_buf);
  nwep_header_set(&headers[hdr_idx++], NWEP_HDR_MAX_STREAMS,
                  (const char *)(header_buf + offset));
  offset += strlen(streams_buf) + 1;

  msg->header_count = hdr_idx;

  /* Update state */
  hs->state.client = NWEP_CLIENT_STATE_WAIT_CONNECT_RESP;

  return 0;
}

int nwep_connect_request_parse(nwep_handshake *hs, const nwep_msg *msg) {
  const nwep_header *hdr;
  size_t decoded_len;

  if (hs == NULL || msg == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Verify method */
  hdr = nwep_msg_find_header(msg, NWEP_HDR_METHOD);
  if (hdr == NULL || !nwep_header_value_eq(hdr, NWEP_METHOD_CONNECT)) {
    return NWEP_ERR_PROTO_INVALID_METHOD;
  }

  /* Get client-id (pubkey) */
  hdr = nwep_msg_find_header(msg, NWEP_HDR_CLIENT_ID);
  if (hdr == NULL) {
    return NWEP_ERR_PROTO_INVALID_HEADER;
  }
  decoded_len = nwep_base64_decode_n(
      hs->peer_pubkey, NWEP_ED25519_PUBKEY_LEN,
      (const char *)hdr->value, hdr->value_len);
  if (decoded_len != NWEP_ED25519_PUBKEY_LEN) {
    return NWEP_ERR_CRYPTO_INVALID_KEY;
  }

  /* Get challenge */
  hdr = nwep_msg_find_header(msg, NWEP_HDR_CHALLENGE);
  if (hdr == NULL) {
    return NWEP_ERR_PROTO_INVALID_HEADER;
  }
  decoded_len = nwep_base64_decode_n(
      hs->peer_challenge, NWEP_CHALLENGE_LEN,
      (const char *)hdr->value, hdr->value_len);
  if (decoded_len != NWEP_CHALLENGE_LEN) {
    return NWEP_ERR_PROTO_INVALID_HEADER;
  }

  /* Get max-streams (optional, use default if missing) */
  hdr = nwep_msg_find_header(msg, NWEP_HDR_MAX_STREAMS);
  if (hdr != NULL) {
    char buf[16];
    size_t len = hdr->value_len < sizeof(buf) - 1 ? hdr->value_len : sizeof(buf) - 1;
    memcpy(buf, hdr->value, len);
    buf[len] = '\0';
    hs->peer_params.max_streams = (uint32_t)atoi(buf);
  } else {
    hs->peer_params.max_streams = NWEP_DEFAULT_MAX_STREAMS;
  }

  /* Store peer's other params (use defaults since not sent in CONNECT) */
  hs->peer_params.max_message_size = NWEP_DEFAULT_MAX_MESSAGE_SIZE;
  hs->peer_params.compression = "none";
  hs->peer_params.role = NULL; /* Client didn't send role in this version */

  /* Negotiate: take minimum of requested and our max */
  hs->negotiated_params.max_streams = hs->peer_params.max_streams;
  if (hs->negotiated_params.max_streams > hs->local_params.max_streams) {
    hs->negotiated_params.max_streams = hs->local_params.max_streams;
  }

  hs->negotiated_params.max_message_size = hs->local_params.max_message_size;
  hs->negotiated_params.compression = hs->local_params.compression;
  hs->negotiated_params.role = hs->local_params.role;

  /* Update state */
  hs->state.server = NWEP_SERVER_STATE_AWAITING_CLIENT_AUTH;

  return 0;
}

int nwep_connect_response_build(nwep_msg *msg, nwep_header *headers,
                                size_t max_headers, uint8_t *header_buf,
                                size_t header_buf_len, nwep_handshake *hs) {
  size_t offset = 0;
  size_t hdr_idx = 0;
  uint8_t challenge_response[NWEP_ED25519_SIG_LEN];
  uint8_t transcript_sig[NWEP_ED25519_SIG_LEN];
  char num_buf[32];
  int rv;

  if (msg == NULL || headers == NULL || header_buf == NULL || hs == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (max_headers < 10) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }

  nwep_msg_init(msg, NWEP_MSG_RESPONSE);
  msg->headers = headers;

  /* Sign the client's challenge */
  rv = nwep_challenge_sign(challenge_response, hs->peer_challenge,
                           hs->local_keypair);
  if (rv != 0) {
    return rv;
  }

  /* Build transcript up to this point */
  rv = nwep_transcript_add_connect_request(hs);
  if (rv != 0) {
    return rv;
  }
  rv = nwep_transcript_add_connect_response(hs);
  if (rv != 0) {
    return rv;
  }

  /* Sign transcript */
  rv = nwep_transcript_sign(transcript_sig, hs);
  if (rv != 0) {
    return rv;
  }

  /* :status = "ok" */
  nwep_header_set(&headers[hdr_idx++], NWEP_HDR_STATUS, NWEP_STATUS_OK);

  /* :version = "WEB/1" */
  nwep_header_set(&headers[hdr_idx++], NWEP_HDR_VERSION, NWEP_PROTO_VER);

  /* server-id = Base64(pubkey) */
  if (write_base64_header(header_buf, header_buf_len, &offset,
                          &headers[hdr_idx++], NWEP_HDR_SERVER_ID,
                          hs->local_keypair->pubkey,
                          NWEP_ED25519_PUBKEY_LEN) == 0) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }

  /* challenge-response = Base64(signature) */
  if (write_base64_header(header_buf, header_buf_len, &offset,
                          &headers[hdr_idx++], NWEP_HDR_CHALLENGE_RESPONSE,
                          challenge_response, NWEP_ED25519_SIG_LEN) == 0) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }

  /* server-challenge = Base64(nonce) */
  if (write_base64_header(header_buf, header_buf_len, &offset,
                          &headers[hdr_idx++], NWEP_HDR_SERVER_CHALLENGE,
                          hs->local_challenge, NWEP_CHALLENGE_LEN) == 0) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }

  /* max-streams */
  snprintf(num_buf, sizeof(num_buf), "%u", hs->negotiated_params.max_streams);
  if (offset + strlen(num_buf) + 1 > header_buf_len) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }
  strcpy((char *)(header_buf + offset), num_buf);
  nwep_header_set(&headers[hdr_idx++], NWEP_HDR_MAX_STREAMS,
                  (const char *)(header_buf + offset));
  offset += strlen(num_buf) + 1;

  /* max-message-size */
  snprintf(num_buf, sizeof(num_buf), "%u",
           hs->negotiated_params.max_message_size);
  if (offset + strlen(num_buf) + 1 > header_buf_len) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }
  strcpy((char *)(header_buf + offset), num_buf);
  nwep_header_set(&headers[hdr_idx++], NWEP_HDR_MAX_MESSAGE_SIZE,
                  (const char *)(header_buf + offset));
  offset += strlen(num_buf) + 1;

  /* compression */
  nwep_header_set(&headers[hdr_idx++], NWEP_HDR_COMPRESSION,
                  hs->negotiated_params.compression);

  /* roles */
  if (hs->negotiated_params.role != NULL) {
    nwep_header_set(&headers[hdr_idx++], NWEP_HDR_ROLES,
                    hs->negotiated_params.role);
  }

  /* transcript-signature = Base64(signature) */
  if (write_base64_header(header_buf, header_buf_len, &offset,
                          &headers[hdr_idx++], NWEP_HDR_TRANSCRIPT_SIG,
                          transcript_sig, NWEP_ED25519_SIG_LEN) == 0) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }

  msg->header_count = hdr_idx;

  return 0;
}

int nwep_connect_response_parse(nwep_handshake *hs, const nwep_msg *msg) {
  const nwep_header *hdr;
  size_t decoded_len;
  uint8_t challenge_response[NWEP_ED25519_SIG_LEN];
  uint8_t transcript_sig[NWEP_ED25519_SIG_LEN];
  int rv;

  if (hs == NULL || msg == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Verify status */
  hdr = nwep_msg_find_header(msg, NWEP_HDR_STATUS);
  if (hdr == NULL || !nwep_header_value_eq(hdr, NWEP_STATUS_OK)) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  /* Get server-id (pubkey) */
  hdr = nwep_msg_find_header(msg, NWEP_HDR_SERVER_ID);
  if (hdr == NULL) {
    return NWEP_ERR_PROTO_INVALID_HEADER;
  }
  decoded_len = nwep_base64_decode_n(
      hs->peer_pubkey, NWEP_ED25519_PUBKEY_LEN,
      (const char *)hdr->value, hdr->value_len);
  if (decoded_len != NWEP_ED25519_PUBKEY_LEN) {
    return NWEP_ERR_CRYPTO_INVALID_KEY;
  }

  /* Get challenge-response */
  hdr = nwep_msg_find_header(msg, NWEP_HDR_CHALLENGE_RESPONSE);
  if (hdr == NULL) {
    return NWEP_ERR_PROTO_INVALID_HEADER;
  }
  decoded_len = nwep_base64_decode_n(
      challenge_response, NWEP_ED25519_SIG_LEN,
      (const char *)hdr->value, hdr->value_len);
  if (decoded_len != NWEP_ED25519_SIG_LEN) {
    return NWEP_ERR_CRYPTO_INVALID_SIG;
  }

  /* Get server-challenge */
  hdr = nwep_msg_find_header(msg, NWEP_HDR_SERVER_CHALLENGE);
  if (hdr == NULL) {
    return NWEP_ERR_PROTO_INVALID_HEADER;
  }
  decoded_len = nwep_base64_decode_n(
      hs->peer_challenge, NWEP_CHALLENGE_LEN,
      (const char *)hdr->value, hdr->value_len);
  if (decoded_len != NWEP_CHALLENGE_LEN) {
    return NWEP_ERR_PROTO_INVALID_HEADER;
  }

  /* Parse negotiated parameters */
  hdr = nwep_msg_find_header(msg, NWEP_HDR_MAX_STREAMS);
  if (hdr != NULL) {
    char buf[16];
    size_t len = hdr->value_len < sizeof(buf) - 1 ? hdr->value_len : sizeof(buf) - 1;
    memcpy(buf, hdr->value, len);
    buf[len] = '\0';
    hs->negotiated_params.max_streams = (uint32_t)atoi(buf);
  }

  hdr = nwep_msg_find_header(msg, NWEP_HDR_MAX_MESSAGE_SIZE);
  if (hdr != NULL) {
    char buf[16];
    size_t len = hdr->value_len < sizeof(buf) - 1 ? hdr->value_len : sizeof(buf) - 1;
    memcpy(buf, hdr->value, len);
    buf[len] = '\0';
    hs->negotiated_params.max_message_size = (uint32_t)atoi(buf);
  }

  hdr = nwep_msg_find_header(msg, NWEP_HDR_COMPRESSION);
  if (hdr != NULL) {
    /* Note: compression value must persist; for now use literal */
    if (hdr->value_len == 4 && memcmp(hdr->value, "none", 4) == 0) {
      hs->negotiated_params.compression = "none";
    } else {
      hs->negotiated_params.compression = "none"; /* Default if unknown */
    }
  } else {
    hs->negotiated_params.compression = "none";
  }

  hdr = nwep_msg_find_header(msg, NWEP_HDR_ROLES);
  if (hdr != NULL) {
    /* Note: role value must persist; for now use known literals */
    if (hdr->value_len == 12 && memcmp(hdr->value, "regular_node", 12) == 0) {
      hs->negotiated_params.role = "regular_node";
    } else {
      hs->negotiated_params.role = NULL; /* Unknown role */
    }
  } else {
    hs->negotiated_params.role = NULL;
  }

  /* Verify Layer 2 (NodeID derivation) */
  rv = nwep_verify_layer2(hs);
  if (rv != 0) {
    hs->state.client = NWEP_CLIENT_STATE_ERROR;
    hs->error_code = rv;
    return rv;
  }

  /* Verify Layer 3 (challenge signature) */
  rv = nwep_verify_layer3(hs, challenge_response);
  if (rv != 0) {
    hs->state.client = NWEP_CLIENT_STATE_ERROR;
    hs->error_code = rv;
    return rv;
  }

  /* Build transcript and verify server's signature */
  rv = nwep_transcript_add_connect_request(hs);
  if (rv != 0) {
    return rv;
  }
  rv = nwep_transcript_add_connect_response(hs);
  if (rv != 0) {
    return rv;
  }

  /* Get and verify transcript signature */
  hdr = nwep_msg_find_header(msg, NWEP_HDR_TRANSCRIPT_SIG);
  if (hdr == NULL) {
    return NWEP_ERR_PROTO_INVALID_HEADER;
  }
  decoded_len = nwep_base64_decode_n(
      transcript_sig, NWEP_ED25519_SIG_LEN,
      (const char *)hdr->value, hdr->value_len);
  if (decoded_len != NWEP_ED25519_SIG_LEN) {
    return NWEP_ERR_CRYPTO_INVALID_SIG;
  }

  rv = nwep_transcript_verify(hs, transcript_sig);
  if (rv != 0) {
    hs->state.client = NWEP_CLIENT_STATE_ERROR;
    hs->error_code = rv;
    return rv;
  }

  hs->peer_nodeid_verified = 1;

  /* Update state */
  hs->state.client = NWEP_CLIENT_STATE_SEND_AUTHENTICATE;

  return 0;
}

/*
 * AUTHENTICATE request building and parsing
 */

int nwep_auth_request_build(nwep_msg *msg, nwep_header *headers,
                            size_t max_headers, uint8_t *header_buf,
                            size_t header_buf_len, nwep_handshake *hs) {
  size_t offset = 0;
  size_t hdr_idx = 0;
  uint8_t auth_response[NWEP_ED25519_SIG_LEN];
  uint8_t transcript_sig[NWEP_ED25519_SIG_LEN];
  int rv;

  if (msg == NULL || headers == NULL || header_buf == NULL || hs == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (max_headers < 4) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }

  nwep_msg_init(msg, NWEP_MSG_REQUEST);
  msg->headers = headers;

  /* Sign server's challenge */
  rv = nwep_challenge_sign(auth_response, hs->peer_challenge,
                           hs->local_keypair);
  if (rv != 0) {
    return rv;
  }

  /* Sign transcript */
  rv = nwep_transcript_sign(transcript_sig, hs);
  if (rv != 0) {
    return rv;
  }

  /* :method = "authenticate" */
  nwep_header_set(&headers[hdr_idx++], NWEP_HDR_METHOD,
                  NWEP_METHOD_AUTHENTICATE);

  /* :path = "/" */
  nwep_header_set(&headers[hdr_idx++], NWEP_HDR_PATH, "/");

  /* auth-response = Base64(signature) */
  if (write_base64_header(header_buf, header_buf_len, &offset,
                          &headers[hdr_idx++], NWEP_HDR_AUTH_RESPONSE,
                          auth_response, NWEP_ED25519_SIG_LEN) == 0) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }

  /* transcript-signature = Base64(signature) */
  if (write_base64_header(header_buf, header_buf_len, &offset,
                          &headers[hdr_idx++], NWEP_HDR_TRANSCRIPT_SIG,
                          transcript_sig, NWEP_ED25519_SIG_LEN) == 0) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }

  msg->header_count = hdr_idx;

  /* Update state */
  hs->state.client = NWEP_CLIENT_STATE_WAIT_AUTH_RESP;

  return 0;
}

int nwep_auth_request_parse(nwep_handshake *hs, const nwep_msg *msg) {
  const nwep_header *hdr;
  size_t decoded_len;
  uint8_t auth_response[NWEP_ED25519_SIG_LEN];
  uint8_t transcript_sig[NWEP_ED25519_SIG_LEN];
  int rv;

  if (hs == NULL || msg == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Verify method */
  hdr = nwep_msg_find_header(msg, NWEP_HDR_METHOD);
  if (hdr == NULL || !nwep_header_value_eq(hdr, NWEP_METHOD_AUTHENTICATE)) {
    return NWEP_ERR_PROTO_INVALID_METHOD;
  }

  /* Get auth-response */
  hdr = nwep_msg_find_header(msg, NWEP_HDR_AUTH_RESPONSE);
  if (hdr == NULL) {
    return NWEP_ERR_PROTO_INVALID_HEADER;
  }
  decoded_len = nwep_base64_decode_n(
      auth_response, NWEP_ED25519_SIG_LEN,
      (const char *)hdr->value, hdr->value_len);
  if (decoded_len != NWEP_ED25519_SIG_LEN) {
    return NWEP_ERR_CRYPTO_INVALID_SIG;
  }

  /* Verify client's challenge response (Layer 3) */
  rv = nwep_verify_layer3(hs, auth_response);
  if (rv != 0) {
    hs->state.server = NWEP_SERVER_STATE_ERROR;
    hs->error_code = rv;
    return rv;
  }

  /* Get and verify transcript signature */
  hdr = nwep_msg_find_header(msg, NWEP_HDR_TRANSCRIPT_SIG);
  if (hdr == NULL) {
    return NWEP_ERR_PROTO_INVALID_HEADER;
  }
  decoded_len = nwep_base64_decode_n(
      transcript_sig, NWEP_ED25519_SIG_LEN,
      (const char *)hdr->value, hdr->value_len);
  if (decoded_len != NWEP_ED25519_SIG_LEN) {
    return NWEP_ERR_CRYPTO_INVALID_SIG;
  }

  rv = nwep_transcript_verify(hs, transcript_sig);
  if (rv != 0) {
    hs->state.server = NWEP_SERVER_STATE_ERROR;
    hs->error_code = rv;
    return rv;
  }

  hs->peer_nodeid_verified = 1;

  /* Connection established on server side */
  hs->state.server = NWEP_SERVER_STATE_CONNECTED;

  return 0;
}

int nwep_auth_response_build(nwep_msg *msg, nwep_header *headers,
                             size_t max_headers, nwep_handshake *hs) {
  size_t hdr_idx = 0;

  if (msg == NULL || headers == NULL || hs == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (max_headers < 1) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }

  nwep_msg_init(msg, NWEP_MSG_RESPONSE);
  msg->headers = headers;

  /* :status = "ok" */
  nwep_header_set(&headers[hdr_idx++], NWEP_HDR_STATUS, NWEP_STATUS_OK);

  msg->header_count = hdr_idx;

  return 0;
}

int nwep_auth_response_parse(nwep_handshake *hs, const nwep_msg *msg) {
  const nwep_header *hdr;

  if (hs == NULL || msg == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Verify status */
  hdr = nwep_msg_find_header(msg, NWEP_HDR_STATUS);
  if (hdr == NULL || !nwep_header_value_eq(hdr, NWEP_STATUS_OK)) {
    hs->state.client = NWEP_CLIENT_STATE_ERROR;
    hs->error_code = NWEP_ERR_IDENTITY_AUTH_FAILED;
    return NWEP_ERR_IDENTITY_AUTH_FAILED;
  }

  /* Connection established! */
  hs->state.client = NWEP_CLIENT_STATE_CONNECTED;

  return 0;
}
