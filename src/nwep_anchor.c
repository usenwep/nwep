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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <nwep/nwep.h>

#include <blst.h>

#include <openssl/rand.h>

#include <stdlib.h>
#include <string.h>

typedef struct {
  nwep_bls_pubkey pk;
  int builtin;
} anchor_entry;

struct nwep_anchor_set {
  anchor_entry anchors[NWEP_MAX_ANCHORS];
  size_t count;
  size_t threshold;
};

#define CHECKPOINT_MSG_SIZE 56

static uint8_t *put_uint64be(uint8_t *p, uint64_t n) {
  *p++ = (uint8_t)(n >> 56);
  *p++ = (uint8_t)(n >> 48);
  *p++ = (uint8_t)(n >> 40);
  *p++ = (uint8_t)(n >> 32);
  *p++ = (uint8_t)(n >> 24);
  *p++ = (uint8_t)(n >> 16);
  *p++ = (uint8_t)(n >> 8);
  *p++ = (uint8_t)n;
  return p;
}

static const uint8_t *get_uint64be(uint64_t *dest, const uint8_t *p) {
  *dest = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
          ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
          ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
          ((uint64_t)p[6] << 8) | (uint64_t)p[7];
  return p + 8;
}

int nwep_bls_keypair_generate(nwep_bls_keypair *kp) {
  uint8_t ikm[32];

  if (kp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (RAND_bytes(ikm, sizeof(ikm)) != 1) {
    return NWEP_ERR_CRYPTO_KEY_GEN_FAILED;
  }

  return nwep_bls_keypair_from_seed(kp, ikm, sizeof(ikm));
}

int nwep_bls_keypair_from_seed(nwep_bls_keypair *kp, const uint8_t *ikm,
                                size_t ikm_len) {
  blst_scalar sk;
  blst_p1 pk_point;

  if (kp == NULL || ikm == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (ikm_len < 32) {
    return NWEP_ERR_CRYPTO_INVALID_KEY;
  }

  blst_keygen(&sk, ikm, ikm_len, NULL, 0);
  blst_bendian_from_scalar(kp->privkey, &sk);
  blst_sk_to_pk_in_g1(&pk_point, &sk);
  blst_p1_compress(kp->pubkey, &pk_point);

  return 0;
}

int nwep_bls_pubkey_serialize(uint8_t out[NWEP_BLS_PUBKEY_LEN],
                               const nwep_bls_pubkey *pk) {
  if (out == NULL || pk == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memcpy(out, pk->data, NWEP_BLS_PUBKEY_LEN);
  return 0;
}

int nwep_bls_pubkey_deserialize(nwep_bls_pubkey *pk,
                                 const uint8_t in[NWEP_BLS_PUBKEY_LEN]) {
  blst_p1_affine pk_affine;
  BLST_ERROR err;

  if (pk == NULL || in == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  err = blst_p1_uncompress(&pk_affine, in);
  if (err != BLST_SUCCESS) {
    return NWEP_ERR_CRYPTO_INVALID_KEY;
  }

  if (!blst_p1_affine_in_g1(&pk_affine)) {
    return NWEP_ERR_CRYPTO_INVALID_KEY;
  }

  memcpy(pk->data, in, NWEP_BLS_PUBKEY_LEN);
  return 0;
}

int nwep_bls_sign(nwep_bls_sig *sig, const nwep_bls_keypair *kp,
                   const uint8_t *msg, size_t msg_len) {
  blst_scalar sk;
  blst_p2 hash_point;
  blst_p2 sig_point;

  if (sig == NULL || kp == NULL || msg == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  blst_scalar_from_bendian(&sk, kp->privkey);
  blst_hash_to_g2(&hash_point, msg, msg_len,
                  (const uint8_t *)NWEP_CHECKPOINT_DST,
                  sizeof(NWEP_CHECKPOINT_DST) - 1, NULL, 0);
  blst_sign_pk_in_g1(&sig_point, &hash_point, &sk);
  blst_p2_compress(sig->data, &sig_point);

  return 0;
}

int nwep_bls_verify(const nwep_bls_pubkey *pk, const nwep_bls_sig *sig,
                     const uint8_t *msg, size_t msg_len) {
  blst_p1_affine pk_affine;
  blst_p2_affine sig_affine;
  BLST_ERROR err;

  if (pk == NULL || sig == NULL || msg == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  err = blst_p1_uncompress(&pk_affine, pk->data);
  if (err != BLST_SUCCESS) {
    return NWEP_ERR_CRYPTO_INVALID_KEY;
  }

  err = blst_p2_uncompress(&sig_affine, sig->data);
  if (err != BLST_SUCCESS) {
    return NWEP_ERR_CRYPTO_SIGN_FAILED;
  }

  err = blst_core_verify_pk_in_g1(&pk_affine, &sig_affine, 1, msg, msg_len,
                                   (const uint8_t *)NWEP_CHECKPOINT_DST,
                                   sizeof(NWEP_CHECKPOINT_DST) - 1, NULL, 0);
  if (err != BLST_SUCCESS) {
    return NWEP_ERR_CRYPTO_SIGN_FAILED;
  }

  return 0;
}

int nwep_bls_aggregate_sigs(nwep_bls_sig *out, const nwep_bls_sig *sigs,
                             size_t n) {
  blst_p2 agg;
  blst_p2_affine sig_affine;
  BLST_ERROR err;

  if (out == NULL || sigs == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (n == 0) {
    return NWEP_ERR_INTERNAL_INVALID_STATE;
  }

  err = blst_p2_uncompress(&sig_affine, sigs[0].data);
  if (err != BLST_SUCCESS) {
    return NWEP_ERR_CRYPTO_SIGN_FAILED;
  }
  blst_p2_from_affine(&agg, &sig_affine);

  for (size_t i = 1; i < n; i++) {
    err = blst_p2_uncompress(&sig_affine, sigs[i].data);
    if (err != BLST_SUCCESS) {
      return NWEP_ERR_CRYPTO_SIGN_FAILED;
    }
    blst_p2_add_or_double_affine(&agg, &agg, &sig_affine);
  }

  blst_p2_compress(out->data, &agg);

  return 0;
}

int nwep_bls_verify_aggregate(const nwep_bls_pubkey *pks, size_t n,
                               const nwep_bls_sig *sig, const uint8_t *msg,
                               size_t msg_len) {
  blst_p1 agg_pk;
  blst_p1_affine pk_affine;
  blst_p1_affine agg_pk_affine;
  blst_p2_affine sig_affine;
  BLST_ERROR err;

  if (pks == NULL || sig == NULL || msg == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (n == 0) {
    return NWEP_ERR_INTERNAL_INVALID_STATE;
  }

  err = blst_p1_uncompress(&pk_affine, pks[0].data);
  if (err != BLST_SUCCESS) {
    return NWEP_ERR_CRYPTO_INVALID_KEY;
  }
  blst_p1_from_affine(&agg_pk, &pk_affine);

  for (size_t i = 1; i < n; i++) {
    err = blst_p1_uncompress(&pk_affine, pks[i].data);
    if (err != BLST_SUCCESS) {
      return NWEP_ERR_CRYPTO_INVALID_KEY;
    }
    blst_p1_add_or_double_affine(&agg_pk, &agg_pk, &pk_affine);
  }

  blst_p1_to_affine(&agg_pk_affine, &agg_pk);

  err = blst_p2_uncompress(&sig_affine, sig->data);
  if (err != BLST_SUCCESS) {
    return NWEP_ERR_CRYPTO_SIGN_FAILED;
  }

  err = blst_core_verify_pk_in_g1(&agg_pk_affine, &sig_affine, 1, msg, msg_len,
                                   (const uint8_t *)NWEP_CHECKPOINT_DST,
                                   sizeof(NWEP_CHECKPOINT_DST) - 1, NULL, 0);
  if (err != BLST_SUCCESS) {
    return NWEP_ERR_CRYPTO_SIGN_FAILED;
  }

  return 0;
}

int nwep_anchor_set_new(nwep_anchor_set **pset, size_t threshold) {
  nwep_anchor_set *set;

  if (pset == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (threshold == 0 || threshold > NWEP_MAX_ANCHORS) {
    return NWEP_ERR_CONFIG_VALIDATION_FAILED;
  }

  set = calloc(1, sizeof(*set));
  if (set == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  set->threshold = threshold;
  *pset = set;
  return 0;
}

void nwep_anchor_set_free(nwep_anchor_set *set) {
  free(set);
}

int nwep_anchor_set_add(nwep_anchor_set *set, const nwep_bls_pubkey *pk,
                         int builtin) {
  if (set == NULL || pk == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (set->count >= NWEP_MAX_ANCHORS) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  for (size_t i = 0; i < set->count; i++) {
    if (memcmp(set->anchors[i].pk.data, pk->data, NWEP_BLS_PUBKEY_LEN) == 0) {
      return NWEP_ERR_INTERNAL_INVALID_STATE;
    }
  }

  memcpy(&set->anchors[set->count].pk, pk, sizeof(nwep_bls_pubkey));
  set->anchors[set->count].builtin = builtin;
  set->count++;

  return 0;
}

int nwep_anchor_set_remove(nwep_anchor_set *set, const nwep_bls_pubkey *pk) {
  if (set == NULL || pk == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  for (size_t i = 0; i < set->count; i++) {
    if (memcmp(set->anchors[i].pk.data, pk->data, NWEP_BLS_PUBKEY_LEN) == 0) {
      if (set->anchors[i].builtin) {
        return NWEP_ERR_INTERNAL_INVALID_STATE;
      }
      for (size_t j = i; j < set->count - 1; j++) {
        set->anchors[j] = set->anchors[j + 1];
      }
      set->count--;
      return 0;
    }
  }

  return NWEP_ERR_STORAGE_KEY_NOT_FOUND;
}

size_t nwep_anchor_set_size(const nwep_anchor_set *set) {
  if (set == NULL) {
    return 0;
  }
  return set->count;
}

int nwep_anchor_set_get(const nwep_anchor_set *set, size_t idx,
                         nwep_bls_pubkey *pk, int *builtin) {
  if (set == NULL || pk == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (idx >= set->count) {
    return NWEP_ERR_STORAGE_INDEX_OUT_OF_RANGE;
  }

  memcpy(pk, &set->anchors[idx].pk, sizeof(nwep_bls_pubkey));
  if (builtin != NULL) {
    *builtin = set->anchors[idx].builtin;
  }

  return 0;
}

size_t nwep_anchor_set_threshold(const nwep_anchor_set *set) {
  if (set == NULL) {
    return 0;
  }
  return set->threshold;
}

int nwep_anchor_set_contains(const nwep_anchor_set *set,
                              const nwep_bls_pubkey *pk) {
  if (set == NULL || pk == NULL) {
    return 0;
  }

  for (size_t i = 0; i < set->count; i++) {
    if (memcmp(set->anchors[i].pk.data, pk->data, NWEP_BLS_PUBKEY_LEN) == 0) {
      return 1;
    }
  }

  return 0;
}

nwep_ssize nwep_checkpoint_message(uint8_t *buf, size_t buflen,
                                    const nwep_checkpoint *cp) {
  uint8_t *p;

  if (buf == NULL || cp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (buflen < CHECKPOINT_MSG_SIZE) {
    return NWEP_ERR_PROTO_MSG_TOO_LARGE;
  }

  p = buf;
  p = put_uint64be(p, cp->epoch);
  p = put_uint64be(p, cp->timestamp);
  memcpy(p, cp->merkle_root.data, 32);
  p += 32;
  p = put_uint64be(p, cp->log_size);

  return CHECKPOINT_MSG_SIZE;
}

int nwep_checkpoint_new(nwep_checkpoint *cp, uint64_t epoch,
                         nwep_tstamp timestamp,
                         const nwep_merkle_hash *merkle_root,
                         uint64_t log_size) {
  if (cp == NULL || merkle_root == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(cp, 0, sizeof(*cp));
  cp->epoch = epoch;
  cp->timestamp = timestamp;
  memcpy(&cp->merkle_root, merkle_root, sizeof(nwep_merkle_hash));
  cp->log_size = log_size;

  return 0;
}

int nwep_checkpoint_sign(nwep_checkpoint *cp, const nwep_bls_keypair *anchor_kp) {
  uint8_t msg[CHECKPOINT_MSG_SIZE];
  nwep_ssize msg_len;
  nwep_bls_sig new_sig;
  nwep_bls_pubkey signer_pk;
  int rv;

  if (cp == NULL || anchor_kp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (cp->num_signers >= NWEP_MAX_ANCHORS) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  msg_len = nwep_checkpoint_message(msg, sizeof(msg), cp);
  if (msg_len < 0) {
    return (int)msg_len;
  }

  rv = nwep_bls_sign(&new_sig, anchor_kp, msg, (size_t)msg_len);
  if (rv != 0) {
    return rv;
  }

  memcpy(signer_pk.data, anchor_kp->pubkey, NWEP_BLS_PUBKEY_LEN);

  for (size_t i = 0; i < cp->num_signers; i++) {
    if (memcmp(cp->signers[i].data, signer_pk.data, NWEP_BLS_PUBKEY_LEN) == 0) {
      return NWEP_ERR_INTERNAL_INVALID_STATE;
    }
  }

  if (cp->num_signers == 0) {
    memcpy(&cp->signature, &new_sig, sizeof(nwep_bls_sig));
  } else {
    nwep_bls_sig sigs[2];
    memcpy(&sigs[0], &cp->signature, sizeof(nwep_bls_sig));
    memcpy(&sigs[1], &new_sig, sizeof(nwep_bls_sig));
    rv = nwep_bls_aggregate_sigs(&cp->signature, sigs, 2);
    if (rv != 0) {
      return rv;
    }
  }

  memcpy(&cp->signers[cp->num_signers], &signer_pk, sizeof(nwep_bls_pubkey));
  cp->num_signers++;

  return 0;
}

int nwep_checkpoint_verify(const nwep_checkpoint *cp,
                            const nwep_anchor_set *anchor_set) {
  uint8_t msg[CHECKPOINT_MSG_SIZE];
  nwep_ssize msg_len;
  size_t valid_signers = 0;

  if (cp == NULL || anchor_set == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  for (size_t i = 0; i < cp->num_signers; i++) {
    if (nwep_anchor_set_contains(anchor_set, &cp->signers[i])) {
      valid_signers++;
    }
  }

  if (valid_signers < anchor_set->threshold) {
    return NWEP_ERR_TRUST_QUORUM_NOT_REACHED;
  }

  msg_len = nwep_checkpoint_message(msg, sizeof(msg), cp);
  if (msg_len < 0) {
    return (int)msg_len;
  }

  return nwep_bls_verify_aggregate(cp->signers, cp->num_signers, &cp->signature,
                                    msg, (size_t)msg_len);
}

/*
 * Checkpoint serialization format:
 * [8 bytes epoch BE]
 * [8 bytes timestamp BE]
 * [32 bytes merkle_root]
 * [8 bytes log_size BE]
 * [96 bytes signature]
 * [1 byte num_signers]
 * [num_signers * 48 bytes signer pubkeys]
 *
 * Min size: 8 + 8 + 32 + 8 + 96 + 1 = 153 bytes
 * Max size: 153 + 32 * 48 = 1689 bytes
 */
#define CHECKPOINT_BASE_SIZE (8 + 8 + 32 + 8 + 96 + 1)

nwep_ssize nwep_checkpoint_encode(uint8_t *buf, size_t buflen,
                                   const nwep_checkpoint *cp) {
  uint8_t *p;
  size_t needed;

  if (buf == NULL || cp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  needed = CHECKPOINT_BASE_SIZE + cp->num_signers * NWEP_BLS_PUBKEY_LEN;
  if (buflen < needed) {
    return NWEP_ERR_PROTO_MSG_TOO_LARGE;
  }

  p = buf;

  /* epoch */
  p = put_uint64be(p, cp->epoch);

  /* timestamp */
  p = put_uint64be(p, cp->timestamp);

  /* merkle_root */
  memcpy(p, cp->merkle_root.data, 32);
  p += 32;

  /* log_size */
  p = put_uint64be(p, cp->log_size);

  /* signature */
  memcpy(p, cp->signature.data, NWEP_BLS_SIG_LEN);
  p += NWEP_BLS_SIG_LEN;

  /* num_signers */
  *p++ = (uint8_t)cp->num_signers;

  /* signer pubkeys */
  for (size_t i = 0; i < cp->num_signers; i++) {
    memcpy(p, cp->signers[i].data, NWEP_BLS_PUBKEY_LEN);
    p += NWEP_BLS_PUBKEY_LEN;
  }

  return (nwep_ssize)(p - buf);
}

int nwep_checkpoint_decode(nwep_checkpoint *cp, const uint8_t *data,
                            size_t datalen) {
  const uint8_t *p;
  uint8_t num_signers;
  size_t needed;

  if (cp == NULL || data == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (datalen < CHECKPOINT_BASE_SIZE) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  memset(cp, 0, sizeof(*cp));
  p = data;

  /* epoch */
  p = get_uint64be(&cp->epoch, p);

  /* timestamp */
  p = get_uint64be(&cp->timestamp, p);

  /* merkle_root */
  memcpy(cp->merkle_root.data, p, 32);
  p += 32;

  /* log_size */
  p = get_uint64be(&cp->log_size, p);

  /* signature */
  memcpy(cp->signature.data, p, NWEP_BLS_SIG_LEN);
  p += NWEP_BLS_SIG_LEN;

  /* num_signers */
  num_signers = *p++;
  if (num_signers > NWEP_MAX_ANCHORS) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  needed = CHECKPOINT_BASE_SIZE + num_signers * NWEP_BLS_PUBKEY_LEN;
  if (datalen < needed) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  cp->num_signers = num_signers;

  /* signer pubkeys */
  for (size_t i = 0; i < num_signers; i++) {
    memcpy(cp->signers[i].data, p, NWEP_BLS_PUBKEY_LEN);
    p += NWEP_BLS_PUBKEY_LEN;
  }

  return 0;
}
