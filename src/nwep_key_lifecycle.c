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

#include <openssl/rand.h>

#include <string.h>

/*
 * GF(256) arithmetic for Shamir secret sharing.
 * Uses the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
 */

static uint8_t gf256_add(uint8_t a, uint8_t b) {
  return a ^ b;
}

static uint8_t gf256_mul(uint8_t a, uint8_t b) {
  uint8_t result = 0;
  uint8_t hi_bit;

  for (int i = 0; i < 8; i++) {
    if (b & 1) {
      result ^= a;
    }
    hi_bit = a & 0x80;
    a <<= 1;
    if (hi_bit) {
      a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 reduced */
    }
    b >>= 1;
  }
  return result;
}

static uint8_t gf256_inv(uint8_t a) {
  uint8_t result = a;
  /* a^254 = a^(-1) in GF(256) by Fermat's little theorem */
  for (int i = 0; i < 6; i++) {
    result = gf256_mul(result, result);
    result = gf256_mul(result, a);
  }
  result = gf256_mul(result, result);
  return result;
}

static uint8_t gf256_div(uint8_t a, uint8_t b) {
  if (b == 0) {
    return 0;
  }
  return gf256_mul(a, gf256_inv(b));
}

/*
 * Evaluate polynomial at x using Horner's method.
 * coeffs[0] is the constant term (the secret).
 */
static uint8_t poly_eval(const uint8_t *coeffs, size_t degree, uint8_t x) {
  uint8_t result = coeffs[degree];
  for (size_t i = degree; i > 0; i--) {
    result = gf256_add(gf256_mul(result, x), coeffs[i - 1]);
  }
  return result;
}

/*
 * Lagrange interpolation at x=0 to recover the secret.
 */
static uint8_t lagrange_interpolate(const uint8_t *xs, const uint8_t *ys,
                                    size_t n) {
  uint8_t result = 0;

  for (size_t i = 0; i < n; i++) {
    uint8_t num = 1;
    uint8_t den = 1;

    for (size_t j = 0; j < n; j++) {
      if (i == j) {
        continue;
      }
      /* Evaluating at x=0: (0 - xj) / (xi - xj) = xj / (xi - xj) */
      num = gf256_mul(num, xs[j]);
      den = gf256_mul(den, gf256_add(xs[i], xs[j]));
    }

    uint8_t term = gf256_mul(ys[i], gf256_div(num, den));
    result = gf256_add(result, term);
  }

  return result;
}

int nwep_shamir_split(const uint8_t secret[32], nwep_shamir_share *shares,
                      size_t n, size_t t) {
  uint8_t coeffs[NWEP_SHAMIR_MAX_SHARES];

  if (shares == NULL || secret == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (t < NWEP_SHAMIR_MIN_THRESHOLD || n < t || n > NWEP_SHAMIR_MAX_SHARES) {
    return NWEP_ERR_IDENTITY_INVALID_THRESHOLD;
  }

  /* Process each byte of the secret independently */
  for (size_t byte_idx = 0; byte_idx < 32; byte_idx++) {
    /* coeffs[0] is the secret byte, rest are random */
    coeffs[0] = secret[byte_idx];
    if (RAND_bytes(&coeffs[1], (int)(t - 1)) != 1) {
      return NWEP_ERR_CRYPTO_KEY_GEN_FAILED;
    }

    /* Evaluate polynomial at x = 1, 2, 3, ..., n */
    for (size_t i = 0; i < n; i++) {
      shares[i].index = (uint8_t)(i + 1);
      shares[i].data[byte_idx] = poly_eval(coeffs, t - 1, (uint8_t)(i + 1));
    }
  }

  /* Clear coefficients */
  OPENSSL_cleanse(coeffs, sizeof(coeffs));

  return 0;
}

int nwep_shamir_combine(uint8_t secret[32], const nwep_shamir_share *shares,
                        size_t num_shares) {
  uint8_t xs[NWEP_SHAMIR_MAX_SHARES];
  uint8_t ys[NWEP_SHAMIR_MAX_SHARES];

  if (secret == NULL || shares == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (num_shares < NWEP_SHAMIR_MIN_THRESHOLD) {
    return NWEP_ERR_IDENTITY_INVALID_THRESHOLD;
  }

  /* Check for duplicate indices */
  for (size_t i = 0; i < num_shares; i++) {
    if (shares[i].index == 0) {
      return NWEP_ERR_IDENTITY_INVALID_SHARE;
    }
    for (size_t j = i + 1; j < num_shares; j++) {
      if (shares[i].index == shares[j].index) {
        return NWEP_ERR_IDENTITY_INVALID_SHARE;
      }
    }
  }

  /* Extract x coordinates */
  for (size_t i = 0; i < num_shares; i++) {
    xs[i] = shares[i].index;
  }

  /* Reconstruct each byte independently */
  for (size_t byte_idx = 0; byte_idx < 32; byte_idx++) {
    for (size_t i = 0; i < num_shares; i++) {
      ys[i] = shares[i].data[byte_idx];
    }
    secret[byte_idx] = lagrange_interpolate(xs, ys, num_shares);
  }

  return 0;
}

/*
 * Recovery Authority
 */

int nwep_recovery_authority_new(nwep_recovery_authority *ra) {
  int rv;

  if (ra == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(ra, 0, sizeof(*ra));

  rv = nwep_keypair_generate(&ra->keypair);
  if (rv != 0) {
    return rv;
  }

  ra->initialized = 1;
  return 0;
}

int nwep_recovery_authority_from_keypair(nwep_recovery_authority *ra,
                                         const nwep_keypair *kp) {
  if (ra == NULL || kp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(ra, 0, sizeof(*ra));
  memcpy(&ra->keypair, kp, sizeof(nwep_keypair));
  ra->initialized = 1;

  return 0;
}

void nwep_recovery_authority_clear(nwep_recovery_authority *ra) {
  if (ra == NULL) {
    return;
  }
  nwep_keypair_clear(&ra->keypair);
  OPENSSL_cleanse(ra, sizeof(*ra));
}

const uint8_t *nwep_recovery_authority_get_pubkey(
    const nwep_recovery_authority *ra) {
  if (ra == NULL || !ra->initialized) {
    return NULL;
  }
  return ra->keypair.pubkey;
}

/*
 * Managed Identity
 */

int nwep_managed_identity_new(nwep_managed_identity *identity,
                              const nwep_keypair *kp,
                              const nwep_recovery_authority *ra,
                              nwep_tstamp now) {
  int rv;

  if (identity == NULL || kp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(identity, 0, sizeof(*identity));

  /* Compute NodeID from keypair */
  rv = nwep_nodeid_from_keypair(&identity->nodeid, kp);
  if (rv != 0) {
    return rv;
  }

  /* Set up initial key */
  memcpy(&identity->keys[0].keypair, kp, sizeof(nwep_keypair));
  identity->keys[0].activated_at = now;
  identity->keys[0].expires_at = 0; /* Never expires unless rotated */
  identity->keys[0].active = 1;
  identity->key_count = 1;

  /* Set up recovery authority if provided */
  if (ra != NULL && ra->initialized) {
    memcpy(identity->recovery_pubkey, ra->keypair.pubkey,
           NWEP_ED25519_PUBKEY_LEN);
    identity->has_recovery = 1;
  }

  return 0;
}

int nwep_managed_identity_rotate(nwep_managed_identity *identity,
                                 nwep_tstamp now) {
  nwep_keypair new_kp;
  int rv;
  size_t new_idx;

  if (identity == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (identity->revoked) {
    return NWEP_ERR_IDENTITY_REVOKED;
  }

  /* Count active keys and find slot for new key */
  size_t active_count = 0;
  for (size_t i = 0; i < identity->key_count; i++) {
    if (identity->keys[i].active) {
      active_count++;
    }
  }

  if (active_count >= NWEP_MAX_ACTIVE_KEYS) {
    return NWEP_ERR_IDENTITY_ROTATION_IN_PROGRESS;
  }

  /* Generate new keypair */
  rv = nwep_keypair_generate(&new_kp);
  if (rv != 0) {
    return rv;
  }

  /* Find slot for new key */
  if (identity->key_count < NWEP_MAX_ACTIVE_KEYS) {
    new_idx = identity->key_count;
    identity->key_count++;
  } else {
    /* Reuse inactive slot */
    for (new_idx = 0; new_idx < NWEP_MAX_ACTIVE_KEYS; new_idx++) {
      if (!identity->keys[new_idx].active) {
        break;
      }
    }
  }

  /* Set expiry on old keys */
  for (size_t i = 0; i < identity->key_count; i++) {
    if (identity->keys[i].active && i != new_idx) {
      identity->keys[i].expires_at =
          now + (nwep_tstamp)NWEP_KEY_OVERLAP_SECONDS * NWEP_SECONDS;
    }
  }

  /* Add new key */
  memcpy(&identity->keys[new_idx].keypair, &new_kp, sizeof(nwep_keypair));
  identity->keys[new_idx].activated_at = now;
  identity->keys[new_idx].expires_at = 0;
  identity->keys[new_idx].active = 1;

  nwep_keypair_clear(&new_kp);

  return 0;
}

void nwep_managed_identity_update(nwep_managed_identity *identity,
                                  nwep_tstamp now) {
  if (identity == NULL) {
    return;
  }

  /* Expire old keys */
  for (size_t i = 0; i < identity->key_count; i++) {
    if (identity->keys[i].active && identity->keys[i].expires_at != 0 &&
        now >= identity->keys[i].expires_at) {
      identity->keys[i].active = 0;
      nwep_keypair_clear(&identity->keys[i].keypair);
    }
  }
}

const nwep_keypair *nwep_managed_identity_get_active(
    const nwep_managed_identity *identity) {
  nwep_tstamp newest = 0;
  const nwep_keypair *result = NULL;

  if (identity == NULL || identity->revoked) {
    return NULL;
  }

  /* Return the newest active key */
  for (size_t i = 0; i < identity->key_count; i++) {
    if (identity->keys[i].active) {
      if (result == NULL || identity->keys[i].activated_at > newest) {
        newest = identity->keys[i].activated_at;
        result = &identity->keys[i].keypair;
      }
    }
  }

  return result;
}

size_t nwep_managed_identity_get_active_keys(
    const nwep_managed_identity *identity, const nwep_keypair **keys,
    size_t max_keys) {
  size_t count = 0;

  if (identity == NULL || keys == NULL || identity->revoked) {
    return 0;
  }

  for (size_t i = 0; i < identity->key_count && count < max_keys; i++) {
    if (identity->keys[i].active) {
      keys[count++] = &identity->keys[i].keypair;
    }
  }

  return count;
}

int nwep_managed_identity_is_revoked(const nwep_managed_identity *identity) {
  if (identity == NULL) {
    return 0;
  }
  return identity->revoked;
}

/*
 * Build revocation message for signing:
 * "REVOKE:" || nodeid (32 bytes) || timestamp (8 bytes big-endian)
 */
static void build_revocation_message(uint8_t *msg, const nwep_nodeid *nodeid,
                                     nwep_tstamp timestamp) {
  memcpy(msg, "REVOKE:", 7);
  memcpy(msg + 7, nodeid->data, NWEP_NODEID_LEN);
  msg[39] = (uint8_t)(timestamp >> 56);
  msg[40] = (uint8_t)(timestamp >> 48);
  msg[41] = (uint8_t)(timestamp >> 40);
  msg[42] = (uint8_t)(timestamp >> 32);
  msg[43] = (uint8_t)(timestamp >> 24);
  msg[44] = (uint8_t)(timestamp >> 16);
  msg[45] = (uint8_t)(timestamp >> 8);
  msg[46] = (uint8_t)timestamp;
}

#define REVOCATION_MSG_LEN 47

int nwep_managed_identity_revoke(nwep_managed_identity *identity,
                                 const nwep_recovery_authority *ra,
                                 nwep_tstamp now) {
  uint8_t msg[REVOCATION_MSG_LEN];
  int rv;

  if (identity == NULL || ra == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (!identity->has_recovery) {
    return NWEP_ERR_IDENTITY_NO_RECOVERY;
  }

  if (identity->revoked) {
    return NWEP_ERR_IDENTITY_REVOKED;
  }

  /* Verify recovery authority matches */
  if (memcmp(identity->recovery_pubkey, ra->keypair.pubkey,
             NWEP_ED25519_PUBKEY_LEN) != 0) {
    return NWEP_ERR_IDENTITY_RECOVERY_MISMATCH;
  }

  /* Build and sign revocation message */
  build_revocation_message(msg, &identity->nodeid, now);

  rv = nwep_sign(identity->revocation.signature, msg, sizeof(msg),
                 &ra->keypair);
  if (rv != 0) {
    return rv;
  }

  /* Store revocation record */
  memcpy(&identity->revocation.nodeid, &identity->nodeid, sizeof(nwep_nodeid));
  identity->revocation.timestamp = now;
  memcpy(identity->revocation.recovery_pubkey, ra->keypair.pubkey,
         NWEP_ED25519_PUBKEY_LEN);

  /* Mark as revoked and clear all keys */
  identity->revoked = 1;
  for (size_t i = 0; i < identity->key_count; i++) {
    identity->keys[i].active = 0;
    nwep_keypair_clear(&identity->keys[i].keypair);
  }

  return 0;
}

int nwep_managed_identity_verify_revocation(const nwep_revocation *revocation) {
  uint8_t msg[REVOCATION_MSG_LEN];

  if (revocation == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  build_revocation_message(msg, &revocation->nodeid, revocation->timestamp);

  return nwep_verify(revocation->signature, msg, sizeof(msg),
                     revocation->recovery_pubkey);
}

void nwep_managed_identity_clear(nwep_managed_identity *identity) {
  if (identity == NULL) {
    return;
  }

  for (size_t i = 0; i < identity->key_count; i++) {
    nwep_keypair_clear(&identity->keys[i].keypair);
  }

  OPENSSL_cleanse(identity, sizeof(*identity));
}
