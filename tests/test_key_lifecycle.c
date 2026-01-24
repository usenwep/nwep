/*
 * nwep - Key Lifecycle Tests (Phase 12)
 */
#include <nwep/nwep.h>

#include <stdio.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  %s... ", #name);                                                 \
    fflush(stdout);                                                            \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    tests_passed++;                                                            \
    printf("PASS\n");                                                          \
  } while (0)

#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
    return 1;                                                                  \
  } while (0)

#define ASSERT(cond, msg)                                                      \
  do {                                                                         \
    if (!(cond)) {                                                             \
      FAIL(msg);                                                               \
    }                                                                          \
  } while (0)

/*
 * Shamir Secret Sharing Tests
 */

static int test_shamir_split_combine_2of3(void) {
  TEST(shamir_split_combine_2of3);

  uint8_t secret[32] = {0};
  uint8_t recovered[32] = {0};
  nwep_shamir_share shares[3];
  int rv;

  /* Generate a random secret */
  for (int i = 0; i < 32; i++) {
    secret[i] = (uint8_t)(i * 7 + 13);
  }

  /* Split into 3 shares with threshold 2 */
  rv = nwep_shamir_split(secret, shares, 3, 2);
  ASSERT(rv == 0, "split failed");

  /* Verify shares have unique indices */
  ASSERT(shares[0].index == 1, "wrong index 0");
  ASSERT(shares[1].index == 2, "wrong index 1");
  ASSERT(shares[2].index == 3, "wrong index 2");

  /* Combine with shares 0 and 1 */
  nwep_shamir_share subset1[2] = {shares[0], shares[1]};
  rv = nwep_shamir_combine(recovered, subset1, 2);
  ASSERT(rv == 0, "combine failed");
  ASSERT(memcmp(secret, recovered, 32) == 0, "secret mismatch (0,1)");

  /* Combine with shares 0 and 2 */
  nwep_shamir_share subset2[2] = {shares[0], shares[2]};
  rv = nwep_shamir_combine(recovered, subset2, 2);
  ASSERT(rv == 0, "combine failed");
  ASSERT(memcmp(secret, recovered, 32) == 0, "secret mismatch (0,2)");

  /* Combine with shares 1 and 2 */
  nwep_shamir_share subset3[2] = {shares[1], shares[2]};
  rv = nwep_shamir_combine(recovered, subset3, 2);
  ASSERT(rv == 0, "combine failed");
  ASSERT(memcmp(secret, recovered, 32) == 0, "secret mismatch (1,2)");

  /* Combine with all 3 shares */
  rv = nwep_shamir_combine(recovered, shares, 3);
  ASSERT(rv == 0, "combine with all shares failed");
  ASSERT(memcmp(secret, recovered, 32) == 0, "secret mismatch (all)");

  PASS();
  return 0;
}

static int test_shamir_split_combine_3of5(void) {
  TEST(shamir_split_combine_3of5);

  uint8_t secret[32];
  uint8_t recovered[32];
  nwep_shamir_share shares[5];
  int rv;

  /* Generate random-ish secret */
  for (int i = 0; i < 32; i++) {
    secret[i] = (uint8_t)(i * 17 + 23);
  }

  /* Split into 5 shares with threshold 3 */
  rv = nwep_shamir_split(secret, shares, 5, 3);
  ASSERT(rv == 0, "split failed");

  /* Combine with shares 0, 2, 4 */
  nwep_shamir_share subset[3] = {shares[0], shares[2], shares[4]};
  rv = nwep_shamir_combine(recovered, subset, 3);
  ASSERT(rv == 0, "combine failed");
  ASSERT(memcmp(secret, recovered, 32) == 0, "secret mismatch");

  PASS();
  return 0;
}

static int test_shamir_invalid_params(void) {
  TEST(shamir_invalid_params);

  uint8_t secret[32] = {0};
  nwep_shamir_share shares[3];
  int rv;

  /* Threshold < 2 */
  rv = nwep_shamir_split(secret, shares, 3, 1);
  ASSERT(rv == NWEP_ERR_IDENTITY_INVALID_THRESHOLD, "should reject t<2");

  /* n < t */
  rv = nwep_shamir_split(secret, shares, 2, 3);
  ASSERT(rv == NWEP_ERR_IDENTITY_INVALID_THRESHOLD, "should reject n<t");

  /* n > 255 */
  rv = nwep_shamir_split(secret, shares, 256, 2);
  ASSERT(rv == NWEP_ERR_IDENTITY_INVALID_THRESHOLD, "should reject n>255");

  PASS();
  return 0;
}

static int test_shamir_duplicate_indices(void) {
  TEST(shamir_duplicate_indices);

  uint8_t secret[32] = {0};
  uint8_t recovered[32];
  nwep_shamir_share shares[3];
  int rv;

  /* Create valid shares first */
  rv = nwep_shamir_split(secret, shares, 3, 2);
  ASSERT(rv == 0, "split failed");

  /* Duplicate the first share */
  nwep_shamir_share dup_shares[2] = {shares[0], shares[0]};
  rv = nwep_shamir_combine(recovered, dup_shares, 2);
  ASSERT(rv == NWEP_ERR_IDENTITY_INVALID_SHARE, "should reject duplicates");

  PASS();
  return 0;
}

/*
 * Recovery Authority Tests
 */

static int test_recovery_authority_new(void) {
  TEST(recovery_authority_new);

  nwep_recovery_authority ra;
  int rv;

  rv = nwep_recovery_authority_new(&ra);
  ASSERT(rv == 0, "failed to create recovery authority");
  ASSERT(ra.initialized == 1, "not initialized");

  const uint8_t *pubkey = nwep_recovery_authority_get_pubkey(&ra);
  ASSERT(pubkey != NULL, "pubkey is NULL");

  /* Verify pubkey is not all zeros */
  int all_zero = 1;
  for (int i = 0; i < 32; i++) {
    if (pubkey[i] != 0) {
      all_zero = 0;
      break;
    }
  }
  ASSERT(!all_zero, "pubkey is all zeros");

  nwep_recovery_authority_clear(&ra);
  ASSERT(ra.initialized == 0, "not cleared");

  PASS();
  return 0;
}

static int test_recovery_authority_from_keypair(void) {
  TEST(recovery_authority_from_keypair);

  nwep_keypair kp;
  nwep_recovery_authority ra;
  int rv;

  rv = nwep_keypair_generate(&kp);
  ASSERT(rv == 0, "keypair gen failed");

  rv = nwep_recovery_authority_from_keypair(&ra, &kp);
  ASSERT(rv == 0, "from_keypair failed");

  const uint8_t *pubkey = nwep_recovery_authority_get_pubkey(&ra);
  ASSERT(memcmp(pubkey, kp.pubkey, 32) == 0, "pubkey mismatch");

  nwep_recovery_authority_clear(&ra);
  nwep_keypair_clear(&kp);

  PASS();
  return 0;
}

/*
 * Managed Identity Tests
 */

static int test_managed_identity_new(void) {
  TEST(managed_identity_new);

  nwep_keypair kp;
  nwep_recovery_authority ra;
  nwep_managed_identity identity;
  nwep_tstamp now = 1000000000ULL * NWEP_SECONDS;
  int rv;

  rv = nwep_keypair_generate(&kp);
  ASSERT(rv == 0, "keypair gen failed");

  rv = nwep_recovery_authority_new(&ra);
  ASSERT(rv == 0, "ra gen failed");

  rv = nwep_managed_identity_new(&identity, &kp, &ra, now);
  ASSERT(rv == 0, "identity creation failed");

  ASSERT(identity.key_count == 1, "wrong key count");
  ASSERT(identity.has_recovery == 1, "no recovery");
  ASSERT(identity.revoked == 0, "should not be revoked");

  const nwep_keypair *active = nwep_managed_identity_get_active(&identity);
  ASSERT(active != NULL, "no active key");
  ASSERT(memcmp(active->pubkey, kp.pubkey, 32) == 0, "wrong active key");

  nwep_managed_identity_clear(&identity);
  nwep_recovery_authority_clear(&ra);
  nwep_keypair_clear(&kp);

  PASS();
  return 0;
}

static int test_managed_identity_no_recovery(void) {
  TEST(managed_identity_no_recovery);

  nwep_keypair kp;
  nwep_managed_identity identity;
  nwep_tstamp now = 1000000000ULL * NWEP_SECONDS;
  int rv;

  rv = nwep_keypair_generate(&kp);
  ASSERT(rv == 0, "keypair gen failed");

  rv = nwep_managed_identity_new(&identity, &kp, NULL, now);
  ASSERT(rv == 0, "identity creation failed");

  ASSERT(identity.has_recovery == 0, "should have no recovery");

  nwep_managed_identity_clear(&identity);
  nwep_keypair_clear(&kp);

  PASS();
  return 0;
}

static int test_managed_identity_rotate(void) {
  TEST(managed_identity_rotate);

  nwep_keypair kp;
  nwep_managed_identity identity;
  nwep_tstamp now = 1000000000ULL * NWEP_SECONDS;
  int rv;

  rv = nwep_keypair_generate(&kp);
  ASSERT(rv == 0, "keypair gen failed");

  rv = nwep_managed_identity_new(&identity, &kp, NULL, now);
  ASSERT(rv == 0, "identity creation failed");

  uint8_t old_pubkey[32];
  memcpy(old_pubkey, kp.pubkey, 32);

  /* Rotate key */
  now += 100 * NWEP_SECONDS;
  rv = nwep_managed_identity_rotate(&identity, now);
  ASSERT(rv == 0, "rotation failed");

  /* Should have 2 active keys now */
  const nwep_keypair *keys[2];
  size_t count = nwep_managed_identity_get_active_keys(&identity, keys, 2);
  ASSERT(count == 2, "should have 2 active keys");

  /* New key should be different */
  const nwep_keypair *active = nwep_managed_identity_get_active(&identity);
  ASSERT(memcmp(active->pubkey, old_pubkey, 32) != 0, "key should have changed");

  /* Cannot rotate again (max 2 active) */
  rv = nwep_managed_identity_rotate(&identity, now);
  ASSERT(rv == NWEP_ERR_IDENTITY_ROTATION_IN_PROGRESS, "should block rotation");

  nwep_managed_identity_clear(&identity);
  nwep_keypair_clear(&kp);

  PASS();
  return 0;
}

static int test_managed_identity_key_expiry(void) {
  TEST(managed_identity_key_expiry);

  nwep_keypair kp;
  nwep_managed_identity identity;
  nwep_tstamp now = 1000000000ULL * NWEP_SECONDS;
  int rv;

  rv = nwep_keypair_generate(&kp);
  ASSERT(rv == 0, "keypair gen failed");

  rv = nwep_managed_identity_new(&identity, &kp, NULL, now);
  ASSERT(rv == 0, "identity creation failed");

  /* Rotate key */
  now += 100 * NWEP_SECONDS;
  rv = nwep_managed_identity_rotate(&identity, now);
  ASSERT(rv == 0, "rotation failed");

  /* Both keys active */
  const nwep_keypair *keys[2];
  size_t count = nwep_managed_identity_get_active_keys(&identity, keys, 2);
  ASSERT(count == 2, "should have 2 active keys");

  /* Advance past overlap period (5 minutes = 300 seconds) */
  now += (NWEP_KEY_OVERLAP_SECONDS + 1) * NWEP_SECONDS;
  nwep_managed_identity_update(&identity, now);

  /* Only new key should be active */
  count = nwep_managed_identity_get_active_keys(&identity, keys, 2);
  ASSERT(count == 1, "should have 1 active key after expiry");

  /* Can rotate again now */
  rv = nwep_managed_identity_rotate(&identity, now);
  ASSERT(rv == 0, "should allow rotation after expiry");

  nwep_managed_identity_clear(&identity);
  nwep_keypair_clear(&kp);

  PASS();
  return 0;
}

static int test_managed_identity_revoke(void) {
  TEST(managed_identity_revoke);

  nwep_keypair kp;
  nwep_recovery_authority ra;
  nwep_managed_identity identity;
  nwep_tstamp now = 1000000000ULL * NWEP_SECONDS;
  int rv;

  rv = nwep_keypair_generate(&kp);
  ASSERT(rv == 0, "keypair gen failed");

  rv = nwep_recovery_authority_new(&ra);
  ASSERT(rv == 0, "ra gen failed");

  rv = nwep_managed_identity_new(&identity, &kp, &ra, now);
  ASSERT(rv == 0, "identity creation failed");

  /* Revoke identity */
  now += 1000 * NWEP_SECONDS;
  rv = nwep_managed_identity_revoke(&identity, &ra, now);
  ASSERT(rv == 0, "revocation failed");

  ASSERT(nwep_managed_identity_is_revoked(&identity), "should be revoked");

  /* No active keys */
  const nwep_keypair *active = nwep_managed_identity_get_active(&identity);
  ASSERT(active == NULL, "should have no active keys");

  /* Cannot revoke again */
  rv = nwep_managed_identity_revoke(&identity, &ra, now);
  ASSERT(rv == NWEP_ERR_IDENTITY_REVOKED, "should reject double revoke");

  /* Verify revocation record */
  rv = nwep_managed_identity_verify_revocation(&identity.revocation);
  ASSERT(rv == 0, "revocation verification failed");

  nwep_managed_identity_clear(&identity);
  nwep_recovery_authority_clear(&ra);
  nwep_keypair_clear(&kp);

  PASS();
  return 0;
}

static int test_managed_identity_revoke_wrong_ra(void) {
  TEST(managed_identity_revoke_wrong_ra);

  nwep_keypair kp;
  nwep_recovery_authority ra1, ra2;
  nwep_managed_identity identity;
  nwep_tstamp now = 1000000000ULL * NWEP_SECONDS;
  int rv;

  rv = nwep_keypair_generate(&kp);
  ASSERT(rv == 0, "keypair gen failed");

  rv = nwep_recovery_authority_new(&ra1);
  ASSERT(rv == 0, "ra1 gen failed");

  rv = nwep_recovery_authority_new(&ra2);
  ASSERT(rv == 0, "ra2 gen failed");

  rv = nwep_managed_identity_new(&identity, &kp, &ra1, now);
  ASSERT(rv == 0, "identity creation failed");

  /* Try to revoke with wrong RA */
  rv = nwep_managed_identity_revoke(&identity, &ra2, now);
  ASSERT(rv == NWEP_ERR_IDENTITY_RECOVERY_MISMATCH, "should reject wrong RA");

  ASSERT(!nwep_managed_identity_is_revoked(&identity), "should not be revoked");

  nwep_managed_identity_clear(&identity);
  nwep_recovery_authority_clear(&ra1);
  nwep_recovery_authority_clear(&ra2);
  nwep_keypair_clear(&kp);

  PASS();
  return 0;
}

static int test_managed_identity_revoke_no_recovery(void) {
  TEST(managed_identity_revoke_no_recovery);

  nwep_keypair kp;
  nwep_recovery_authority ra;
  nwep_managed_identity identity;
  nwep_tstamp now = 1000000000ULL * NWEP_SECONDS;
  int rv;

  rv = nwep_keypair_generate(&kp);
  ASSERT(rv == 0, "keypair gen failed");

  rv = nwep_recovery_authority_new(&ra);
  ASSERT(rv == 0, "ra gen failed");

  /* Create identity without recovery */
  rv = nwep_managed_identity_new(&identity, &kp, NULL, now);
  ASSERT(rv == 0, "identity creation failed");

  /* Cannot revoke without recovery authority */
  rv = nwep_managed_identity_revoke(&identity, &ra, now);
  ASSERT(rv == NWEP_ERR_IDENTITY_NO_RECOVERY, "should reject no recovery");

  nwep_managed_identity_clear(&identity);
  nwep_recovery_authority_clear(&ra);
  nwep_keypair_clear(&kp);

  PASS();
  return 0;
}

static int test_revoked_identity_no_rotate(void) {
  TEST(revoked_identity_no_rotate);

  nwep_keypair kp;
  nwep_recovery_authority ra;
  nwep_managed_identity identity;
  nwep_tstamp now = 1000000000ULL * NWEP_SECONDS;
  int rv;

  rv = nwep_keypair_generate(&kp);
  ASSERT(rv == 0, "keypair gen failed");

  rv = nwep_recovery_authority_new(&ra);
  ASSERT(rv == 0, "ra gen failed");

  rv = nwep_managed_identity_new(&identity, &kp, &ra, now);
  ASSERT(rv == 0, "identity creation failed");

  /* Revoke */
  rv = nwep_managed_identity_revoke(&identity, &ra, now);
  ASSERT(rv == 0, "revocation failed");

  /* Cannot rotate revoked identity */
  rv = nwep_managed_identity_rotate(&identity, now);
  ASSERT(rv == NWEP_ERR_IDENTITY_REVOKED, "should reject rotation");

  nwep_managed_identity_clear(&identity);
  nwep_recovery_authority_clear(&ra);
  nwep_keypair_clear(&kp);

  PASS();
  return 0;
}

int main(void) {
  printf("Key Lifecycle Tests (Phase 12)\n");
  printf("==============================\n\n");

  printf("Shamir Secret Sharing:\n");
  test_shamir_split_combine_2of3();
  test_shamir_split_combine_3of5();
  test_shamir_invalid_params();
  test_shamir_duplicate_indices();

  printf("\nRecovery Authority:\n");
  test_recovery_authority_new();
  test_recovery_authority_from_keypair();

  printf("\nManaged Identity:\n");
  test_managed_identity_new();
  test_managed_identity_no_recovery();
  test_managed_identity_rotate();
  test_managed_identity_key_expiry();
  test_managed_identity_revoke();
  test_managed_identity_revoke_wrong_ra();
  test_managed_identity_revoke_no_recovery();
  test_revoked_identity_no_rotate();

  printf("\n==============================\n");
  printf("Tests: %d/%d passed\n", tests_passed, tests_run);

  return tests_passed == tests_run ? 0 : 1;
}
