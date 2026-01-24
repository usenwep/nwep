/*
 * nwep - Anchor Coordination Tests (Phase 14)
 */
#include <nwep/nwep.h>

#include <stdio.h>
#include <stdlib.h>
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
 * BLS Key Management Tests
 */

static int test_bls_keypair_generate(void) {
  TEST(bls_keypair_generate);

  nwep_bls_keypair kp1, kp2;
  int rv;

  rv = nwep_bls_keypair_generate(&kp1);
  ASSERT(rv == 0, "keypair generation failed");

  rv = nwep_bls_keypair_generate(&kp2);
  ASSERT(rv == 0, "second keypair generation failed");

  /* Keys should be different */
  ASSERT(memcmp(kp1.pubkey, kp2.pubkey, NWEP_BLS_PUBKEY_LEN) != 0,
         "generated keys should be unique");

  PASS();
  return 0;
}

static int test_bls_keypair_from_seed(void) {
  TEST(bls_keypair_from_seed);

  nwep_bls_keypair kp1, kp2;
  uint8_t seed[32];
  int rv;

  memset(seed, 0x42, sizeof(seed));

  rv = nwep_bls_keypair_from_seed(&kp1, seed, sizeof(seed));
  ASSERT(rv == 0, "keypair from seed failed");

  rv = nwep_bls_keypair_from_seed(&kp2, seed, sizeof(seed));
  ASSERT(rv == 0, "second keypair from seed failed");

  /* Same seed should produce same keys */
  ASSERT(memcmp(kp1.pubkey, kp2.pubkey, NWEP_BLS_PUBKEY_LEN) == 0,
         "deterministic generation should be consistent");
  ASSERT(memcmp(kp1.privkey, kp2.privkey, NWEP_BLS_PRIVKEY_LEN) == 0,
         "private keys should match");

  PASS();
  return 0;
}

static int test_bls_pubkey_serialize(void) {
  TEST(bls_pubkey_serialize);

  nwep_bls_keypair kp;
  nwep_bls_pubkey pk;
  uint8_t buf[NWEP_BLS_PUBKEY_LEN];
  int rv;

  rv = nwep_bls_keypair_generate(&kp);
  ASSERT(rv == 0, "keypair generation failed");

  /* Deserialize from keypair */
  rv = nwep_bls_pubkey_deserialize(&pk, kp.pubkey);
  ASSERT(rv == 0, "pubkey deserialize failed");

  /* Serialize back */
  rv = nwep_bls_pubkey_serialize(buf, &pk);
  ASSERT(rv == 0, "pubkey serialize failed");

  ASSERT(memcmp(buf, kp.pubkey, NWEP_BLS_PUBKEY_LEN) == 0,
         "round-trip serialization should match");

  PASS();
  return 0;
}

/*
 * BLS Signing and Verification Tests
 */

static int test_bls_sign_verify(void) {
  TEST(bls_sign_verify);

  nwep_bls_keypair kp;
  nwep_bls_pubkey pk;
  nwep_bls_sig sig;
  uint8_t msg[] = "test message";
  int rv;

  rv = nwep_bls_keypair_generate(&kp);
  ASSERT(rv == 0, "keypair generation failed");

  /* Sign message */
  rv = nwep_bls_sign(&sig, &kp, msg, sizeof(msg) - 1);
  ASSERT(rv == 0, "signing failed");

  /* Verify signature */
  memcpy(pk.data, kp.pubkey, NWEP_BLS_PUBKEY_LEN);
  rv = nwep_bls_verify(&pk, &sig, msg, sizeof(msg) - 1);
  ASSERT(rv == 0, "verification failed");

  /* Verify should fail with wrong message */
  uint8_t wrong_msg[] = "wrong message";
  rv = nwep_bls_verify(&pk, &sig, wrong_msg, sizeof(wrong_msg) - 1);
  ASSERT(rv != 0, "verification should fail with wrong message");

  PASS();
  return 0;
}

static int test_bls_aggregate_sigs(void) {
  TEST(bls_aggregate_sigs);

  nwep_bls_keypair kps[3];
  nwep_bls_pubkey pks[3];
  nwep_bls_sig sigs[3];
  nwep_bls_sig agg_sig;
  uint8_t msg[] = "aggregation test";
  int rv;

  /* Generate 3 keypairs and sign the same message */
  for (int i = 0; i < 3; i++) {
    uint8_t seed[32];
    memset(seed, (uint8_t)i, sizeof(seed));
    rv = nwep_bls_keypair_from_seed(&kps[i], seed, sizeof(seed));
    ASSERT(rv == 0, "keypair generation failed");

    memcpy(pks[i].data, kps[i].pubkey, NWEP_BLS_PUBKEY_LEN);

    rv = nwep_bls_sign(&sigs[i], &kps[i], msg, sizeof(msg) - 1);
    ASSERT(rv == 0, "signing failed");
  }

  /* Aggregate signatures */
  rv = nwep_bls_aggregate_sigs(&agg_sig, sigs, 3);
  ASSERT(rv == 0, "aggregation failed");

  /* Verify aggregated signature */
  rv = nwep_bls_verify_aggregate(pks, 3, &agg_sig, msg, sizeof(msg) - 1);
  ASSERT(rv == 0, "aggregate verification failed");

  /* Verify should fail with wrong number of public keys */
  rv = nwep_bls_verify_aggregate(pks, 2, &agg_sig, msg, sizeof(msg) - 1);
  ASSERT(rv != 0, "aggregate verification should fail with wrong pks");

  PASS();
  return 0;
}

/*
 * Anchor Set Tests
 */

static int test_anchor_set_new(void) {
  TEST(anchor_set_new);

  nwep_anchor_set *set;
  int rv;

  rv = nwep_anchor_set_new(&set, 5);
  ASSERT(rv == 0, "anchor set creation failed");
  ASSERT(nwep_anchor_set_size(set) == 0, "initial size should be 0");
  ASSERT(nwep_anchor_set_threshold(set) == 5, "threshold should be 5");

  nwep_anchor_set_free(set);

  PASS();
  return 0;
}

static int test_anchor_set_add_remove(void) {
  TEST(anchor_set_add_remove);

  nwep_anchor_set *set;
  nwep_bls_keypair kp1, kp2;
  nwep_bls_pubkey pk1, pk2;
  int rv;

  rv = nwep_anchor_set_new(&set, 2);
  ASSERT(rv == 0, "anchor set creation failed");

  /* Generate two anchors */
  uint8_t seed1[32], seed2[32];
  memset(seed1, 1, sizeof(seed1));
  memset(seed2, 2, sizeof(seed2));
  nwep_bls_keypair_from_seed(&kp1, seed1, sizeof(seed1));
  nwep_bls_keypair_from_seed(&kp2, seed2, sizeof(seed2));
  memcpy(pk1.data, kp1.pubkey, NWEP_BLS_PUBKEY_LEN);
  memcpy(pk2.data, kp2.pubkey, NWEP_BLS_PUBKEY_LEN);

  /* Add first as built-in */
  rv = nwep_anchor_set_add(set, &pk1, 1);
  ASSERT(rv == 0, "adding builtin anchor failed");
  ASSERT(nwep_anchor_set_size(set) == 1, "size should be 1");

  /* Add second as non-builtin */
  rv = nwep_anchor_set_add(set, &pk2, 0);
  ASSERT(rv == 0, "adding anchor failed");
  ASSERT(nwep_anchor_set_size(set) == 2, "size should be 2");

  /* Check contains */
  ASSERT(nwep_anchor_set_contains(set, &pk1) == 1, "should contain pk1");
  ASSERT(nwep_anchor_set_contains(set, &pk2) == 1, "should contain pk2");

  /* Cannot remove builtin */
  rv = nwep_anchor_set_remove(set, &pk1);
  ASSERT(rv != 0, "should not be able to remove builtin");

  /* Can remove non-builtin */
  rv = nwep_anchor_set_remove(set, &pk2);
  ASSERT(rv == 0, "should be able to remove non-builtin");
  ASSERT(nwep_anchor_set_size(set) == 1, "size should be 1 after remove");
  ASSERT(nwep_anchor_set_contains(set, &pk2) == 0, "should not contain pk2");

  nwep_anchor_set_free(set);

  PASS();
  return 0;
}

/*
 * Checkpoint Tests
 */

static int test_checkpoint_new(void) {
  TEST(checkpoint_new);

  nwep_checkpoint cp;
  nwep_merkle_hash root;
  int rv;

  memset(root.data, 0xAB, 32);

  rv = nwep_checkpoint_new(&cp, 1, 1000000000ULL, &root, 100);
  ASSERT(rv == 0, "checkpoint creation failed");
  ASSERT(cp.epoch == 1, "epoch should be 1");
  ASSERT(cp.log_size == 100, "log_size should be 100");
  ASSERT(cp.num_signers == 0, "should have no signers initially");

  PASS();
  return 0;
}

static int test_checkpoint_sign_verify(void) {
  TEST(checkpoint_sign_verify);

  nwep_checkpoint cp;
  nwep_merkle_hash root;
  nwep_anchor_set *anchor_set;
  nwep_bls_keypair kps[3];
  nwep_bls_pubkey pks[3];
  int rv;

  /* Setup anchor set with threshold 2 */
  rv = nwep_anchor_set_new(&anchor_set, 2);
  ASSERT(rv == 0, "anchor set creation failed");

  /* Generate 3 anchor keypairs */
  for (int i = 0; i < 3; i++) {
    uint8_t seed[32];
    memset(seed, (uint8_t)(i + 10), sizeof(seed));
    rv = nwep_bls_keypair_from_seed(&kps[i], seed, sizeof(seed));
    ASSERT(rv == 0, "keypair generation failed");
    memcpy(pks[i].data, kps[i].pubkey, NWEP_BLS_PUBKEY_LEN);
    rv = nwep_anchor_set_add(anchor_set, &pks[i], 0);
    ASSERT(rv == 0, "anchor add failed");
  }

  /* Create checkpoint */
  memset(root.data, 0xCD, 32);
  rv = nwep_checkpoint_new(&cp, 42, 1234567890ULL * NWEP_SECONDS, &root, 500);
  ASSERT(rv == 0, "checkpoint creation failed");

  /* Sign with first anchor - should not verify (threshold not met) */
  rv = nwep_checkpoint_sign(&cp, &kps[0]);
  ASSERT(rv == 0, "first signature failed");
  ASSERT(cp.num_signers == 1, "should have 1 signer");

  rv = nwep_checkpoint_verify(&cp, anchor_set);
  ASSERT(rv != 0, "should not verify with only 1 signer");

  /* Sign with second anchor - should verify now (threshold met) */
  rv = nwep_checkpoint_sign(&cp, &kps[1]);
  ASSERT(rv == 0, "second signature failed");
  ASSERT(cp.num_signers == 2, "should have 2 signers");

  rv = nwep_checkpoint_verify(&cp, anchor_set);
  ASSERT(rv == 0, "verification should succeed with 2 signers");

  /* Sign with third anchor - should still verify */
  rv = nwep_checkpoint_sign(&cp, &kps[2]);
  ASSERT(rv == 0, "third signature failed");
  ASSERT(cp.num_signers == 3, "should have 3 signers");

  rv = nwep_checkpoint_verify(&cp, anchor_set);
  ASSERT(rv == 0, "verification should succeed with 3 signers");

  nwep_anchor_set_free(anchor_set);

  PASS();
  return 0;
}

static int test_checkpoint_encode_decode(void) {
  TEST(checkpoint_encode_decode);

  nwep_checkpoint cp, decoded;
  nwep_merkle_hash root;
  nwep_bls_keypair kp;
  uint8_t buf[2048];
  nwep_ssize len;
  int rv;

  /* Create and sign checkpoint */
  memset(root.data, 0xEF, 32);
  rv = nwep_checkpoint_new(&cp, 123, 9876543210ULL * NWEP_SECONDS, &root, 1000);
  ASSERT(rv == 0, "checkpoint creation failed");

  uint8_t seed[32];
  memset(seed, 0x55, sizeof(seed));
  rv = nwep_bls_keypair_from_seed(&kp, seed, sizeof(seed));
  ASSERT(rv == 0, "keypair generation failed");

  rv = nwep_checkpoint_sign(&cp, &kp);
  ASSERT(rv == 0, "signing failed");

  /* Encode */
  len = nwep_checkpoint_encode(buf, sizeof(buf), &cp);
  ASSERT(len > 0, "encoding failed");

  /* Decode */
  rv = nwep_checkpoint_decode(&decoded, buf, (size_t)len);
  ASSERT(rv == 0, "decoding failed");

  /* Verify fields match */
  ASSERT(decoded.epoch == cp.epoch, "epoch mismatch");
  ASSERT(decoded.timestamp == cp.timestamp, "timestamp mismatch");
  ASSERT(memcmp(decoded.merkle_root.data, cp.merkle_root.data, 32) == 0,
         "merkle_root mismatch");
  ASSERT(decoded.log_size == cp.log_size, "log_size mismatch");
  ASSERT(decoded.num_signers == cp.num_signers, "num_signers mismatch");
  ASSERT(memcmp(decoded.signature.data, cp.signature.data, NWEP_BLS_SIG_LEN) == 0,
         "signature mismatch");

  PASS();
  return 0;
}

static int test_checkpoint_message(void) {
  TEST(checkpoint_message);

  nwep_checkpoint cp1, cp2;
  nwep_merkle_hash root;
  uint8_t msg1[64], msg2[64];
  nwep_ssize len1, len2;

  memset(root.data, 0x11, 32);

  /* Same checkpoint should produce same message */
  nwep_checkpoint_new(&cp1, 1, 1000000000ULL, &root, 50);
  nwep_checkpoint_new(&cp2, 1, 1000000000ULL, &root, 50);

  len1 = nwep_checkpoint_message(msg1, sizeof(msg1), &cp1);
  len2 = nwep_checkpoint_message(msg2, sizeof(msg2), &cp2);

  ASSERT(len1 == 56, "message should be 56 bytes");
  ASSERT(len1 == len2, "lengths should match");
  ASSERT(memcmp(msg1, msg2, (size_t)len1) == 0, "messages should match");

  /* Different epoch should produce different message */
  nwep_checkpoint_new(&cp2, 2, 1000000000ULL, &root, 50);
  len2 = nwep_checkpoint_message(msg2, sizeof(msg2), &cp2);
  ASSERT(memcmp(msg1, msg2, (size_t)len1) != 0, "different epochs should differ");

  PASS();
  return 0;
}

int main(void) {
  printf("Anchor Coordination Tests (Phase 14)\n");
  printf("====================================\n\n");

  printf("BLS Key Management:\n");
  test_bls_keypair_generate();
  test_bls_keypair_from_seed();
  test_bls_pubkey_serialize();

  printf("\nBLS Signing & Verification:\n");
  test_bls_sign_verify();
  test_bls_aggregate_sigs();

  printf("\nAnchor Set:\n");
  test_anchor_set_new();
  test_anchor_set_add_remove();

  printf("\nCheckpoints:\n");
  test_checkpoint_new();
  test_checkpoint_sign_verify();
  test_checkpoint_encode_decode();
  test_checkpoint_message();

  printf("\n====================================\n");
  printf("Tests: %d/%d passed\n", tests_passed, tests_run);

  return tests_passed == tests_run ? 0 : 1;
}
