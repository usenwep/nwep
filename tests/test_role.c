/*
 * nwep - Server Role Tests (Phase 16)
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
 * In-memory storage for testing log server
 */

#define MAX_ENTRIES 1000

typedef struct {
  uint8_t data[MAX_ENTRIES][NWEP_LOG_ENTRY_MAX_SIZE];
  size_t lengths[MAX_ENTRIES];
  uint64_t count;
} mem_log_storage;

static int mem_log_append(void *user_data, uint64_t index, const uint8_t *entry,
                          size_t entry_len) {
  mem_log_storage *storage = (mem_log_storage *)user_data;
  if (index >= MAX_ENTRIES || entry_len > NWEP_LOG_ENTRY_MAX_SIZE) {
    return NWEP_ERR_STORAGE_WRITE_ERROR;
  }
  memcpy(storage->data[index], entry, entry_len);
  storage->lengths[index] = entry_len;
  if (index >= storage->count) {
    storage->count = index + 1;
  }
  return 0;
}

static nwep_ssize mem_log_get(void *user_data, uint64_t index, uint8_t *buf,
                              size_t buflen) {
  mem_log_storage *storage = (mem_log_storage *)user_data;
  if (index >= storage->count) {
    return NWEP_ERR_STORAGE_INDEX_OUT_OF_RANGE;
  }
  size_t len = storage->lengths[index];
  if (buflen < len) {
    return NWEP_ERR_PROTO_MSG_TOO_LARGE;
  }
  memcpy(buf, storage->data[index], len);
  return (nwep_ssize)len;
}

static uint64_t mem_log_size(void *user_data) {
  mem_log_storage *storage = (mem_log_storage *)user_data;
  return storage->count;
}

/*
 * Helper: create a test entry
 */
static void make_test_entry(nwep_merkle_entry *entry, nwep_merkle_entry_type type,
                            uint8_t seed) {
  memset(entry, 0, sizeof(*entry));
  entry->type = type;
  entry->timestamp = (nwep_tstamp)seed * 1000000ULL * NWEP_SECONDS;
  memset(entry->nodeid.data, seed, NWEP_NODEID_LEN);
  memset(entry->pubkey, seed + 1, NWEP_ED25519_PUBKEY_LEN);
  memset(entry->prev_pubkey, seed + 2, NWEP_ED25519_PUBKEY_LEN);
  memset(entry->recovery_pubkey, seed + 3, NWEP_ED25519_PUBKEY_LEN);
  memset(entry->signature, seed + 4, NWEP_ED25519_SIG_LEN);
}

/*
 * Test authorization callback for log server (allows all for testing)
 */
static int test_log_authorize(void *user_data, const nwep_nodeid *nodeid,
                              const nwep_merkle_entry *entry) {
  (void)user_data;
  (void)nodeid;
  (void)entry;
  return 0; /* Allow all writes */
}

/*
 * Test proposal callback for anchor server (allows all proposals)
 */
static int test_on_proposal(void *user_data, const nwep_checkpoint *cp) {
  (void)user_data;
  (void)cp;
  return 0; /* Accept all proposals */
}

/*
 * Role Conversion Tests
 */

static int test_role_from_str(void) {
  TEST(role_from_str);

  nwep_server_role role;

  role = nwep_role_from_str("regular");
  ASSERT(role == NWEP_ROLE_REGULAR, "regular string should parse");

  role = nwep_role_from_str("log_server");
  ASSERT(role == NWEP_ROLE_LOG_SERVER, "log_server string should parse");

  role = nwep_role_from_str("anchor");
  ASSERT(role == NWEP_ROLE_ANCHOR, "anchor string should parse");

  /* Unknown role should default to regular */
  role = nwep_role_from_str("unknown");
  ASSERT(role == NWEP_ROLE_REGULAR, "unknown should default to regular");

  role = nwep_role_from_str(NULL);
  ASSERT(role == NWEP_ROLE_REGULAR, "NULL should default to regular");

  PASS();
  return 0;
}

static int test_role_to_str(void) {
  TEST(role_to_str);

  const char *str;

  str = nwep_role_to_str(NWEP_ROLE_REGULAR);
  ASSERT(str != NULL, "regular should return string");
  ASSERT(strcmp(str, "regular") == 0, "regular string mismatch");

  str = nwep_role_to_str(NWEP_ROLE_LOG_SERVER);
  ASSERT(str != NULL, "log_server should return string");
  ASSERT(strcmp(str, "log_server") == 0, "log_server string mismatch");

  str = nwep_role_to_str(NWEP_ROLE_ANCHOR);
  ASSERT(str != NULL, "anchor should return string");
  ASSERT(strcmp(str, "anchor") == 0, "anchor string mismatch");

  /* Invalid role should return "regular" */
  str = nwep_role_to_str((nwep_server_role)99);
  ASSERT(str != NULL, "invalid should return string");
  ASSERT(strcmp(str, "regular") == 0, "invalid should default to regular");

  PASS();
  return 0;
}

static int test_role_roundtrip(void) {
  TEST(role_roundtrip);

  nwep_server_role roles[] = {NWEP_ROLE_REGULAR, NWEP_ROLE_LOG_SERVER, NWEP_ROLE_ANCHOR};

  for (size_t i = 0; i < sizeof(roles) / sizeof(roles[0]); i++) {
    const char *str = nwep_role_to_str(roles[i]);
    ASSERT(str != NULL, "to_str failed");

    nwep_server_role parsed = nwep_role_from_str(str);
    ASSERT(parsed == roles[i], "roundtrip failed");
  }

  PASS();
  return 0;
}

/*
 * Proof Encode/Decode Tests
 */

static int test_proof_encode_decode_empty(void) {
  TEST(proof_encode_decode_empty);

  nwep_merkle_proof proof, decoded;
  uint8_t buf[NWEP_MERKLE_PROOF_MAX_SIZE];
  nwep_ssize len;
  int rv;

  /* Single entry proof (depth 0) */
  memset(&proof, 0, sizeof(proof));
  proof.index = 0;
  proof.log_size = 1;
  memset(proof.leaf_hash.data, 0xAA, 32);
  proof.depth = 0;

  len = nwep_merkle_proof_encode(buf, sizeof(buf), &proof);
  ASSERT(len > 0, "encode failed");
  ASSERT(len == 8 + 8 + 32 + 4, "unexpected encoded length for depth 0");

  rv = nwep_merkle_proof_decode(&decoded, buf, (size_t)len);
  ASSERT(rv == 0, "decode failed");

  ASSERT(decoded.index == proof.index, "index mismatch");
  ASSERT(decoded.log_size == proof.log_size, "log_size mismatch");
  ASSERT(memcmp(decoded.leaf_hash.data, proof.leaf_hash.data, 32) == 0, "leaf_hash mismatch");
  ASSERT(decoded.depth == proof.depth, "depth mismatch");

  PASS();
  return 0;
}

static int test_proof_encode_decode_deep(void) {
  TEST(proof_encode_decode_deep);

  nwep_merkle_proof proof, decoded;
  uint8_t buf[NWEP_MERKLE_PROOF_MAX_SIZE];
  nwep_ssize len;
  int rv;

  /* Multi-level proof */
  memset(&proof, 0, sizeof(proof));
  proof.index = 42;
  proof.log_size = 100;
  memset(proof.leaf_hash.data, 0xBB, 32);
  proof.depth = 7;

  for (size_t i = 0; i < proof.depth; i++) {
    memset(proof.siblings[i].data, (uint8_t)(0x10 + i), 32);
  }

  len = nwep_merkle_proof_encode(buf, sizeof(buf), &proof);
  ASSERT(len > 0, "encode failed");
  ASSERT(len == 8 + 8 + 32 + 4 + 7 * 32, "unexpected encoded length");

  rv = nwep_merkle_proof_decode(&decoded, buf, (size_t)len);
  ASSERT(rv == 0, "decode failed");

  ASSERT(decoded.index == proof.index, "index mismatch");
  ASSERT(decoded.log_size == proof.log_size, "log_size mismatch");
  ASSERT(memcmp(decoded.leaf_hash.data, proof.leaf_hash.data, 32) == 0, "leaf_hash mismatch");
  ASSERT(decoded.depth == proof.depth, "depth mismatch");

  for (size_t i = 0; i < proof.depth; i++) {
    ASSERT(memcmp(decoded.siblings[i].data, proof.siblings[i].data, 32) == 0, "sibling mismatch");
  }

  PASS();
  return 0;
}

static int test_proof_encode_buffer_too_small(void) {
  TEST(proof_encode_buffer_too_small);

  nwep_merkle_proof proof;
  uint8_t buf[10]; /* Too small */
  nwep_ssize len;

  memset(&proof, 0, sizeof(proof));
  proof.index = 0;
  proof.log_size = 1;
  proof.depth = 0;

  len = nwep_merkle_proof_encode(buf, sizeof(buf), &proof);
  ASSERT(len < 0, "encode should fail with small buffer");

  PASS();
  return 0;
}

static int test_proof_decode_truncated(void) {
  TEST(proof_decode_truncated);

  nwep_merkle_proof decoded;
  uint8_t buf[10];
  int rv;

  memset(buf, 0, sizeof(buf));
  rv = nwep_merkle_proof_decode(&decoded, buf, 10);
  ASSERT(rv < 0, "decode should fail with truncated data");

  PASS();
  return 0;
}

/*
 * Log Server Tests
 */

static int test_log_server_create_free(void) {
  TEST(log_server_create_free);

  mem_log_storage storage;
  memset(&storage, 0, sizeof(storage));

  nwep_log_storage log_callbacks = {.append = mem_log_append,
                                     .get = mem_log_get,
                                     .size = mem_log_size,
                                     .user_data = &storage};

  nwep_merkle_log *log;
  int rv = nwep_merkle_log_new(&log, &log_callbacks);
  ASSERT(rv == 0, "log creation failed");

  nwep_log_server_settings settings = {.authorize = test_log_authorize,
                                        .user_data = NULL};

  nwep_log_server *server;
  rv = nwep_log_server_new(&server, log, &settings);
  ASSERT(rv == 0, "log server creation failed");
  ASSERT(server != NULL, "server should not be NULL");

  nwep_log_server_free(server);
  /* Note: log is also freed by log_server_free */

  PASS();
  return 0;
}

static int test_log_server_get_log(void) {
  TEST(log_server_get_log);

  mem_log_storage storage;
  memset(&storage, 0, sizeof(storage));

  nwep_log_storage log_callbacks = {.append = mem_log_append,
                                     .get = mem_log_get,
                                     .size = mem_log_size,
                                     .user_data = &storage};

  nwep_merkle_log *log;
  nwep_merkle_log_new(&log, &log_callbacks);

  nwep_log_server_settings settings = {.authorize = test_log_authorize,
                                        .user_data = NULL};

  nwep_log_server *server;
  nwep_log_server_new(&server, log, &settings);

  nwep_merkle_log *retrieved = nwep_log_server_get_log(server);
  ASSERT(retrieved == log, "get_log should return underlying log");

  nwep_log_server_free(server);

  PASS();
  return 0;
}

/*
 * Anchor Server Tests
 */

static int test_anchor_server_create_free(void) {
  TEST(anchor_server_create_free);

  /* Generate BLS keypair from seed */
  nwep_bls_keypair keypair;
  uint8_t seed[32];
  memset(seed, 0x42, sizeof(seed));
  int rv = nwep_bls_keypair_from_seed(&keypair, seed, sizeof(seed));
  ASSERT(rv == 0, "BLS keygen failed");

  /* Create anchor set */
  nwep_anchor_set *anchors;
  rv = nwep_anchor_set_new(&anchors, 1); /* threshold of 1 */
  ASSERT(rv == 0, "anchor set creation failed");

  /* Wrap pubkey in nwep_bls_pubkey struct */
  nwep_bls_pubkey pubkey;
  memcpy(pubkey.data, keypair.pubkey, NWEP_BLS_PUBKEY_LEN);

  rv = nwep_anchor_set_add(anchors, &pubkey, 1); /* builtin=1 */
  ASSERT(rv == 0, "anchor set add failed");

  nwep_anchor_server_settings settings = {.on_proposal = test_on_proposal,
                                           .user_data = NULL};

  nwep_anchor_server *server;
  rv = nwep_anchor_server_new(&server, &keypair, anchors, &settings);
  ASSERT(rv == 0, "anchor server creation failed");
  ASSERT(server != NULL, "server should not be NULL");

  nwep_anchor_server_free(server);
  /* Note: anchors is also freed by anchor_server_free */

  PASS();
  return 0;
}

static int test_anchor_server_add_checkpoint(void) {
  TEST(anchor_server_add_checkpoint);

  /* Generate BLS keypair from seed */
  nwep_bls_keypair keypair;
  uint8_t seed[32];
  memset(seed, 0x42, sizeof(seed));
  nwep_bls_keypair_from_seed(&keypair, seed, sizeof(seed));

  /* Create anchor set */
  nwep_anchor_set *anchors;
  nwep_anchor_set_new(&anchors, 1);

  /* Wrap pubkey in nwep_bls_pubkey struct */
  nwep_bls_pubkey pubkey;
  memcpy(pubkey.data, keypair.pubkey, NWEP_BLS_PUBKEY_LEN);
  nwep_anchor_set_add(anchors, &pubkey, 1);

  nwep_anchor_server_settings settings = {.on_proposal = test_on_proposal,
                                           .user_data = NULL};

  nwep_anchor_server *server;
  nwep_anchor_server_new(&server, &keypair, anchors, &settings);

  /* Create a checkpoint */
  nwep_merkle_hash merkle_root;
  memset(merkle_root.data, 0xAA, 32);

  nwep_checkpoint checkpoint;
  int rv = nwep_checkpoint_new(&checkpoint, 1, 1000 * NWEP_SECONDS, &merkle_root, 100);
  ASSERT(rv == 0, "checkpoint creation failed");

  /* Sign the checkpoint with our anchor key */
  rv = nwep_checkpoint_sign(&checkpoint, &keypair);
  ASSERT(rv == 0, "checkpoint sign failed");

  rv = nwep_anchor_server_add_checkpoint(server, &checkpoint);
  ASSERT(rv == 0, "add checkpoint failed");

  /* Retrieve latest */
  nwep_checkpoint retrieved;
  rv = nwep_anchor_server_get_latest(server, &retrieved);
  ASSERT(rv == 0, "get latest failed");
  ASSERT(retrieved.epoch == checkpoint.epoch, "epoch mismatch");
  ASSERT(retrieved.log_size == checkpoint.log_size, "log_size mismatch");
  ASSERT(memcmp(retrieved.merkle_root.data, checkpoint.merkle_root.data, 32) == 0, "merkle_root mismatch");

  /* Retrieve by epoch */
  rv = nwep_anchor_server_get_checkpoint(server, 1, &retrieved);
  ASSERT(rv == 0, "get checkpoint by epoch failed");
  ASSERT(retrieved.epoch == 1, "epoch mismatch");

  /* Non-existent epoch */
  rv = nwep_anchor_server_get_checkpoint(server, 99, &retrieved);
  ASSERT(rv == NWEP_ERR_TRUST_ENTRY_NOT_FOUND, "should fail for unknown epoch");

  nwep_anchor_server_free(server);

  PASS();
  return 0;
}

static int test_anchor_server_create_proposal(void) {
  TEST(anchor_server_create_proposal);

  /* Generate BLS keypair from seed */
  nwep_bls_keypair keypair;
  uint8_t seed[32];
  memset(seed, 0x42, sizeof(seed));
  nwep_bls_keypair_from_seed(&keypair, seed, sizeof(seed));

  /* Create anchor set */
  nwep_anchor_set *anchors;
  nwep_anchor_set_new(&anchors, 1);

  /* Wrap pubkey in nwep_bls_pubkey struct */
  nwep_bls_pubkey pubkey;
  memcpy(pubkey.data, keypair.pubkey, NWEP_BLS_PUBKEY_LEN);
  nwep_anchor_set_add(anchors, &pubkey, 1);

  nwep_anchor_server_settings settings = {.on_proposal = test_on_proposal,
                                           .user_data = NULL};

  nwep_anchor_server *server;
  nwep_anchor_server_new(&server, &keypair, anchors, &settings);

  /* Create a merkle log to checkpoint */
  mem_log_storage storage;
  memset(&storage, 0, sizeof(storage));

  nwep_log_storage log_callbacks = {.append = mem_log_append,
                                     .get = mem_log_get,
                                     .size = mem_log_size,
                                     .user_data = &storage};

  nwep_merkle_log *log;
  nwep_merkle_log_new(&log, &log_callbacks);

  /* Add some entries to the log */
  for (int i = 0; i < 5; i++) {
    nwep_merkle_entry entry;
    make_test_entry(&entry, NWEP_LOG_ENTRY_KEY_BINDING, (uint8_t)i);
    nwep_merkle_log_append(log, &entry, NULL);
  }

  /* Create a proposal */
  nwep_checkpoint proposal;
  int rv = nwep_anchor_server_create_proposal(server, log, 1, 1234 * NWEP_SECONDS, &proposal);
  ASSERT(rv == 0, "create proposal failed");
  ASSERT(proposal.epoch == 1, "epoch should be 1");
  ASSERT(proposal.log_size == 5, "log_size should be 5");

  nwep_merkle_log_free(log);
  nwep_anchor_server_free(server);

  PASS();
  return 0;
}

static int test_anchor_server_sign_proposal(void) {
  TEST(anchor_server_sign_proposal);

  /* Generate BLS keypair from seed */
  nwep_bls_keypair keypair;
  uint8_t seed[32];
  memset(seed, 0x42, sizeof(seed));
  nwep_bls_keypair_from_seed(&keypair, seed, sizeof(seed));

  /* Create anchor set */
  nwep_anchor_set *anchors;
  nwep_anchor_set_new(&anchors, 1);

  /* Wrap pubkey in nwep_bls_pubkey struct */
  nwep_bls_pubkey pubkey;
  memcpy(pubkey.data, keypair.pubkey, NWEP_BLS_PUBKEY_LEN);
  nwep_anchor_set_add(anchors, &pubkey, 1);

  nwep_anchor_server_settings settings = {.on_proposal = test_on_proposal,
                                           .user_data = NULL};

  nwep_anchor_server *server;
  nwep_anchor_server_new(&server, &keypair, anchors, &settings);

  /* Create a merkle log to checkpoint */
  mem_log_storage storage;
  memset(&storage, 0, sizeof(storage));

  nwep_log_storage log_callbacks = {.append = mem_log_append,
                                     .get = mem_log_get,
                                     .size = mem_log_size,
                                     .user_data = &storage};

  nwep_merkle_log *log;
  nwep_merkle_log_new(&log, &log_callbacks);

  /* Add some entries to the log */
  for (int i = 0; i < 5; i++) {
    nwep_merkle_entry entry;
    make_test_entry(&entry, NWEP_LOG_ENTRY_KEY_BINDING, (uint8_t)i);
    nwep_merkle_log_append(log, &entry, NULL);
  }

  /* Create a proposal */
  nwep_checkpoint proposal;
  nwep_anchor_server_create_proposal(server, log, 1, 5678 * NWEP_SECONDS, &proposal);

  /* Sign the proposal (modifies checkpoint in place) */
  int rv = nwep_anchor_server_sign_proposal(server, &proposal);
  ASSERT(rv == 0, "sign proposal failed");

  /* Verify signature was added */
  ASSERT(proposal.num_signers == 1, "should have one signer");

  /* Verify signature bytes are non-zero */
  int all_zero = 1;
  for (size_t i = 0; i < sizeof(proposal.signature.data); i++) {
    if (proposal.signature.data[i] != 0) {
      all_zero = 0;
      break;
    }
  }
  ASSERT(!all_zero, "signature should not be all zeros");

  nwep_merkle_log_free(log);
  nwep_anchor_server_free(server);

  PASS();
  return 0;
}

int main(void) {
  printf("Server Role Tests (Phase 16)\n");
  printf("============================\n\n");

  printf("Role Conversion:\n");
  test_role_from_str();
  test_role_to_str();
  test_role_roundtrip();

  printf("\nProof Encode/Decode:\n");
  test_proof_encode_decode_empty();
  test_proof_encode_decode_deep();
  test_proof_encode_buffer_too_small();
  test_proof_decode_truncated();

  printf("\nLog Server:\n");
  test_log_server_create_free();
  test_log_server_get_log();

  printf("\nAnchor Server:\n");
  test_anchor_server_create_free();
  test_anchor_server_add_checkpoint();
  test_anchor_server_create_proposal();
  test_anchor_server_sign_proposal();

  printf("\n============================\n");
  printf("Tests: %d/%d passed\n", tests_passed, tests_run);

  return tests_passed == tests_run ? 0 : 1;
}
