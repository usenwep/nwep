/*
 * nwep - Merkle Log Tests (Phase 13)
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
 * In-memory storage for testing
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
 * In-memory index storage for testing
 */

#define MAX_INDEX_ENTRIES 100

typedef struct {
  nwep_log_index_entry entries[MAX_INDEX_ENTRIES];
  int valid[MAX_INDEX_ENTRIES];
  size_t count;
} mem_index_storage;

static int mem_index_get(void *user_data, const nwep_nodeid *nodeid,
                         nwep_log_index_entry *entry) {
  mem_index_storage *storage = (mem_index_storage *)user_data;
  for (size_t i = 0; i < storage->count; i++) {
    if (storage->valid[i] &&
        memcmp(storage->entries[i].nodeid.data, nodeid->data, NWEP_NODEID_LEN) ==
            0) {
      *entry = storage->entries[i];
      return 0;
    }
  }
  return NWEP_ERR_STORAGE_KEY_NOT_FOUND;
}

static int mem_index_put(void *user_data, const nwep_log_index_entry *entry) {
  mem_index_storage *storage = (mem_index_storage *)user_data;

  /* Check for existing entry to update */
  for (size_t i = 0; i < storage->count; i++) {
    if (storage->valid[i] &&
        memcmp(storage->entries[i].nodeid.data, entry->nodeid.data,
               NWEP_NODEID_LEN) == 0) {
      storage->entries[i] = *entry;
      return 0;
    }
  }

  /* Add new entry */
  if (storage->count >= MAX_INDEX_ENTRIES) {
    return NWEP_ERR_STORAGE_WRITE_ERROR;
  }
  storage->entries[storage->count] = *entry;
  storage->valid[storage->count] = 1;
  storage->count++;
  return 0;
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
 * Entry Serialization Tests
 */

static int test_entry_encode_decode(void) {
  TEST(entry_encode_decode);

  nwep_merkle_entry entry, decoded;
  uint8_t buf[NWEP_LOG_ENTRY_MAX_SIZE];
  nwep_ssize len;
  int rv;

  make_test_entry(&entry, NWEP_LOG_ENTRY_KEY_BINDING, 42);

  len = nwep_merkle_entry_encode(buf, sizeof(buf), &entry);
  ASSERT(len > 0, "encode failed");
  ASSERT(len == 201, "unexpected encoded length");

  rv = nwep_merkle_entry_decode(&decoded, buf, (size_t)len);
  ASSERT(rv == 0, "decode failed");

  ASSERT(decoded.type == entry.type, "type mismatch");
  ASSERT(decoded.timestamp == entry.timestamp, "timestamp mismatch");
  ASSERT(memcmp(decoded.nodeid.data, entry.nodeid.data, NWEP_NODEID_LEN) == 0,
         "nodeid mismatch");
  ASSERT(memcmp(decoded.pubkey, entry.pubkey, NWEP_ED25519_PUBKEY_LEN) == 0,
         "pubkey mismatch");
  ASSERT(memcmp(decoded.signature, entry.signature, NWEP_ED25519_SIG_LEN) == 0,
         "signature mismatch");

  PASS();
  return 0;
}

static int test_entry_encode_all_types(void) {
  TEST(entry_encode_all_types);

  nwep_merkle_entry entry, decoded;
  uint8_t buf[NWEP_LOG_ENTRY_MAX_SIZE];
  nwep_ssize len;
  int rv;

  nwep_merkle_entry_type types[] = {NWEP_LOG_ENTRY_KEY_BINDING,
                                     NWEP_LOG_ENTRY_KEY_ROTATION,
                                     NWEP_LOG_ENTRY_REVOCATION,
                                     NWEP_LOG_ENTRY_ANCHOR_CHANGE};

  for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
    make_test_entry(&entry, types[i], (uint8_t)i);

    len = nwep_merkle_entry_encode(buf, sizeof(buf), &entry);
    ASSERT(len > 0, "encode failed");

    rv = nwep_merkle_entry_decode(&decoded, buf, (size_t)len);
    ASSERT(rv == 0, "decode failed");
    ASSERT(decoded.type == types[i], "type mismatch");
  }

  PASS();
  return 0;
}

/*
 * Hash Computation Tests
 */

static int test_leaf_hash(void) {
  TEST(leaf_hash);

  nwep_merkle_entry entry1, entry2;
  nwep_merkle_hash hash1, hash2;
  int rv;

  make_test_entry(&entry1, NWEP_LOG_ENTRY_KEY_BINDING, 1);
  make_test_entry(&entry2, NWEP_LOG_ENTRY_KEY_BINDING, 2);

  rv = nwep_merkle_leaf_hash(&hash1, &entry1);
  ASSERT(rv == 0, "hash1 failed");

  rv = nwep_merkle_leaf_hash(&hash2, &entry2);
  ASSERT(rv == 0, "hash2 failed");

  /* Different entries should have different hashes */
  ASSERT(memcmp(hash1.data, hash2.data, 32) != 0, "hashes should differ");

  /* Same entry should produce same hash */
  nwep_merkle_hash hash1_again;
  rv = nwep_merkle_leaf_hash(&hash1_again, &entry1);
  ASSERT(rv == 0, "hash1_again failed");
  ASSERT(memcmp(hash1.data, hash1_again.data, 32) == 0, "hash not deterministic");

  PASS();
  return 0;
}

static int test_node_hash(void) {
  TEST(node_hash);

  nwep_merkle_hash left, right, parent1, parent2;
  int rv;

  memset(left.data, 0xAA, 32);
  memset(right.data, 0xBB, 32);

  rv = nwep_merkle_node_hash(&parent1, &left, &right);
  ASSERT(rv == 0, "node hash failed");

  /* Order matters */
  rv = nwep_merkle_node_hash(&parent2, &right, &left);
  ASSERT(rv == 0, "reversed node hash failed");
  ASSERT(memcmp(parent1.data, parent2.data, 32) != 0, "order should matter");

  PASS();
  return 0;
}

/*
 * Merkle Log Tests
 */

static int test_log_append_get(void) {
  TEST(log_append_get);

  mem_log_storage storage;
  memset(&storage, 0, sizeof(storage));

  nwep_log_storage callbacks = {.append = mem_log_append,
                                .get = mem_log_get,
                                .size = mem_log_size,
                                .user_data = &storage};

  nwep_merkle_log *log;
  int rv = nwep_merkle_log_new(&log, &callbacks);
  ASSERT(rv == 0, "log creation failed");

  ASSERT(nwep_merkle_log_size(log) == 0, "initial size should be 0");

  /* Append entries */
  nwep_merkle_entry entry1, entry2, retrieved;
  uint64_t idx1, idx2;

  make_test_entry(&entry1, NWEP_LOG_ENTRY_KEY_BINDING, 1);
  rv = nwep_merkle_log_append(log, &entry1, &idx1);
  ASSERT(rv == 0, "append1 failed");
  ASSERT(idx1 == 0, "first index should be 0");

  make_test_entry(&entry2, NWEP_LOG_ENTRY_KEY_ROTATION, 2);
  rv = nwep_merkle_log_append(log, &entry2, &idx2);
  ASSERT(rv == 0, "append2 failed");
  ASSERT(idx2 == 1, "second index should be 1");

  ASSERT(nwep_merkle_log_size(log) == 2, "size should be 2");

  /* Retrieve entries */
  rv = nwep_merkle_log_get(log, 0, &retrieved);
  ASSERT(rv == 0, "get0 failed");
  ASSERT(retrieved.type == NWEP_LOG_ENTRY_KEY_BINDING, "wrong type at 0");

  rv = nwep_merkle_log_get(log, 1, &retrieved);
  ASSERT(rv == 0, "get1 failed");
  ASSERT(retrieved.type == NWEP_LOG_ENTRY_KEY_ROTATION, "wrong type at 1");

  /* Out of range */
  rv = nwep_merkle_log_get(log, 2, &retrieved);
  ASSERT(rv == NWEP_ERR_STORAGE_INDEX_OUT_OF_RANGE, "should fail for index 2");

  nwep_merkle_log_free(log);

  PASS();
  return 0;
}

static int test_log_root_single(void) {
  TEST(log_root_single);

  mem_log_storage storage;
  memset(&storage, 0, sizeof(storage));

  nwep_log_storage callbacks = {.append = mem_log_append,
                                .get = mem_log_get,
                                .size = mem_log_size,
                                .user_data = &storage};

  nwep_merkle_log *log;
  nwep_merkle_log_new(&log, &callbacks);

  nwep_merkle_entry entry;
  make_test_entry(&entry, NWEP_LOG_ENTRY_KEY_BINDING, 1);
  nwep_merkle_log_append(log, &entry, NULL);

  nwep_merkle_hash root, leaf;
  int rv = nwep_merkle_log_root(log, &root);
  ASSERT(rv == 0, "root computation failed");

  /* For single entry, root should equal leaf hash */
  rv = nwep_merkle_leaf_hash(&leaf, &entry);
  ASSERT(rv == 0, "leaf hash failed");
  ASSERT(memcmp(root.data, leaf.data, 32) == 0, "root should equal leaf for single entry");

  nwep_merkle_log_free(log);

  PASS();
  return 0;
}

static int test_log_root_multiple(void) {
  TEST(log_root_multiple);

  mem_log_storage storage;
  memset(&storage, 0, sizeof(storage));

  nwep_log_storage callbacks = {.append = mem_log_append,
                                .get = mem_log_get,
                                .size = mem_log_size,
                                .user_data = &storage};

  nwep_merkle_log *log;
  nwep_merkle_log_new(&log, &callbacks);

  /* Add 4 entries */
  for (int i = 0; i < 4; i++) {
    nwep_merkle_entry entry;
    make_test_entry(&entry, NWEP_LOG_ENTRY_KEY_BINDING, (uint8_t)i);
    nwep_merkle_log_append(log, &entry, NULL);
  }

  nwep_merkle_hash root1, root2;
  int rv = nwep_merkle_log_root(log, &root1);
  ASSERT(rv == 0, "root1 computation failed");

  /* Root should be deterministic */
  rv = nwep_merkle_log_root(log, &root2);
  ASSERT(rv == 0, "root2 computation failed");
  ASSERT(memcmp(root1.data, root2.data, 32) == 0, "root should be deterministic");

  nwep_merkle_log_free(log);

  PASS();
  return 0;
}

static int test_log_proof_verify(void) {
  TEST(log_proof_verify);

  mem_log_storage storage;
  memset(&storage, 0, sizeof(storage));

  nwep_log_storage callbacks = {.append = mem_log_append,
                                .get = mem_log_get,
                                .size = mem_log_size,
                                .user_data = &storage};

  nwep_merkle_log *log;
  nwep_merkle_log_new(&log, &callbacks);

  /* Add 7 entries (non-power of 2 to test edge cases) */
  for (int i = 0; i < 7; i++) {
    nwep_merkle_entry entry;
    make_test_entry(&entry, NWEP_LOG_ENTRY_KEY_BINDING, (uint8_t)i);
    nwep_merkle_log_append(log, &entry, NULL);
  }

  nwep_merkle_hash root;
  int rv = nwep_merkle_log_root(log, &root);
  ASSERT(rv == 0, "root computation failed");

  /* Generate and verify proof for each entry */
  for (uint64_t i = 0; i < 7; i++) {
    nwep_merkle_proof proof;
    rv = nwep_merkle_log_prove(log, i, &proof);
    ASSERT(rv == 0, "proof generation failed");
    ASSERT(proof.index == i, "proof index wrong");
    ASSERT(proof.log_size == 7, "proof log_size wrong");

    rv = nwep_merkle_proof_verify(&proof, &root);
    ASSERT(rv == 0, "proof verification failed");
  }

  /* Verify with wrong root should fail */
  nwep_merkle_proof proof;
  nwep_merkle_log_prove(log, 0, &proof);
  nwep_merkle_hash wrong_root;
  memset(wrong_root.data, 0xFF, 32);
  rv = nwep_merkle_proof_verify(&proof, &wrong_root);
  ASSERT(rv == NWEP_ERR_TRUST_INVALID_PROOF, "should fail with wrong root");

  nwep_merkle_log_free(log);

  PASS();
  return 0;
}

static int test_log_proof_single(void) {
  TEST(log_proof_single);

  mem_log_storage storage;
  memset(&storage, 0, sizeof(storage));

  nwep_log_storage callbacks = {.append = mem_log_append,
                                .get = mem_log_get,
                                .size = mem_log_size,
                                .user_data = &storage};

  nwep_merkle_log *log;
  nwep_merkle_log_new(&log, &callbacks);

  nwep_merkle_entry entry;
  make_test_entry(&entry, NWEP_LOG_ENTRY_KEY_BINDING, 1);
  nwep_merkle_log_append(log, &entry, NULL);

  nwep_merkle_hash root;
  nwep_merkle_log_root(log, &root);

  nwep_merkle_proof proof;
  int rv = nwep_merkle_log_prove(log, 0, &proof);
  ASSERT(rv == 0, "proof generation failed");
  ASSERT(proof.depth == 0, "single entry should have depth 0");

  rv = nwep_merkle_proof_verify(&proof, &root);
  ASSERT(rv == 0, "proof verification failed");

  nwep_merkle_log_free(log);

  PASS();
  return 0;
}

/*
 * Log Index Tests
 */

static int test_index_lookup_update(void) {
  TEST(index_lookup_update);

  mem_index_storage storage;
  memset(&storage, 0, sizeof(storage));

  nwep_log_index_storage callbacks = {
      .get = mem_index_get, .put = mem_index_put, .user_data = &storage};

  nwep_log_index *index;
  int rv = nwep_log_index_new(&index, &callbacks);
  ASSERT(rv == 0, "index creation failed");

  /* Create entry */
  nwep_merkle_entry entry;
  make_test_entry(&entry, NWEP_LOG_ENTRY_KEY_BINDING, 1);

  /* Update index */
  rv = nwep_log_index_update(index, &entry, 0);
  ASSERT(rv == 0, "index update failed");

  /* Lookup */
  nwep_log_index_entry idx_entry;
  rv = nwep_log_index_lookup(index, &entry.nodeid, &idx_entry);
  ASSERT(rv == 0, "lookup failed");
  ASSERT(idx_entry.log_index == 0, "wrong log index");
  ASSERT(memcmp(idx_entry.pubkey, entry.pubkey, NWEP_ED25519_PUBKEY_LEN) == 0,
         "wrong pubkey");
  ASSERT(idx_entry.revoked == 0, "should not be revoked");

  /* Update with rotation */
  nwep_merkle_entry rotation;
  make_test_entry(&rotation, NWEP_LOG_ENTRY_KEY_ROTATION, 1);
  memset(rotation.pubkey, 0xAA, NWEP_ED25519_PUBKEY_LEN); /* New key */

  rv = nwep_log_index_update(index, &rotation, 1);
  ASSERT(rv == 0, "rotation update failed");

  rv = nwep_log_index_lookup(index, &rotation.nodeid, &idx_entry);
  ASSERT(rv == 0, "lookup after rotation failed");
  ASSERT(idx_entry.log_index == 1, "wrong log index after rotation");

  /* Update with revocation */
  nwep_merkle_entry revocation;
  make_test_entry(&revocation, NWEP_LOG_ENTRY_REVOCATION, 1);

  rv = nwep_log_index_update(index, &revocation, 2);
  ASSERT(rv == 0, "revocation update failed");

  rv = nwep_log_index_lookup(index, &revocation.nodeid, &idx_entry);
  ASSERT(rv == 0, "lookup after revocation failed");
  ASSERT(idx_entry.revoked == 1, "should be revoked");

  nwep_log_index_free(index);

  PASS();
  return 0;
}

static int test_index_not_found(void) {
  TEST(index_not_found);

  mem_index_storage storage;
  memset(&storage, 0, sizeof(storage));

  nwep_log_index_storage callbacks = {
      .get = mem_index_get, .put = mem_index_put, .user_data = &storage};

  nwep_log_index *index;
  nwep_log_index_new(&index, &callbacks);

  nwep_nodeid nodeid;
  memset(nodeid.data, 0x42, NWEP_NODEID_LEN);

  nwep_log_index_entry entry;
  int rv = nwep_log_index_lookup(index, &nodeid, &entry);
  ASSERT(rv == NWEP_ERR_STORAGE_KEY_NOT_FOUND, "should return not found");

  nwep_log_index_free(index);

  PASS();
  return 0;
}

int main(void) {
  printf("Merkle Log Tests (Phase 13)\n");
  printf("===========================\n\n");

  printf("Entry Serialization:\n");
  test_entry_encode_decode();
  test_entry_encode_all_types();

  printf("\nHash Computation:\n");
  test_leaf_hash();
  test_node_hash();

  printf("\nMerkle Log:\n");
  test_log_append_get();
  test_log_root_single();
  test_log_root_multiple();
  test_log_proof_verify();
  test_log_proof_single();

  printf("\nLog Index:\n");
  test_index_lookup_update();
  test_index_not_found();

  printf("\n===========================\n");
  printf("Tests: %d/%d passed\n", tests_passed, tests_run);

  return tests_passed == tests_run ? 0 : 1;
}
