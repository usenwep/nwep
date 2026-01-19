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

#include <openssl/evp.h>

#include <stdlib.h>
#include <string.h>

/*
 * Entry serialization format:
 * [1 byte type][8 bytes timestamp BE][32 bytes nodeid][32 bytes pubkey]
 * [32 bytes prev_pubkey][32 bytes recovery_pubkey][64 bytes signature]
 * Total: 201 bytes
 */
#define ENTRY_SERIALIZED_SIZE 201

struct nwep_merkle_log {
  nwep_log_storage storage;
  uint64_t cached_size;
  int size_cached;
};

struct nwep_log_index {
  nwep_log_index_storage storage;
};

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

nwep_ssize nwep_merkle_entry_encode(uint8_t *buf, size_t buflen,
                                    const nwep_merkle_entry *entry) {
  uint8_t *p;

  if (buf == NULL || entry == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (buflen < ENTRY_SERIALIZED_SIZE) {
    return NWEP_ERR_PROTO_MSG_TOO_LARGE;
  }

  p = buf;
  *p++ = (uint8_t)entry->type;
  p = put_uint64be(p, entry->timestamp);
  memcpy(p, entry->nodeid.data, NWEP_NODEID_LEN);
  p += NWEP_NODEID_LEN;
  memcpy(p, entry->pubkey, NWEP_ED25519_PUBKEY_LEN);
  p += NWEP_ED25519_PUBKEY_LEN;
  memcpy(p, entry->prev_pubkey, NWEP_ED25519_PUBKEY_LEN);
  p += NWEP_ED25519_PUBKEY_LEN;
  memcpy(p, entry->recovery_pubkey, NWEP_ED25519_PUBKEY_LEN);
  p += NWEP_ED25519_PUBKEY_LEN;
  memcpy(p, entry->signature, NWEP_ED25519_SIG_LEN);
  p += NWEP_ED25519_SIG_LEN;

  return (nwep_ssize)(p - buf);
}

int nwep_merkle_entry_decode(nwep_merkle_entry *entry, const uint8_t *data,
                             size_t datalen) {
  const uint8_t *p;

  if (entry == NULL || data == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (datalen < ENTRY_SERIALIZED_SIZE) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  p = data;
  entry->type = (nwep_merkle_entry_type)*p++;
  if (entry->type < NWEP_LOG_ENTRY_KEY_BINDING ||
      entry->type > NWEP_LOG_ENTRY_ANCHOR_CHANGE) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }
  p = get_uint64be(&entry->timestamp, p);
  memcpy(entry->nodeid.data, p, NWEP_NODEID_LEN);
  p += NWEP_NODEID_LEN;
  memcpy(entry->pubkey, p, NWEP_ED25519_PUBKEY_LEN);
  p += NWEP_ED25519_PUBKEY_LEN;
  memcpy(entry->prev_pubkey, p, NWEP_ED25519_PUBKEY_LEN);
  p += NWEP_ED25519_PUBKEY_LEN;
  memcpy(entry->recovery_pubkey, p, NWEP_ED25519_PUBKEY_LEN);
  p += NWEP_ED25519_PUBKEY_LEN;
  memcpy(entry->signature, p, NWEP_ED25519_SIG_LEN);

  return 0;
}

int nwep_merkle_leaf_hash(nwep_merkle_hash *hash,
                          const nwep_merkle_entry *entry) {
  uint8_t buf[1 + ENTRY_SERIALIZED_SIZE];
  nwep_ssize entry_len;
  EVP_MD_CTX *ctx;
  unsigned int hash_len;

  if (hash == NULL || entry == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  buf[0] = 0x00; /* leaf prefix */
  entry_len = nwep_merkle_entry_encode(buf + 1, sizeof(buf) - 1, entry);
  if (entry_len < 0) {
    return (int)entry_len;
  }

  ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(ctx, buf, 1 + (size_t)entry_len) != 1 ||
      EVP_DigestFinal_ex(ctx, hash->data, &hash_len) != 1) {
    EVP_MD_CTX_free(ctx);
    return NWEP_ERR_CRYPTO_HASH_FAILED;
  }

  EVP_MD_CTX_free(ctx);
  return 0;
}

int nwep_merkle_node_hash(nwep_merkle_hash *hash, const nwep_merkle_hash *left,
                          const nwep_merkle_hash *right) {
  uint8_t buf[1 + 32 + 32];
  EVP_MD_CTX *ctx;
  unsigned int hash_len;

  if (hash == NULL || left == NULL || right == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  buf[0] = 0x01; /* node prefix */
  memcpy(buf + 1, left->data, 32);
  memcpy(buf + 33, right->data, 32);

  ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(ctx, buf, sizeof(buf)) != 1 ||
      EVP_DigestFinal_ex(ctx, hash->data, &hash_len) != 1) {
    EVP_MD_CTX_free(ctx);
    return NWEP_ERR_CRYPTO_HASH_FAILED;
  }
  EVP_MD_CTX_free(ctx);
  return 0;
}

int nwep_merkle_proof_verify(const nwep_merkle_proof *proof,
                             const nwep_merkle_hash *root) {
  nwep_merkle_hash current;
  uint64_t idx, level_size, split;
  uint8_t path[NWEP_MERKLE_PROOF_MAX_DEPTH]; /* 0=left, 1=right */
  size_t path_len;
  int rv;

  if (proof == NULL || root == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (proof->index >= proof->log_size) {
    return NWEP_ERR_STORAGE_INDEX_OUT_OF_RANGE;
  }

  idx = proof->index;
  level_size = proof->log_size;
  path_len = 0;

  while (level_size > 1 && path_len < NWEP_MERKLE_PROOF_MAX_DEPTH) {
    split = 1;
    while (split * 2 < level_size) {
      split *= 2;
    }

    if (idx < split) {
      path[path_len] = 0;
      level_size = split;
    } else {
      path[path_len] = 1;
      idx -= split;
      level_size -= split;
    }
    path_len++;
  }

  if (path_len != proof->depth) {
    return NWEP_ERR_TRUST_INVALID_PROOF;
  }

  memcpy(&current, &proof->leaf_hash, sizeof(nwep_merkle_hash));
  for (size_t i = proof->depth; i > 0; i--) {
    size_t level = i - 1;
    if (path[level] == 0) {
      rv = nwep_merkle_node_hash(&current, &current, &proof->siblings[level]);
    } else {
      rv = nwep_merkle_node_hash(&current, &proof->siblings[level], &current);
    }
    if (rv != 0) {
      return rv;
    }
  }

  if (memcmp(current.data, root->data, 32) != 0) {
    return NWEP_ERR_TRUST_INVALID_PROOF;
  }

  return 0;
}

int nwep_merkle_log_new(nwep_merkle_log **plog,
                        const nwep_log_storage *storage) {
  nwep_merkle_log *log;

  if (plog == NULL || storage == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (storage->append == NULL || storage->get == NULL ||
      storage->size == NULL) {
    return NWEP_ERR_CONFIG_VALIDATION_FAILED;
  }

  log = calloc(1, sizeof(*log));
  if (log == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  log->storage = *storage;

  *plog = log;
  return 0;
}

void nwep_merkle_log_free(nwep_merkle_log *log) {
  free(log);
}

int nwep_merkle_log_append(nwep_merkle_log *log, const nwep_merkle_entry *entry,
                           uint64_t *pindex) {
  uint8_t buf[ENTRY_SERIALIZED_SIZE];
  nwep_ssize entry_len;
  uint64_t index;
  int rv;

  if (log == NULL || entry == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Serialize entry */
  entry_len = nwep_merkle_entry_encode(buf, sizeof(buf), entry);
  if (entry_len < 0) {
    return (int)entry_len;
  }

  /* Get current size as new index */
  index = log->storage.size(log->storage.user_data);

  /* Append to storage */
  rv = log->storage.append(log->storage.user_data, index, buf,
                           (size_t)entry_len);
  if (rv != 0) {
    return rv;
  }

  /* Invalidate size cache */
  log->size_cached = 0;

  if (pindex != NULL) {
    *pindex = index;
  }

  return 0;
}

int nwep_merkle_log_get(nwep_merkle_log *log, uint64_t index,
                        nwep_merkle_entry *entry) {
  uint8_t buf[NWEP_LOG_ENTRY_MAX_SIZE];
  nwep_ssize entry_len;

  if (log == NULL || entry == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Get from storage */
  entry_len = log->storage.get(log->storage.user_data, index, buf, sizeof(buf));
  if (entry_len < 0) {
    return (int)entry_len;
  }

  /* Decode */
  return nwep_merkle_entry_decode(entry, buf, (size_t)entry_len);
}

uint64_t nwep_merkle_log_size(const nwep_merkle_log *log) {
  if (log == NULL) {
    return 0;
  }
  return log->storage.size(log->storage.user_data);
}

static int compute_entry_hash(nwep_merkle_log *log, uint64_t index,
                              nwep_merkle_hash *hash) {
  nwep_merkle_entry entry;
  int rv;

  rv = nwep_merkle_log_get(log, index, &entry);
  if (rv != 0) {
    return rv;
  }

  return nwep_merkle_leaf_hash(hash, &entry);
}

static int compute_subtree_hash(nwep_merkle_log *log, uint64_t start,
                                uint64_t size, nwep_merkle_hash *hash) {
  nwep_merkle_hash left, right;
  uint64_t split;
  int rv;

  if (size == 0) {
    memset(hash->data, 0, 32);
    return 0;
  }

  if (size == 1) {
    return compute_entry_hash(log, start, hash);
  }

  split = 1;
  while (split * 2 < size) {
    split *= 2;
  }

  rv = compute_subtree_hash(log, start, split, &left);
  if (rv != 0) {
    return rv;
  }

  rv = compute_subtree_hash(log, start + split, size - split, &right);
  if (rv != 0) {
    return rv;
  }

  return nwep_merkle_node_hash(hash, &left, &right);
}

int nwep_merkle_log_root(nwep_merkle_log *log, nwep_merkle_hash *root) {
  uint64_t size;

  if (log == NULL || root == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  size = nwep_merkle_log_size(log);
  return compute_subtree_hash(log, 0, size, root);
}

int nwep_merkle_log_prove(nwep_merkle_log *log, uint64_t index,
                          nwep_merkle_proof *proof) {
  uint64_t size, idx, level_size, start, split;
  int rv;

  if (log == NULL || proof == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  size = nwep_merkle_log_size(log);
  if (index >= size) {
    return NWEP_ERR_STORAGE_INDEX_OUT_OF_RANGE;
  }

  memset(proof, 0, sizeof(*proof));
  proof->index = index;
  proof->log_size = size;

  rv = compute_entry_hash(log, index, &proof->leaf_hash);
  if (rv != 0) {
    return rv;
  }

  idx = index;
  level_size = size;
  start = 0;
  proof->depth = 0;

  while (level_size > 1 && proof->depth < NWEP_MERKLE_PROOF_MAX_DEPTH) {
    split = 1;
    while (split * 2 < level_size) {
      split *= 2;
    }

    if (idx < split) {
      rv = compute_subtree_hash(log, start + split, level_size - split,
                                &proof->siblings[proof->depth]);
      level_size = split;
    } else {
      rv = compute_subtree_hash(log, start, split,
                                &proof->siblings[proof->depth]);
      start += split;
      idx -= split;
      level_size -= split;
    }

    if (rv != 0) {
      return rv;
    }

    proof->depth++;
  }

  return 0;
}

int nwep_log_index_new(nwep_log_index **pindex,
                       const nwep_log_index_storage *storage) {
  nwep_log_index *index;

  if (pindex == NULL || storage == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (storage->get == NULL || storage->put == NULL) {
    return NWEP_ERR_CONFIG_VALIDATION_FAILED;
  }

  index = calloc(1, sizeof(*index));
  if (index == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  index->storage = *storage;

  *pindex = index;
  return 0;
}

void nwep_log_index_free(nwep_log_index *index) {
  free(index);
}

int nwep_log_index_lookup(nwep_log_index *index, const nwep_nodeid *nodeid,
                          nwep_log_index_entry *entry) {
  if (index == NULL || nodeid == NULL || entry == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  return index->storage.get(index->storage.user_data, nodeid, entry);
}

int nwep_log_index_update(nwep_log_index *index, const nwep_merkle_entry *entry,
                          uint64_t log_idx) {
  nwep_log_index_entry idx_entry;

  if (index == NULL || entry == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(&idx_entry, 0, sizeof(idx_entry));
  memcpy(&idx_entry.nodeid, &entry->nodeid, sizeof(nwep_nodeid));
  memcpy(idx_entry.pubkey, entry->pubkey, NWEP_ED25519_PUBKEY_LEN);
  idx_entry.log_index = log_idx;

  if (entry->type == NWEP_LOG_ENTRY_REVOCATION) {
    idx_entry.revoked = 1;
  }

  return index->storage.put(index->storage.user_data, &idx_entry);
}

/*
 * Merkle proof wire format:
 * [8 bytes index BE][8 bytes log_size BE][32 bytes leaf_hash]
 * [4 bytes depth BE][depth * 32 bytes siblings]
 */
nwep_ssize nwep_merkle_proof_encode(uint8_t *buf, size_t buflen,
                                    const nwep_merkle_proof *proof) {
  uint8_t *p;
  size_t required;

  if (buf == NULL || proof == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (proof->depth > NWEP_MERKLE_PROOF_MAX_DEPTH) {
    return NWEP_ERR_INTERNAL_INVALID_ARG;
  }

  required = 8 + 8 + 32 + 4 + proof->depth * 32;
  if (buflen < required) {
    return NWEP_ERR_INTERNAL_NOBUF;
  }

  p = buf;
  *p++ = (uint8_t)(proof->index >> 56);
  *p++ = (uint8_t)(proof->index >> 48);
  *p++ = (uint8_t)(proof->index >> 40);
  *p++ = (uint8_t)(proof->index >> 32);
  *p++ = (uint8_t)(proof->index >> 24);
  *p++ = (uint8_t)(proof->index >> 16);
  *p++ = (uint8_t)(proof->index >> 8);
  *p++ = (uint8_t)(proof->index);
  *p++ = (uint8_t)(proof->log_size >> 56);
  *p++ = (uint8_t)(proof->log_size >> 48);
  *p++ = (uint8_t)(proof->log_size >> 40);
  *p++ = (uint8_t)(proof->log_size >> 32);
  *p++ = (uint8_t)(proof->log_size >> 24);
  *p++ = (uint8_t)(proof->log_size >> 16);
  *p++ = (uint8_t)(proof->log_size >> 8);
  *p++ = (uint8_t)(proof->log_size);
  memcpy(p, proof->leaf_hash.data, 32);
  p += 32;
  *p++ = (uint8_t)(proof->depth >> 24);
  *p++ = (uint8_t)(proof->depth >> 16);
  *p++ = (uint8_t)(proof->depth >> 8);
  *p++ = (uint8_t)(proof->depth);
  for (size_t i = 0; i < proof->depth; i++) {
    memcpy(p, proof->siblings[i].data, 32);
    p += 32;
  }

  return (nwep_ssize)(p - buf);
}

int nwep_merkle_proof_decode(nwep_merkle_proof *proof, const uint8_t *data,
                             size_t datalen) {
  const uint8_t *p;
  uint32_t depth;

  if (proof == NULL || data == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (datalen < 52) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  p = data;
  proof->index = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
                 ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
                 ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
                 ((uint64_t)p[6] << 8) | (uint64_t)p[7];
  p += 8;
  proof->log_size = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
                    ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
                    ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
                    ((uint64_t)p[6] << 8) | (uint64_t)p[7];
  p += 8;
  memcpy(proof->leaf_hash.data, p, 32);
  p += 32;
  depth = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
          ((uint32_t)p[2] << 8) | (uint32_t)p[3];
  p += 4;

  if (depth > NWEP_MERKLE_PROOF_MAX_DEPTH) {
    return NWEP_ERR_TRUST_INVALID_PROOF;
  }
  proof->depth = (size_t)depth;
  if (datalen < 52 + depth * 32) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }
  for (size_t i = 0; i < proof->depth; i++) {
    memcpy(proof->siblings[i].data, p, 32);
    p += 32;
  }

  return 0;
}
