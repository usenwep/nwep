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

#include <stdlib.h>
#include <string.h>

#define IDENTITY_CACHE_SIZE 256

typedef struct {
  nwep_verified_identity identity;
  int valid;
} identity_cache_entry;

struct nwep_trust_store {
  nwep_anchor_set *anchors;
  nwep_checkpoint checkpoints[NWEP_MAX_CHECKPOINTS];
  size_t checkpoint_count;
  uint64_t latest_epoch;
  nwep_trust_settings settings;
  nwep_trust_storage storage;
  identity_cache_entry identity_cache[IDENTITY_CACHE_SIZE];
};

void nwep_trust_settings_default(nwep_trust_settings *settings) {
  if (settings == NULL) {
    return;
  }
  *settings = (nwep_trust_settings){
      .staleness_warning_ns = NWEP_STALENESS_WARNING_NS,
      .staleness_reject_ns = NWEP_STALENESS_REJECT_NS,
      .identity_cache_ttl = NWEP_IDENTITY_CACHE_TTL,
      .anchor_threshold = NWEP_DEFAULT_ANCHOR_THRESHOLD,
  };
}

int nwep_trust_store_new(nwep_trust_store **pstore,
                          const nwep_trust_settings *settings,
                          const nwep_trust_storage *storage) {
  nwep_trust_store *store;
  nwep_trust_settings default_settings;
  int rv;

  if (pstore == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  store = calloc(1, sizeof(*store));
  if (store == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  if (settings != NULL) {
    store->settings = *settings;
  } else {
    nwep_trust_settings_default(&default_settings);
    store->settings = default_settings;
  }

  if (storage != NULL) {
    store->storage = *storage;
  }

  rv = nwep_anchor_set_new(&store->anchors, store->settings.anchor_threshold);
  if (rv != 0) {
    free(store);
    return rv;
  }

  if (store->storage.anchor_load != NULL) {
    nwep_bls_pubkey loaded_anchors[NWEP_MAX_ANCHORS];
    int count =
        store->storage.anchor_load(store->storage.user_data, loaded_anchors,
                                   NWEP_MAX_ANCHORS);
    if (count > 0) {
      for (int i = 0; i < count; i++) {
        nwep_anchor_set_add(store->anchors, &loaded_anchors[i], 0);
      }
    }
  }

  if (store->storage.checkpoint_load != NULL) {
    int count = store->storage.checkpoint_load(
        store->storage.user_data, store->checkpoints, NWEP_MAX_CHECKPOINTS);
    if (count > 0) {
      store->checkpoint_count = (size_t)count;
      for (size_t i = 0; i < store->checkpoint_count; i++) {
        if (store->checkpoints[i].epoch > store->latest_epoch) {
          store->latest_epoch = store->checkpoints[i].epoch;
        }
      }
    }
  }

  *pstore = store;
  return 0;
}

void nwep_trust_store_free(nwep_trust_store *store) {
  if (store == NULL) {
    return;
  }
  nwep_anchor_set_free(store->anchors);
  free(store);
}

int nwep_trust_store_add_anchor(nwep_trust_store *store,
                                 const nwep_bls_pubkey *pk, int builtin) {
  int rv;

  if (store == NULL || pk == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  rv = nwep_anchor_set_add(store->anchors, pk, builtin);
  if (rv != 0) {
    return rv;
  }

  if (store->storage.anchor_save != NULL && !builtin) {
    nwep_bls_pubkey anchors[NWEP_MAX_ANCHORS];
    size_t count = nwep_anchor_set_size(store->anchors);
    for (size_t i = 0; i < count; i++) {
      nwep_anchor_set_get(store->anchors, i, &anchors[i], NULL);
    }
    store->storage.anchor_save(store->storage.user_data, anchors, count);
  }

  return 0;
}

int nwep_trust_store_remove_anchor(nwep_trust_store *store,
                                    const nwep_bls_pubkey *pk) {
  int rv;

  if (store == NULL || pk == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  rv = nwep_anchor_set_remove(store->anchors, pk);
  if (rv != 0) {
    return rv;
  }

  if (store->storage.anchor_save != NULL) {
    nwep_bls_pubkey anchors[NWEP_MAX_ANCHORS];
    size_t count = nwep_anchor_set_size(store->anchors);
    for (size_t i = 0; i < count; i++) {
      nwep_anchor_set_get(store->anchors, i, &anchors[i], NULL);
    }
    store->storage.anchor_save(store->storage.user_data, anchors, count);
  }

  return 0;
}

const nwep_anchor_set *
nwep_trust_store_get_anchors(const nwep_trust_store *store) {
  if (store == NULL) {
    return NULL;
  }
  return store->anchors;
}

int nwep_trust_store_add_checkpoint(nwep_trust_store *store,
                                     const nwep_checkpoint *cp) {
  int rv;
  size_t idx;

  if (store == NULL || cp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  rv = nwep_checkpoint_verify(cp, store->anchors);
  if (rv != 0) {
    return rv;
  }

  rv = nwep_trust_store_check_equivocation(store, cp, NULL);
  if (rv != 0) {
    return rv;
  }

  idx = store->checkpoint_count;
  for (size_t i = 0; i < store->checkpoint_count; i++) {
    if (store->checkpoints[i].epoch == cp->epoch) {
      idx = i;
      break;
    }
  }

  if (idx == store->checkpoint_count) {
    if (store->checkpoint_count >= NWEP_MAX_CHECKPOINTS) {
      uint64_t oldest_epoch = UINT64_MAX;
      size_t oldest_idx = 0;
      for (size_t i = 0; i < store->checkpoint_count; i++) {
        if (store->checkpoints[i].epoch < oldest_epoch) {
          oldest_epoch = store->checkpoints[i].epoch;
          oldest_idx = i;
        }
      }
      idx = oldest_idx;
    } else {
      store->checkpoint_count++;
    }
  }

  memcpy(&store->checkpoints[idx], cp, sizeof(nwep_checkpoint));

  if (cp->epoch > store->latest_epoch) {
    store->latest_epoch = cp->epoch;
  }

  if (store->storage.checkpoint_save != NULL) {
    store->storage.checkpoint_save(store->storage.user_data, cp);
  }

  return 0;
}

int nwep_trust_store_get_latest_checkpoint(const nwep_trust_store *store,
                                            nwep_checkpoint *cp) {
  if (store == NULL || cp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (store->checkpoint_count == 0) {
    return NWEP_ERR_TRUST_ENTRY_NOT_FOUND;
  }

  for (size_t i = 0; i < store->checkpoint_count; i++) {
    if (store->checkpoints[i].epoch == store->latest_epoch) {
      memcpy(cp, &store->checkpoints[i], sizeof(nwep_checkpoint));
      return 0;
    }
  }

  return NWEP_ERR_TRUST_ENTRY_NOT_FOUND;
}

int nwep_trust_store_get_checkpoint(const nwep_trust_store *store,
                                     uint64_t epoch, nwep_checkpoint *cp) {
  if (store == NULL || cp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  for (size_t i = 0; i < store->checkpoint_count; i++) {
    if (store->checkpoints[i].epoch == epoch) {
      memcpy(cp, &store->checkpoints[i], sizeof(nwep_checkpoint));
      return 0;
    }
  }

  return NWEP_ERR_TRUST_ENTRY_NOT_FOUND;
}

size_t nwep_trust_store_checkpoint_count(const nwep_trust_store *store) {
  if (store == NULL) {
    return 0;
  }
  return store->checkpoint_count;
}

nwep_staleness nwep_trust_store_check_staleness(const nwep_trust_store *store,
                                                 nwep_tstamp now) {
  nwep_duration age;

  if (store == NULL || store->checkpoint_count == 0) {
    return NWEP_STALENESS_REJECT;
  }

  age = nwep_trust_store_get_staleness_age(store, now);

  if (age >= store->settings.staleness_reject_ns) {
    return NWEP_STALENESS_REJECT;
  }
  if (age >= store->settings.staleness_warning_ns) {
    return NWEP_STALENESS_WARNING;
  }
  return NWEP_STALENESS_FRESH;
}

nwep_duration nwep_trust_store_get_staleness_age(const nwep_trust_store *store,
                                                  nwep_tstamp now) {
  nwep_checkpoint latest;

  if (store == NULL || store->checkpoint_count == 0) {
    return 0;
  }

  if (nwep_trust_store_get_latest_checkpoint(store, &latest) != 0) {
    return 0;
  }

  if (now <= latest.timestamp) {
    return 0;
  }

  return now - latest.timestamp;
}

/*
 * identity_hash computes hash of |nodeid| for cache lookup.
 */
static size_t identity_hash(const nwep_nodeid *nodeid) {
  size_t hash = 0;
  for (size_t i = 0; i < NWEP_NODEID_LEN; i++) {
    hash = hash * 31 + nodeid->data[i];
  }
  return hash % IDENTITY_CACHE_SIZE;
}

int nwep_trust_store_verify_identity(nwep_trust_store *store,
                                      const nwep_merkle_entry *entry,
                                      const nwep_merkle_proof *proof,
                                      const nwep_checkpoint *checkpoint,
                                      nwep_tstamp now,
                                      nwep_verified_identity *result) {
  nwep_checkpoint cp;
  nwep_merkle_hash leaf_hash;
  int rv;

  if (store == NULL || entry == NULL || proof == NULL || result == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (checkpoint != NULL) {
    memcpy(&cp, checkpoint, sizeof(nwep_checkpoint));
  } else {
    rv = nwep_trust_store_get_latest_checkpoint(store, &cp);
    if (rv != 0) {
      return rv;
    }
  }

  if (now > cp.timestamp + store->settings.staleness_reject_ns) {
    return NWEP_ERR_TRUST_CHECKPOINT_STALE;
  }

  if (proof->index >= cp.log_size || proof->log_size != cp.log_size) {
    return NWEP_ERR_TRUST_INVALID_PROOF;
  }

  rv = nwep_merkle_leaf_hash(&leaf_hash, entry);
  if (rv != 0) {
    return rv;
  }

  if (memcmp(leaf_hash.data, proof->leaf_hash.data, 32) != 0) {
    return NWEP_ERR_TRUST_INVALID_PROOF;
  }

  rv = nwep_merkle_proof_verify(proof, &cp.merkle_root);
  if (rv != 0) {
    return NWEP_ERR_TRUST_INVALID_PROOF;
  }

  memset(result, 0, sizeof(*result));
  memcpy(&result->nodeid, &entry->nodeid, sizeof(nwep_nodeid));
  memcpy(result->pubkey, entry->pubkey, NWEP_ED25519_PUBKEY_LEN);
  result->log_index = proof->index;
  result->checkpoint_epoch = cp.epoch;
  result->verified_at = now;
  result->revoked = (entry->type == NWEP_LOG_ENTRY_REVOCATION);

  return 0;
}

int nwep_trust_store_cache_identity(nwep_trust_store *store,
                                     const nwep_verified_identity *identity) {
  size_t idx;

  if (store == NULL || identity == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  idx = identity_hash(&identity->nodeid);
  store->identity_cache[idx].identity = *identity;
  store->identity_cache[idx].valid = 1;

  return 0;
}

int nwep_trust_store_lookup_identity(const nwep_trust_store *store,
                                      const nwep_nodeid *nodeid, nwep_tstamp now,
                                      nwep_verified_identity *out) {
  size_t idx;
  const identity_cache_entry *entry;

  if (store == NULL || nodeid == NULL || out == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  idx = identity_hash(nodeid);
  entry = &store->identity_cache[idx];

  if (!entry->valid) {
    return NWEP_ERR_TRUST_NODE_NOT_FOUND;
  }

  if (memcmp(entry->identity.nodeid.data, nodeid->data, NWEP_NODEID_LEN) != 0) {
    return NWEP_ERR_TRUST_NODE_NOT_FOUND;
  }

  if (now > entry->identity.verified_at + store->settings.identity_cache_ttl) {
    return NWEP_ERR_TRUST_NODE_NOT_FOUND;
  }

  *out = entry->identity;
  return 0;
}

int nwep_trust_store_check_equivocation(nwep_trust_store *store,
                                         const nwep_checkpoint *cp,
                                         nwep_equivocation *out) {
  if (store == NULL || cp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  for (size_t i = 0; i < store->checkpoint_count; i++) {
    if (store->checkpoints[i].epoch == cp->epoch) {
      if (memcmp(store->checkpoints[i].merkle_root.data, cp->merkle_root.data,
                 32) != 0) {
        /* Different roots for same epoch = equivocation */
        for (size_t j = 0; j < cp->num_signers; j++) {
          for (size_t k = 0; k < store->checkpoints[i].num_signers; k++) {
            if (memcmp(cp->signers[j].data,
                       store->checkpoints[i].signers[k].data,
                       NWEP_BLS_PUBKEY_LEN) == 0) {
              if (out != NULL) {
                memcpy(&out->anchor, &cp->signers[j], sizeof(nwep_bls_pubkey));
                out->epoch = cp->epoch;
                memcpy(&out->root1, &store->checkpoints[i].merkle_root,
                       sizeof(nwep_merkle_hash));
                memcpy(&out->root2, &cp->merkle_root, sizeof(nwep_merkle_hash));
              }
              return NWEP_ERR_TRUST_EQUIVOCATION;
            }
          }
        }
      }
      return 0;
    }
  }

  return 0;
}
