#include "nwep_napi.h"

static napi_value napi_merkle_entry_encode(napi_env env,
                                            napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  nwep_merkle_entry entry;
  memset(&entry, 0, sizeof(entry));

  napi_value val;
  uint32_t type;
  uint64_t timestamp;
  uint8_t *data;
  size_t len;

  NWEP_NAPI_CALL(env, napi_get_named_property(env, argv[0], "type", &val));
  if (nwep_napi_get_uint32(env, val, &type) != 0) return NULL;
  entry.type = (nwep_merkle_entry_type)type;

  NWEP_NAPI_CALL(env,
                  napi_get_named_property(env, argv[0], "timestamp", &val));
  if (nwep_napi_get_bigint_uint64(env, val, &timestamp) != 0) return NULL;
  entry.timestamp = timestamp;

  NWEP_NAPI_CALL(env, napi_get_named_property(env, argv[0], "nodeid", &val));
  if (nwep_napi_js_to_nodeid(env, val, &entry.nodeid) != 0) return NULL;

  NWEP_NAPI_CALL(env, napi_get_named_property(env, argv[0], "pubkey", &val));
  if (nwep_napi_get_buffer(env, val, &data, &len) != 0) return NULL;
  if (len != NWEP_ED25519_PUBKEY_LEN)
    return nwep_napi_throw_type(env, "pubkey must be 32 bytes");
  memcpy(entry.pubkey, data, NWEP_ED25519_PUBKEY_LEN);

  NWEP_NAPI_CALL(env,
                  napi_get_named_property(env, argv[0], "prevPubkey", &val));
  if (nwep_napi_get_buffer(env, val, &data, &len) != 0) return NULL;
  if (len != NWEP_ED25519_PUBKEY_LEN)
    return nwep_napi_throw_type(env, "prevPubkey must be 32 bytes");
  memcpy(entry.prev_pubkey, data, NWEP_ED25519_PUBKEY_LEN);

  NWEP_NAPI_CALL(
      env, napi_get_named_property(env, argv[0], "recoveryPubkey", &val));
  if (nwep_napi_get_buffer(env, val, &data, &len) != 0) return NULL;
  if (len != NWEP_ED25519_PUBKEY_LEN)
    return nwep_napi_throw_type(env, "recoveryPubkey must be 32 bytes");
  memcpy(entry.recovery_pubkey, data, NWEP_ED25519_PUBKEY_LEN);

  NWEP_NAPI_CALL(env,
                  napi_get_named_property(env, argv[0], "signature", &val));
  if (nwep_napi_get_buffer(env, val, &data, &len) != 0) return NULL;
  if (len != NWEP_ED25519_SIG_LEN)
    return nwep_napi_throw_type(env, "signature must be 64 bytes");
  memcpy(entry.signature, data, NWEP_ED25519_SIG_LEN);

  uint8_t buf[512];
  nwep_ssize n = nwep_merkle_entry_encode(buf, sizeof(buf), &entry);
  if (n < 0) return nwep_napi_throw(env, (int)n);
  return nwep_napi_create_buffer(env, buf, (size_t)n);
}

static napi_value napi_merkle_entry_to_js(napi_env env,
                                           const nwep_merkle_entry *entry) {
  napi_value obj;
  napi_create_object(env, &obj);

  napi_value type_val;
  napi_create_uint32(env, (uint32_t)entry->type, &type_val);
  nwep_napi_set_prop(env, obj, "type", type_val);

  nwep_napi_set_prop(env, obj, "timestamp",
                     nwep_napi_create_bigint(env, entry->timestamp));
  nwep_napi_set_prop(env, obj, "nodeid",
                     nwep_napi_nodeid_to_js(env, &entry->nodeid));
  nwep_napi_set_prop(
      env, obj, "pubkey",
      nwep_napi_create_buffer(env, entry->pubkey, NWEP_ED25519_PUBKEY_LEN));
  nwep_napi_set_prop(env, obj, "prevPubkey",
                     nwep_napi_create_buffer(env, entry->prev_pubkey,
                                             NWEP_ED25519_PUBKEY_LEN));
  nwep_napi_set_prop(env, obj, "recoveryPubkey",
                     nwep_napi_create_buffer(env, entry->recovery_pubkey,
                                             NWEP_ED25519_PUBKEY_LEN));
  nwep_napi_set_prop(
      env, obj, "signature",
      nwep_napi_create_buffer(env, entry->signature, NWEP_ED25519_SIG_LEN));
  return obj;
}

static napi_value napi_merkle_entry_decode(napi_env env,
                                            napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint8_t *data;
  size_t len;
  if (nwep_napi_get_buffer(env, argv[0], &data, &len) != 0) return NULL;

  nwep_merkle_entry entry;
  int rv = nwep_merkle_entry_decode(&entry, data, len);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return napi_merkle_entry_to_js(env, &entry);
}

static napi_value napi_merkle_leaf_hash(napi_env env,
                                         napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  nwep_merkle_entry entry;
  memset(&entry, 0, sizeof(entry));

  napi_value val;
  uint32_t type;
  uint64_t timestamp;
  uint8_t *data;
  size_t len;

  NWEP_NAPI_CALL(env, napi_get_named_property(env, argv[0], "type", &val));
  if (nwep_napi_get_uint32(env, val, &type) != 0) return NULL;
  entry.type = (nwep_merkle_entry_type)type;

  NWEP_NAPI_CALL(env,
                  napi_get_named_property(env, argv[0], "timestamp", &val));
  if (nwep_napi_get_bigint_uint64(env, val, &timestamp) != 0) return NULL;
  entry.timestamp = timestamp;

  NWEP_NAPI_CALL(env, napi_get_named_property(env, argv[0], "nodeid", &val));
  if (nwep_napi_js_to_nodeid(env, val, &entry.nodeid) != 0) return NULL;

  NWEP_NAPI_CALL(env, napi_get_named_property(env, argv[0], "pubkey", &val));
  if (nwep_napi_get_buffer(env, val, &data, &len) != 0) return NULL;
  if (len != NWEP_ED25519_PUBKEY_LEN)
    return nwep_napi_throw_type(env, "pubkey must be 32 bytes");
  memcpy(entry.pubkey, data, NWEP_ED25519_PUBKEY_LEN);

  NWEP_NAPI_CALL(env,
                  napi_get_named_property(env, argv[0], "prevPubkey", &val));
  if (nwep_napi_get_buffer(env, val, &data, &len) != 0) return NULL;
  if (len != NWEP_ED25519_PUBKEY_LEN)
    return nwep_napi_throw_type(env, "prevPubkey must be 32 bytes");
  memcpy(entry.prev_pubkey, data, NWEP_ED25519_PUBKEY_LEN);

  NWEP_NAPI_CALL(
      env, napi_get_named_property(env, argv[0], "recoveryPubkey", &val));
  if (nwep_napi_get_buffer(env, val, &data, &len) != 0) return NULL;
  if (len != NWEP_ED25519_PUBKEY_LEN)
    return nwep_napi_throw_type(env, "recoveryPubkey must be 32 bytes");
  memcpy(entry.recovery_pubkey, data, NWEP_ED25519_PUBKEY_LEN);

  NWEP_NAPI_CALL(env,
                  napi_get_named_property(env, argv[0], "signature", &val));
  if (nwep_napi_get_buffer(env, val, &data, &len) != 0) return NULL;
  if (len != NWEP_ED25519_SIG_LEN)
    return nwep_napi_throw_type(env, "signature must be 64 bytes");
  memcpy(entry.signature, data, NWEP_ED25519_SIG_LEN);

  nwep_merkle_hash hash;
  int rv = nwep_merkle_leaf_hash(&hash, &entry);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_create_buffer(env, hash.data, 32);
}

static napi_value napi_merkle_node_hash(napi_env env,
                                         napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  uint8_t *ldata, *rdata;
  size_t llen, rlen;
  if (nwep_napi_get_buffer(env, argv[0], &ldata, &llen) != 0) return NULL;
  if (nwep_napi_get_buffer(env, argv[1], &rdata, &rlen) != 0) return NULL;
  if (llen != 32)
    return nwep_napi_throw_type(env, "left hash must be 32 bytes");
  if (rlen != 32)
    return nwep_napi_throw_type(env, "right hash must be 32 bytes");

  nwep_merkle_hash left, right, out;
  memcpy(left.data, ldata, 32);
  memcpy(right.data, rdata, 32);
  int rv = nwep_merkle_node_hash(&out, &left, &right);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_create_buffer(env, out.data, 32);
}

static int napi_js_to_merkle_proof(napi_env env, napi_value obj,
                                    nwep_merkle_proof *proof) {
  napi_value val;
  uint8_t *data;
  size_t len;

  if (napi_get_named_property(env, obj, "index", &val) != napi_ok) {
    napi_throw_type_error(env, NULL, "proof must have index");
    return -1;
  }
  if (nwep_napi_get_bigint_uint64(env, val, &proof->index) != 0) return -1;

  if (napi_get_named_property(env, obj, "logSize", &val) != napi_ok) {
    napi_throw_type_error(env, NULL, "proof must have logSize");
    return -1;
  }
  if (nwep_napi_get_bigint_uint64(env, val, &proof->log_size) != 0) return -1;

  if (napi_get_named_property(env, obj, "leafHash", &val) != napi_ok) {
    napi_throw_type_error(env, NULL, "proof must have leafHash");
    return -1;
  }
  if (nwep_napi_get_buffer(env, val, &data, &len) != 0) return -1;
  if (len != 32) {
    napi_throw_type_error(env, NULL, "leafHash must be 32 bytes");
    return -1;
  }
  memcpy(proof->leaf_hash.data, data, 32);

  napi_value siblings_val;
  if (napi_get_named_property(env, obj, "siblings", &siblings_val) !=
      napi_ok) {
    napi_throw_type_error(env, NULL, "proof must have siblings");
    return -1;
  }
  uint32_t num_siblings;
  if (napi_get_array_length(env, siblings_val, &num_siblings) != napi_ok) {
    napi_throw_type_error(env, NULL, "siblings must be an array");
    return -1;
  }
  if (num_siblings > NWEP_MERKLE_PROOF_MAX_DEPTH) {
    napi_throw_type_error(env, NULL, "too many siblings");
    return -1;
  }
  for (uint32_t i = 0; i < num_siblings; i++) {
    napi_value elem;
    napi_get_element(env, siblings_val, i, &elem);
    if (nwep_napi_get_buffer(env, elem, &data, &len) != 0) return -1;
    if (len != 32) {
      napi_throw_type_error(env, NULL, "sibling hash must be 32 bytes");
      return -1;
    }
    memcpy(proof->siblings[i].data, data, 32);
  }

  uint32_t depth;
  if (napi_get_named_property(env, obj, "depth", &val) != napi_ok) {
    napi_throw_type_error(env, NULL, "proof must have depth");
    return -1;
  }
  if (nwep_napi_get_uint32(env, val, &depth) != 0) return -1;
  proof->depth = (size_t)depth;

  return 0;
}

static napi_value napi_merkle_proof_to_js(napi_env env,
                                           const nwep_merkle_proof *proof) {
  napi_value obj;
  napi_create_object(env, &obj);

  nwep_napi_set_prop(env, obj, "index",
                     nwep_napi_create_bigint(env, proof->index));
  nwep_napi_set_prop(env, obj, "logSize",
                     nwep_napi_create_bigint(env, proof->log_size));
  nwep_napi_set_prop(
      env, obj, "leafHash",
      nwep_napi_create_buffer(env, proof->leaf_hash.data, 32));

  napi_value siblings;
  napi_create_array_with_length(env, proof->depth, &siblings);
  for (size_t i = 0; i < proof->depth; i++) {
    napi_value sib =
        nwep_napi_create_buffer(env, proof->siblings[i].data, 32);
    napi_set_element(env, siblings, (uint32_t)i, sib);
  }
  nwep_napi_set_prop(env, obj, "siblings", siblings);

  napi_value depth_val;
  napi_create_uint32(env, (uint32_t)proof->depth, &depth_val);
  nwep_napi_set_prop(env, obj, "depth", depth_val);

  return obj;
}

static napi_value napi_merkle_proof_verify(napi_env env,
                                            napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;

  nwep_merkle_proof proof;
  memset(&proof, 0, sizeof(proof));
  if (napi_js_to_merkle_proof(env, argv[0], &proof) != 0) return NULL;

  uint8_t *root_data;
  size_t root_len;
  if (nwep_napi_get_buffer(env, argv[1], &root_data, &root_len) != 0)
    return NULL;
  if (root_len != 32)
    return nwep_napi_throw_type(env, "root must be 32 bytes");

  nwep_merkle_hash root;
  memcpy(root.data, root_data, 32);

  int rv = nwep_merkle_proof_verify(&proof, &root);
  napi_value result;
  napi_get_boolean(env, rv == 0, &result);
  return result;
}

static napi_value napi_merkle_proof_encode(napi_env env,
                                            napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  nwep_merkle_proof proof;
  memset(&proof, 0, sizeof(proof));
  if (napi_js_to_merkle_proof(env, argv[0], &proof) != 0) return NULL;

  uint8_t buf[NWEP_MERKLE_PROOF_MAX_SIZE];
  nwep_ssize n = nwep_merkle_proof_encode(buf, sizeof(buf), &proof);
  if (n < 0) return nwep_napi_throw(env, (int)n);
  return nwep_napi_create_buffer(env, buf, (size_t)n);
}

static napi_value napi_merkle_proof_decode(napi_env env,
                                            napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint8_t *data;
  size_t len;
  if (nwep_napi_get_buffer(env, argv[0], &data, &len) != 0) return NULL;

  nwep_merkle_proof proof;
  memset(&proof, 0, sizeof(proof));
  int rv = nwep_merkle_proof_decode(&proof, data, len);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return napi_merkle_proof_to_js(env, &proof);
}

napi_value nwep_napi_init_merkle(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"merkleEntryEncode", NULL, napi_merkle_entry_encode, NULL, NULL, NULL,
       napi_default, NULL},
      {"merkleEntryDecode", NULL, napi_merkle_entry_decode, NULL, NULL, NULL,
       napi_default, NULL},
      {"merkleLeafHash", NULL, napi_merkle_leaf_hash, NULL, NULL, NULL,
       napi_default, NULL},
      {"merkleNodeHash", NULL, napi_merkle_node_hash, NULL, NULL, NULL,
       napi_default, NULL},
      {"merkleProofVerify", NULL, napi_merkle_proof_verify, NULL, NULL, NULL,
       napi_default, NULL},
      {"merkleProofEncode", NULL, napi_merkle_proof_encode, NULL, NULL, NULL,
       napi_default, NULL},
      {"merkleProofDecode", NULL, napi_merkle_proof_decode, NULL, NULL, NULL,
       napi_default, NULL},
  };
  napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]),
                         props);
  return exports;
}
