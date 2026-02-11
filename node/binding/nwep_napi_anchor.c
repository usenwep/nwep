#include "nwep_napi.h"

/*
 * napi_js_to_bls_pubkey extracts a nwep_bls_pubkey from a JS Buffer(48).
 */
static int napi_js_to_bls_pubkey(napi_env env, napi_value val,
                                  nwep_bls_pubkey *pk) {
  uint8_t *data;
  size_t len;
  if (nwep_napi_get_buffer(env, val, &data, &len) != 0) return -1;
  if (len != NWEP_BLS_PUBKEY_LEN) {
    napi_throw_type_error(env, NULL, "BLS pubkey must be 48 bytes");
    return -1;
  }
  int rv = nwep_bls_pubkey_deserialize(pk, data);
  if (rv != 0) {
    napi_throw_error(env, NULL, nwep_strerror(rv));
    return -1;
  }
  return 0;
}

/*
 * napi_bls_pubkey_to_js serializes a nwep_bls_pubkey to a JS Buffer(48).
 */
static napi_value napi_bls_pubkey_to_js(napi_env env,
                                         const nwep_bls_pubkey *pk) {
  uint8_t buf[NWEP_BLS_PUBKEY_LEN];
  int rv = nwep_bls_pubkey_serialize(buf, pk);
  if (rv != 0) return NULL;
  return nwep_napi_create_buffer(env, buf, NWEP_BLS_PUBKEY_LEN);
}

/*
 * napi_js_to_bls_sig extracts a nwep_bls_sig from a JS Buffer(96).
 */
static int napi_js_to_bls_sig(napi_env env, napi_value val,
                                nwep_bls_sig *sig) {
  uint8_t *data;
  size_t len;
  if (nwep_napi_get_buffer(env, val, &data, &len) != 0) return -1;
  if (len != NWEP_BLS_SIG_LEN) {
    napi_throw_type_error(env, NULL, "BLS signature must be 96 bytes");
    return -1;
  }
  memcpy(sig->data, data, NWEP_BLS_SIG_LEN);
  return 0;
}

/*
 * napi_js_to_bls_keypair extracts a nwep_bls_keypair from a JS object.
 */
static int napi_js_to_bls_keypair(napi_env env, napi_value obj,
                                   nwep_bls_keypair *kp) {
  napi_value pubkey_val, privkey_val;
  uint8_t *pubdata, *privdata;
  size_t publen, privlen;

  if (napi_get_named_property(env, obj, "pubkey", &pubkey_val) != napi_ok ||
      napi_get_named_property(env, obj, "privkey", &privkey_val) != napi_ok) {
    napi_throw_type_error(env, NULL,
                          "BLS keypair must have pubkey and privkey");
    return -1;
  }
  if (nwep_napi_get_buffer(env, pubkey_val, &pubdata, &publen) != 0 ||
      nwep_napi_get_buffer(env, privkey_val, &privdata, &privlen) != 0) {
    return -1;
  }
  if (publen != NWEP_BLS_PUBKEY_LEN) {
    napi_throw_type_error(env, NULL, "BLS pubkey must be 48 bytes");
    return -1;
  }
  if (privlen != NWEP_BLS_PRIVKEY_LEN) {
    napi_throw_type_error(env, NULL, "BLS privkey must be 32 bytes");
    return -1;
  }
  memcpy(kp->pubkey, pubdata, NWEP_BLS_PUBKEY_LEN);
  memcpy(kp->privkey, privdata, NWEP_BLS_PRIVKEY_LEN);
  return 0;
}

static napi_value napi_bls_keypair_to_js(napi_env env,
                                          const nwep_bls_keypair *kp) {
  napi_value obj, pubkey, privkey;
  napi_create_object(env, &obj);
  pubkey = nwep_napi_create_buffer(env, kp->pubkey, NWEP_BLS_PUBKEY_LEN);
  privkey = nwep_napi_create_buffer(env, kp->privkey, NWEP_BLS_PRIVKEY_LEN);
  if (!pubkey || !privkey) return NULL;
  nwep_napi_set_prop(env, obj, "pubkey", pubkey);
  nwep_napi_set_prop(env, obj, "privkey", privkey);
  return obj;
}

static napi_value napi_bls_keypair_generate(napi_env env,
                                             napi_callback_info info) {
  nwep_bls_keypair kp;
  int rv = nwep_bls_keypair_generate(&kp);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return napi_bls_keypair_to_js(env, &kp);
}

static napi_value napi_bls_keypair_from_seed(napi_env env,
                                              napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint8_t *data;
  size_t len;
  if (nwep_napi_get_buffer(env, argv[0], &data, &len) != 0) return NULL;
  nwep_bls_keypair kp;
  int rv = nwep_bls_keypair_from_seed(&kp, data, len);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return napi_bls_keypair_to_js(env, &kp);
}

static napi_value napi_bls_sign(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_bls_keypair kp;
  if (napi_js_to_bls_keypair(env, argv[0], &kp) != 0) return NULL;
  uint8_t *msg;
  size_t msglen;
  if (nwep_napi_get_buffer(env, argv[1], &msg, &msglen) != 0) return NULL;
  nwep_bls_sig sig;
  int rv = nwep_bls_sign(&sig, &kp, msg, msglen);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_create_buffer(env, sig.data, NWEP_BLS_SIG_LEN);
}

static napi_value napi_bls_verify(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (nwep_napi_get_args(env, info, 3, 3, argv, NULL) != 0) return NULL;
  nwep_bls_pubkey pk;
  if (napi_js_to_bls_pubkey(env, argv[0], &pk) != 0) return NULL;
  nwep_bls_sig sig;
  if (napi_js_to_bls_sig(env, argv[1], &sig) != 0) return NULL;
  uint8_t *msg;
  size_t msglen;
  if (nwep_napi_get_buffer(env, argv[2], &msg, &msglen) != 0) return NULL;
  int rv = nwep_bls_verify(&pk, &sig, msg, msglen);
  napi_value result;
  napi_get_boolean(env, rv == 0, &result);
  return result;
}

static napi_value napi_bls_aggregate_sigs(napi_env env,
                                           napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  uint32_t n;
  NWEP_NAPI_CALL(env, napi_get_array_length(env, argv[0], &n));
  if (n == 0)
    return nwep_napi_throw_type(env, "sigs array must not be empty");

  nwep_bls_sig *sigs = (nwep_bls_sig *)malloc(n * sizeof(nwep_bls_sig));
  if (!sigs) return nwep_napi_throw_msg(env, "Out of memory");

  for (uint32_t i = 0; i < n; i++) {
    napi_value elem;
    napi_get_element(env, argv[0], i, &elem);
    if (napi_js_to_bls_sig(env, elem, &sigs[i]) != 0) {
      free(sigs);
      return NULL;
    }
  }

  nwep_bls_sig out;
  int rv = nwep_bls_aggregate_sigs(&out, sigs, n);
  free(sigs);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_create_buffer(env, out.data, NWEP_BLS_SIG_LEN);
}

static napi_value napi_bls_verify_aggregate(napi_env env,
                                              napi_callback_info info) {
  napi_value argv[3];
  if (nwep_napi_get_args(env, info, 3, 3, argv, NULL) != 0) return NULL;

  uint32_t n;
  NWEP_NAPI_CALL(env, napi_get_array_length(env, argv[0], &n));

  nwep_bls_pubkey *pks = (nwep_bls_pubkey *)malloc(n * sizeof(nwep_bls_pubkey));
  if (!pks) return nwep_napi_throw_msg(env, "Out of memory");

  for (uint32_t i = 0; i < n; i++) {
    napi_value elem;
    napi_get_element(env, argv[0], i, &elem);
    if (napi_js_to_bls_pubkey(env, elem, &pks[i]) != 0) {
      free(pks);
      return NULL;
    }
  }

  nwep_bls_sig sig;
  if (napi_js_to_bls_sig(env, argv[1], &sig) != 0) {
    free(pks);
    return NULL;
  }

  uint8_t *msg;
  size_t msglen;
  if (nwep_napi_get_buffer(env, argv[2], &msg, &msglen) != 0) {
    free(pks);
    return NULL;
  }

  int rv = nwep_bls_verify_aggregate(pks, n, &sig, msg, msglen);
  free(pks);
  napi_value result;
  napi_get_boolean(env, rv == 0, &result);
  return result;
}

static void napi_anchor_set_destructor(napi_env env, void *data,
                                        void *hint) {
  (void)env;
  (void)hint;
  nwep_anchor_set_free((nwep_anchor_set *)data);
}

static napi_value napi_anchor_set_new(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint32_t threshold;
  if (nwep_napi_get_uint32(env, argv[0], &threshold) != 0) return NULL;

  nwep_anchor_set *set;
  int rv = nwep_anchor_set_new(&set, (size_t)threshold);
  if (rv != 0) return nwep_napi_throw(env, rv);

  napi_value external;
  NWEP_NAPI_CALL(env, napi_create_external(env, set,
                                            napi_anchor_set_destructor, NULL,
                                            &external));
  return external;
}

static napi_value napi_anchor_set_free(napi_env env,
                                        napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  /* The destructor handles freeing; this is a no-op for explicit free calls
   * since napi externals are freed on GC. Users can call this for clarity. */
  return NULL;
}

static napi_value napi_anchor_set_add(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (nwep_napi_get_args(env, info, 3, 3, argv, NULL) != 0) return NULL;
  nwep_anchor_set *set =
      (nwep_anchor_set *)nwep_napi_get_external(env, argv[0]);
  if (!set) return NULL;

  nwep_bls_pubkey pk;
  if (napi_js_to_bls_pubkey(env, argv[1], &pk) != 0) return NULL;

  bool builtin;
  NWEP_NAPI_CALL(env, napi_get_value_bool(env, argv[2], &builtin));

  int rv = nwep_anchor_set_add(set, &pk, builtin ? 1 : 0);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return NULL;
}

static napi_value napi_anchor_set_remove(napi_env env,
                                          napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_anchor_set *set =
      (nwep_anchor_set *)nwep_napi_get_external(env, argv[0]);
  if (!set) return NULL;

  nwep_bls_pubkey pk;
  if (napi_js_to_bls_pubkey(env, argv[1], &pk) != 0) return NULL;

  int rv = nwep_anchor_set_remove(set, &pk);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return NULL;
}

static napi_value napi_anchor_set_size(napi_env env,
                                        napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_anchor_set *set =
      (nwep_anchor_set *)nwep_napi_get_external(env, argv[0]);
  if (!set) return NULL;

  napi_value result;
  napi_create_uint32(env, (uint32_t)nwep_anchor_set_size(set), &result);
  return result;
}

static napi_value napi_anchor_set_threshold(napi_env env,
                                             napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_anchor_set *set =
      (nwep_anchor_set *)nwep_napi_get_external(env, argv[0]);
  if (!set) return NULL;

  napi_value result;
  napi_create_uint32(env, (uint32_t)nwep_anchor_set_threshold(set), &result);
  return result;
}

static napi_value napi_anchor_set_contains(napi_env env,
                                            napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_anchor_set *set =
      (nwep_anchor_set *)nwep_napi_get_external(env, argv[0]);
  if (!set) return NULL;

  nwep_bls_pubkey pk;
  if (napi_js_to_bls_pubkey(env, argv[1], &pk) != 0) return NULL;

  int found = nwep_anchor_set_contains(set, &pk);
  napi_value result;
  napi_get_boolean(env, found == 1, &result);
  return result;
}

/*
 * napi_checkpoint_to_js converts a nwep_checkpoint to a JS object.
 */
static napi_value napi_checkpoint_to_js(napi_env env,
                                         const nwep_checkpoint *cp) {
  napi_value obj;
  napi_create_object(env, &obj);

  nwep_napi_set_prop(env, obj, "epoch",
                     nwep_napi_create_bigint(env, cp->epoch));
  nwep_napi_set_prop(env, obj, "timestamp",
                     nwep_napi_create_bigint(env, cp->timestamp));
  nwep_napi_set_prop(
      env, obj, "merkleRoot",
      nwep_napi_create_buffer(env, cp->merkle_root.data, 32));
  nwep_napi_set_prop(env, obj, "logSize",
                     nwep_napi_create_bigint(env, cp->log_size));
  nwep_napi_set_prop(
      env, obj, "signature",
      nwep_napi_create_buffer(env, cp->signature.data, NWEP_BLS_SIG_LEN));

  napi_value signers;
  napi_create_array_with_length(env, cp->num_signers, &signers);
  for (size_t i = 0; i < cp->num_signers; i++) {
    napi_value pk_buf = napi_bls_pubkey_to_js(env, &cp->signers[i]);
    if (pk_buf) napi_set_element(env, signers, (uint32_t)i, pk_buf);
  }
  nwep_napi_set_prop(env, obj, "signers", signers);

  napi_value num_signers_val;
  napi_create_uint32(env, (uint32_t)cp->num_signers, &num_signers_val);
  nwep_napi_set_prop(env, obj, "numSigners", num_signers_val);

  return obj;
}

/*
 * napi_js_to_checkpoint extracts a nwep_checkpoint from a JS object.
 */
static int napi_js_to_checkpoint(napi_env env, napi_value obj,
                                  nwep_checkpoint *cp) {
  napi_value val;
  uint8_t *data;
  size_t len;

  memset(cp, 0, sizeof(*cp));

  if (napi_get_named_property(env, obj, "epoch", &val) != napi_ok) {
    napi_throw_type_error(env, NULL, "checkpoint must have epoch");
    return -1;
  }
  if (nwep_napi_get_bigint_uint64(env, val, &cp->epoch) != 0) return -1;

  if (napi_get_named_property(env, obj, "timestamp", &val) != napi_ok) {
    napi_throw_type_error(env, NULL, "checkpoint must have timestamp");
    return -1;
  }
  if (nwep_napi_get_bigint_uint64(env, val, &cp->timestamp) != 0) return -1;

  if (napi_get_named_property(env, obj, "merkleRoot", &val) != napi_ok) {
    napi_throw_type_error(env, NULL, "checkpoint must have merkleRoot");
    return -1;
  }
  if (nwep_napi_get_buffer(env, val, &data, &len) != 0) return -1;
  if (len != 32) {
    napi_throw_type_error(env, NULL, "merkleRoot must be 32 bytes");
    return -1;
  }
  memcpy(cp->merkle_root.data, data, 32);

  if (napi_get_named_property(env, obj, "logSize", &val) != napi_ok) {
    napi_throw_type_error(env, NULL, "checkpoint must have logSize");
    return -1;
  }
  if (nwep_napi_get_bigint_uint64(env, val, &cp->log_size) != 0) return -1;

  /* signature is optional (may not be present for new checkpoints) */
  napi_valuetype vtype;
  if (napi_get_named_property(env, obj, "signature", &val) == napi_ok) {
    if (napi_typeof(env, val, &vtype) == napi_ok && vtype != napi_undefined) {
      if (nwep_napi_get_buffer(env, val, &data, &len) != 0) return -1;
      if (len != NWEP_BLS_SIG_LEN) {
        napi_throw_type_error(env, NULL, "signature must be 96 bytes");
        return -1;
      }
      memcpy(cp->signature.data, data, NWEP_BLS_SIG_LEN);
    }
  }

  /* signers is optional */
  napi_value signers_val;
  if (napi_get_named_property(env, obj, "signers", &signers_val) == napi_ok) {
    if (napi_typeof(env, signers_val, &vtype) == napi_ok &&
        vtype != napi_undefined) {
      uint32_t num;
      if (napi_get_array_length(env, signers_val, &num) == napi_ok) {
        if (num > NWEP_MAX_ANCHORS) {
          napi_throw_type_error(env, NULL, "too many signers");
          return -1;
        }
        cp->num_signers = (size_t)num;
        for (uint32_t i = 0; i < num; i++) {
          napi_value elem;
          napi_get_element(env, signers_val, i, &elem);
          if (napi_js_to_bls_pubkey(env, elem, &cp->signers[i]) != 0)
            return -1;
        }
      }
    }
  }

  /* numSigners override if present */
  if (napi_get_named_property(env, obj, "numSigners", &val) == napi_ok) {
    if (napi_typeof(env, val, &vtype) == napi_ok && vtype == napi_number) {
      uint32_t ns;
      napi_get_value_uint32(env, val, &ns);
      cp->num_signers = (size_t)ns;
    }
  }

  return 0;
}

static napi_value napi_checkpoint_new(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  if (nwep_napi_get_args(env, info, 4, 4, argv, NULL) != 0) return NULL;

  uint64_t epoch, timestamp, log_size;
  if (nwep_napi_get_bigint_uint64(env, argv[0], &epoch) != 0) return NULL;
  if (nwep_napi_get_bigint_uint64(env, argv[1], &timestamp) != 0) return NULL;

  uint8_t *root_data;
  size_t root_len;
  if (nwep_napi_get_buffer(env, argv[2], &root_data, &root_len) != 0)
    return NULL;
  if (root_len != 32)
    return nwep_napi_throw_type(env, "merkleRoot must be 32 bytes");

  if (nwep_napi_get_bigint_uint64(env, argv[3], &log_size) != 0) return NULL;

  nwep_merkle_hash merkle_root;
  memcpy(merkle_root.data, root_data, 32);

  nwep_checkpoint cp;
  int rv = nwep_checkpoint_new(&cp, epoch, timestamp, &merkle_root, log_size);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return napi_checkpoint_to_js(env, &cp);
}

static napi_value napi_checkpoint_encode(napi_env env,
                                          napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  nwep_checkpoint cp;
  if (napi_js_to_checkpoint(env, argv[0], &cp) != 0) return NULL;

  uint8_t buf[8192];
  nwep_ssize n = nwep_checkpoint_encode(buf, sizeof(buf), &cp);
  if (n < 0) return nwep_napi_throw(env, (int)n);
  return nwep_napi_create_buffer(env, buf, (size_t)n);
}

static napi_value napi_checkpoint_decode(napi_env env,
                                          napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint8_t *data;
  size_t len;
  if (nwep_napi_get_buffer(env, argv[0], &data, &len) != 0) return NULL;

  nwep_checkpoint cp;
  int rv = nwep_checkpoint_decode(&cp, data, len);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return napi_checkpoint_to_js(env, &cp);
}

napi_value nwep_napi_init_anchor(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"blsKeypairGenerate", NULL, napi_bls_keypair_generate, NULL, NULL, NULL,
       napi_default, NULL},
      {"blsKeypairFromSeed", NULL, napi_bls_keypair_from_seed, NULL, NULL,
       NULL, napi_default, NULL},
      {"blsSign", NULL, napi_bls_sign, NULL, NULL, NULL, napi_default, NULL},
      {"blsVerify", NULL, napi_bls_verify, NULL, NULL, NULL, napi_default,
       NULL},
      {"blsAggregateSigs", NULL, napi_bls_aggregate_sigs, NULL, NULL, NULL,
       napi_default, NULL},
      {"blsVerifyAggregate", NULL, napi_bls_verify_aggregate, NULL, NULL, NULL,
       napi_default, NULL},
      {"anchorSetNew", NULL, napi_anchor_set_new, NULL, NULL, NULL,
       napi_default, NULL},
      {"anchorSetFree", NULL, napi_anchor_set_free, NULL, NULL, NULL,
       napi_default, NULL},
      {"anchorSetAdd", NULL, napi_anchor_set_add, NULL, NULL, NULL,
       napi_default, NULL},
      {"anchorSetRemove", NULL, napi_anchor_set_remove, NULL, NULL, NULL,
       napi_default, NULL},
      {"anchorSetSize", NULL, napi_anchor_set_size, NULL, NULL, NULL,
       napi_default, NULL},
      {"anchorSetThreshold", NULL, napi_anchor_set_threshold, NULL, NULL, NULL,
       napi_default, NULL},
      {"anchorSetContains", NULL, napi_anchor_set_contains, NULL, NULL, NULL,
       napi_default, NULL},
      {"checkpointNew", NULL, napi_checkpoint_new, NULL, NULL, NULL,
       napi_default, NULL},
      {"checkpointEncode", NULL, napi_checkpoint_encode, NULL, NULL, NULL,
       napi_default, NULL},
      {"checkpointDecode", NULL, napi_checkpoint_decode, NULL, NULL, NULL,
       napi_default, NULL},
  };
  napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]),
                         props);
  return exports;
}
