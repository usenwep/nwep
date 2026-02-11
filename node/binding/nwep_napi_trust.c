#include "nwep_napi.h"

static int napi_trust_js_to_bls_pubkey(napi_env env, napi_value val,
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

static napi_value napi_trust_bls_pubkey_to_js(napi_env env,
                                               const nwep_bls_pubkey *pk) {
  uint8_t buf[NWEP_BLS_PUBKEY_LEN];
  int rv = nwep_bls_pubkey_serialize(buf, pk);
  if (rv != 0) return NULL;
  return nwep_napi_create_buffer(env, buf, NWEP_BLS_PUBKEY_LEN);
}

static napi_value napi_trust_checkpoint_to_js(napi_env env,
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
    napi_value pk_buf = napi_trust_bls_pubkey_to_js(env, &cp->signers[i]);
    if (pk_buf) napi_set_element(env, signers, (uint32_t)i, pk_buf);
  }
  nwep_napi_set_prop(env, obj, "signers", signers);

  napi_value num_signers_val;
  napi_create_uint32(env, (uint32_t)cp->num_signers, &num_signers_val);
  nwep_napi_set_prop(env, obj, "numSigners", num_signers_val);

  return obj;
}

static int napi_trust_js_to_checkpoint(napi_env env, napi_value obj,
                                        nwep_checkpoint *cp) {
  napi_value val;
  uint8_t *data;
  size_t len;
  napi_valuetype vtype;

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
          if (napi_trust_js_to_bls_pubkey(env, elem, &cp->signers[i]) != 0)
            return -1;
        }
      }
    }
  }

  if (napi_get_named_property(env, obj, "numSigners", &val) == napi_ok) {
    if (napi_typeof(env, val, &vtype) == napi_ok && vtype == napi_number) {
      uint32_t ns;
      napi_get_value_uint32(env, val, &ns);
      cp->num_signers = (size_t)ns;
    }
  }

  return 0;
}

static napi_value napi_trust_settings_default(napi_env env,
                                               napi_callback_info info) {
  nwep_trust_settings settings;
  nwep_trust_settings_default(&settings);

  napi_value obj;
  napi_create_object(env, &obj);

  nwep_napi_set_prop(env, obj, "stalenessWarningNs",
                     nwep_napi_create_bigint(env, settings.staleness_warning_ns));
  nwep_napi_set_prop(env, obj, "stalenessRejectNs",
                     nwep_napi_create_bigint(env, settings.staleness_reject_ns));
  nwep_napi_set_prop(env, obj, "identityCacheTtl",
                     nwep_napi_create_bigint(env, settings.identity_cache_ttl));

  napi_value threshold_val;
  napi_create_uint32(env, (uint32_t)settings.anchor_threshold, &threshold_val);
  nwep_napi_set_prop(env, obj, "anchorThreshold", threshold_val);

  return obj;
}

static void napi_trust_store_destructor(napi_env env, void *data,
                                         void *hint) {
  (void)env;
  (void)hint;
  nwep_trust_store_free((nwep_trust_store *)data);
}

static napi_value napi_trust_store_new(napi_env env,
                                        napi_callback_info info) {
  napi_value argv[2];
  size_t argc;
  if (nwep_napi_get_args(env, info, 0, 2, argv, &argc) != 0) return NULL;

  nwep_trust_settings settings;
  nwep_trust_settings *settings_ptr = NULL;

  if (argc >= 1) {
    napi_valuetype vtype;
    napi_typeof(env, argv[0], &vtype);
    if (vtype == napi_object) {
      nwep_trust_settings_default(&settings);
      napi_value val;

      if (napi_get_named_property(env, argv[0], "stalenessWarningNs", &val) ==
          napi_ok) {
        napi_typeof(env, val, &vtype);
        if (vtype == napi_bigint)
          nwep_napi_get_bigint_uint64(env, val, &settings.staleness_warning_ns);
      }
      if (napi_get_named_property(env, argv[0], "stalenessRejectNs", &val) ==
          napi_ok) {
        napi_typeof(env, val, &vtype);
        if (vtype == napi_bigint)
          nwep_napi_get_bigint_uint64(env, val, &settings.staleness_reject_ns);
      }
      if (napi_get_named_property(env, argv[0], "identityCacheTtl", &val) ==
          napi_ok) {
        napi_typeof(env, val, &vtype);
        if (vtype == napi_bigint)
          nwep_napi_get_bigint_uint64(env, val, &settings.identity_cache_ttl);
      }
      if (napi_get_named_property(env, argv[0], "anchorThreshold", &val) ==
          napi_ok) {
        napi_typeof(env, val, &vtype);
        if (vtype == napi_number) {
          uint32_t t;
          napi_get_value_uint32(env, val, &t);
          settings.anchor_threshold = (size_t)t;
        }
      }
      settings_ptr = &settings;
    }
  }

  nwep_trust_store *store;
  int rv = nwep_trust_store_new(&store, settings_ptr, NULL);
  if (rv != 0) return nwep_napi_throw(env, rv);

  napi_value external;
  NWEP_NAPI_CALL(env, napi_create_external(env, store,
                                            napi_trust_store_destructor, NULL,
                                            &external));
  return external;
}

static napi_value napi_trust_store_free(napi_env env,
                                         napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  return NULL;
}

static napi_value napi_trust_store_add_anchor(napi_env env,
                                               napi_callback_info info) {
  napi_value argv[3];
  if (nwep_napi_get_args(env, info, 3, 3, argv, NULL) != 0) return NULL;
  nwep_trust_store *store =
      (nwep_trust_store *)nwep_napi_get_external(env, argv[0]);
  if (!store) return NULL;

  nwep_bls_pubkey pk;
  if (napi_trust_js_to_bls_pubkey(env, argv[1], &pk) != 0) return NULL;

  bool builtin;
  NWEP_NAPI_CALL(env, napi_get_value_bool(env, argv[2], &builtin));

  int rv = nwep_trust_store_add_anchor(store, &pk, builtin ? 1 : 0);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return NULL;
}

static napi_value napi_trust_store_remove_anchor(napi_env env,
                                                  napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_trust_store *store =
      (nwep_trust_store *)nwep_napi_get_external(env, argv[0]);
  if (!store) return NULL;

  nwep_bls_pubkey pk;
  if (napi_trust_js_to_bls_pubkey(env, argv[1], &pk) != 0) return NULL;

  int rv = nwep_trust_store_remove_anchor(store, &pk);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return NULL;
}

static napi_value napi_trust_store_add_checkpoint(napi_env env,
                                                   napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_trust_store *store =
      (nwep_trust_store *)nwep_napi_get_external(env, argv[0]);
  if (!store) return NULL;

  nwep_checkpoint cp;
  if (napi_trust_js_to_checkpoint(env, argv[1], &cp) != 0) return NULL;

  int rv = nwep_trust_store_add_checkpoint(store, &cp);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return NULL;
}

static napi_value napi_trust_store_get_latest_checkpoint(
    napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_trust_store *store =
      (nwep_trust_store *)nwep_napi_get_external(env, argv[0]);
  if (!store) return NULL;

  nwep_checkpoint cp;
  int rv = nwep_trust_store_get_latest_checkpoint(store, &cp);
  if (rv != 0) {
    napi_value null_val;
    napi_get_null(env, &null_val);
    return null_val;
  }
  return napi_trust_checkpoint_to_js(env, &cp);
}

static napi_value napi_trust_store_checkpoint_count(napi_env env,
                                                     napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_trust_store *store =
      (nwep_trust_store *)nwep_napi_get_external(env, argv[0]);
  if (!store) return NULL;

  napi_value result;
  napi_create_uint32(env,
                     (uint32_t)nwep_trust_store_checkpoint_count(store),
                     &result);
  return result;
}

static napi_value napi_trust_store_check_staleness(napi_env env,
                                                    napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_trust_store *store =
      (nwep_trust_store *)nwep_napi_get_external(env, argv[0]);
  if (!store) return NULL;

  uint64_t now;
  if (nwep_napi_get_bigint_uint64(env, argv[1], &now) != 0) return NULL;

  nwep_staleness staleness = nwep_trust_store_check_staleness(store, now);
  napi_value result;
  napi_create_uint32(env, (uint32_t)staleness, &result);
  return result;
}

static napi_value napi_trust_store_get_staleness_age(napi_env env,
                                                      napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_trust_store *store =
      (nwep_trust_store *)nwep_napi_get_external(env, argv[0]);
  if (!store) return NULL;

  uint64_t now;
  if (nwep_napi_get_bigint_uint64(env, argv[1], &now) != 0) return NULL;

  nwep_duration age = nwep_trust_store_get_staleness_age(store, now);
  return nwep_napi_create_bigint(env, age);
}

napi_value nwep_napi_init_trust(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"trustSettingsDefault", NULL, napi_trust_settings_default, NULL, NULL,
       NULL, napi_default, NULL},
      {"trustStoreNew", NULL, napi_trust_store_new, NULL, NULL, NULL,
       napi_default, NULL},
      {"trustStoreFree", NULL, napi_trust_store_free, NULL, NULL, NULL,
       napi_default, NULL},
      {"trustStoreAddAnchor", NULL, napi_trust_store_add_anchor, NULL, NULL,
       NULL, napi_default, NULL},
      {"trustStoreRemoveAnchor", NULL, napi_trust_store_remove_anchor, NULL,
       NULL, NULL, napi_default, NULL},
      {"trustStoreAddCheckpoint", NULL, napi_trust_store_add_checkpoint, NULL,
       NULL, NULL, napi_default, NULL},
      {"trustStoreGetLatestCheckpoint", NULL,
       napi_trust_store_get_latest_checkpoint, NULL, NULL, NULL, napi_default,
       NULL},
      {"trustStoreCheckpointCount", NULL, napi_trust_store_checkpoint_count,
       NULL, NULL, NULL, napi_default, NULL},
      {"trustStoreCheckStaleness", NULL, napi_trust_store_check_staleness,
       NULL, NULL, NULL, napi_default, NULL},
      {"trustStoreGetStalenessAge", NULL, napi_trust_store_get_staleness_age,
       NULL, NULL, NULL, napi_default, NULL},
  };
  napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]),
                         props);
  return exports;
}
