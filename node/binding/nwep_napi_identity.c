#include "nwep_napi.h"

static napi_value napi_managed_identity_to_js(napi_env env,
                                                const nwep_managed_identity *id) {
  napi_value obj;
  napi_create_object(env, &obj);

  napi_set_named_property(env, obj, "nodeid",
                          nwep_napi_nodeid_to_js(env, &id->nodeid));

  napi_value key_count;
  napi_create_uint32(env, (uint32_t)id->key_count, &key_count);
  napi_set_named_property(env, obj, "keyCount", key_count);

  napi_value has_recovery, revoked;
  napi_get_boolean(env, id->has_recovery, &has_recovery);
  napi_get_boolean(env, id->revoked, &revoked);
  napi_set_named_property(env, obj, "hasRecovery", has_recovery);
  napi_set_named_property(env, obj, "revoked", revoked);

  if (id->has_recovery) {
    napi_set_named_property(
        env, obj, "recoveryPubkey",
        nwep_napi_create_buffer(env, id->recovery_pubkey,
                                NWEP_ED25519_PUBKEY_LEN));
  }

  napi_value keys_arr;
  napi_create_array_with_length(env, id->key_count, &keys_arr);
  for (size_t i = 0; i < id->key_count; i++) {
    napi_value key_obj = nwep_napi_keypair_to_js(env, &id->keys[i].keypair);
    napi_value active;
    napi_get_boolean(env, id->keys[i].active, &active);
    napi_set_named_property(env, key_obj, "active", active);
    napi_set_named_property(env, key_obj, "activatedAt",
                            nwep_napi_create_bigint(env, id->keys[i].activated_at));
    napi_set_named_property(env, key_obj, "expiresAt",
                            nwep_napi_create_bigint(env, id->keys[i].expires_at));
    napi_set_element(env, keys_arr, (uint32_t)i, key_obj);
  }
  napi_set_named_property(env, obj, "keys", keys_arr);

  return obj;
}

static napi_value napi_recovery_authority_new(napi_env env,
                                               napi_callback_info info) {
  nwep_recovery_authority ra;
  int rv = nwep_recovery_authority_new(&ra);
  if (rv != 0) return nwep_napi_throw(env, rv);

  napi_value obj;
  napi_create_object(env, &obj);
  napi_set_named_property(env, obj, "keypair",
                          nwep_napi_keypair_to_js(env, &ra.keypair));
  napi_value init;
  napi_get_boolean(env, ra.initialized, &init);
  napi_set_named_property(env, obj, "initialized", init);
  return obj;
}

static napi_value napi_recovery_authority_get_pubkey(napi_env env,
                                                      napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  nwep_recovery_authority ra;
  memset(&ra, 0, sizeof(ra));

  napi_value kp_val;
  napi_get_named_property(env, argv[0], "keypair", &kp_val);
  if (nwep_napi_js_to_keypair(env, kp_val, &ra.keypair) != 0) return NULL;
  ra.initialized = 1;

  const uint8_t *pk = nwep_recovery_authority_get_pubkey(&ra);
  if (!pk) {
    napi_value null_val;
    napi_get_null(env, &null_val);
    return null_val;
  }
  return nwep_napi_create_buffer(env, pk, NWEP_ED25519_PUBKEY_LEN);
}

static napi_value napi_managed_identity_new(napi_env env,
                                             napi_callback_info info) {
  napi_value argv[3];
  size_t argc;
  if (nwep_napi_get_args(env, info, 2, 3, argv, &argc) != 0) return NULL;

  nwep_keypair kp;
  if (nwep_napi_js_to_keypair(env, argv[0], &kp) != 0) return NULL;

  uint64_t now;
  if (nwep_napi_get_bigint_uint64(env, argv[1], &now) != 0) return NULL;

  nwep_recovery_authority ra;
  nwep_recovery_authority *ra_ptr = NULL;
  if (argc > 2) {
    napi_valuetype vt;
    napi_typeof(env, argv[2], &vt);
    if (vt == napi_object) {
      napi_value kp_val;
      napi_get_named_property(env, argv[2], "keypair", &kp_val);
      if (nwep_napi_js_to_keypair(env, kp_val, &ra.keypair) != 0) return NULL;
      ra.initialized = 1;
      ra_ptr = &ra;
    }
  }

  nwep_managed_identity identity;
  int rv = nwep_managed_identity_new(&identity, &kp, ra_ptr, now);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return napi_managed_identity_to_js(env, &identity);
}

static napi_value napi_managed_identity_rotate(napi_env env,
                                                napi_callback_info info) {
  (void)info;
  return nwep_napi_throw_msg(env,
                             "managedIdentityRotate: use C-level identity management");
}

static napi_value napi_managed_identity_is_revoked(napi_env env,
                                                    napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  napi_value revoked_val;
  napi_get_named_property(env, argv[0], "revoked", &revoked_val);
  bool revoked;
  napi_get_value_bool(env, revoked_val, &revoked);

  napi_value result;
  napi_get_boolean(env, revoked, &result);
  return result;
}

napi_value nwep_napi_init_identity(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"recoveryAuthorityNew", NULL, napi_recovery_authority_new, NULL, NULL,
       NULL, napi_default, NULL},
      {"recoveryAuthorityGetPubkey", NULL, napi_recovery_authority_get_pubkey,
       NULL, NULL, NULL, napi_default, NULL},
      {"managedIdentityNew", NULL, napi_managed_identity_new, NULL, NULL, NULL,
       napi_default, NULL},
      {"managedIdentityRotate", NULL, napi_managed_identity_rotate, NULL, NULL,
       NULL, napi_default, NULL},
      {"managedIdentityIsRevoked", NULL, napi_managed_identity_is_revoked,
       NULL, NULL, NULL, napi_default, NULL},
  };
  napi_define_properties(env, exports,
                         sizeof(props) / sizeof(props[0]), props);
  return exports;
}
