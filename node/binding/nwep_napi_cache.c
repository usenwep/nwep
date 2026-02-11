#include "nwep_napi.h"

static void napi_identity_cache_destructor(napi_env env, void *data,
                                            void *hint) {
  (void)env;
  (void)hint;
  nwep_identity_cache_free((nwep_identity_cache *)data);
}

static napi_value napi_identity_cache_new(napi_env env,
                                           napi_callback_info info) {
  napi_value argv[1];
  size_t argc;
  if (nwep_napi_get_args(env, info, 0, 1, argv, &argc) != 0) return NULL;

  nwep_identity_cache_settings settings;
  nwep_identity_cache_settings *settings_ptr = NULL;

  if (argc >= 1) {
    napi_valuetype vtype;
    napi_typeof(env, argv[0], &vtype);
    if (vtype == napi_object) {
      nwep_identity_cache_settings_default(&settings);
      napi_value val;

      if (napi_get_named_property(env, argv[0], "capacity", &val) ==
          napi_ok) {
        napi_typeof(env, val, &vtype);
        if (vtype == napi_number) {
          uint32_t cap;
          napi_get_value_uint32(env, val, &cap);
          settings.capacity = (size_t)cap;
        }
      }
      if (napi_get_named_property(env, argv[0], "ttlNs", &val) == napi_ok) {
        napi_typeof(env, val, &vtype);
        if (vtype == napi_bigint)
          nwep_napi_get_bigint_uint64(env, val, &settings.ttl_ns);
      }
      settings_ptr = &settings;
    }
  }

  nwep_identity_cache *cache;
  int rv = nwep_identity_cache_new(&cache, settings_ptr);
  if (rv != 0) return nwep_napi_throw(env, rv);

  napi_value external;
  NWEP_NAPI_CALL(env,
                  napi_create_external(env, cache,
                                       napi_identity_cache_destructor, NULL,
                                       &external));
  return external;
}

static napi_value napi_identity_cache_free(napi_env env,
                                            napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  return NULL;
}

static napi_value napi_identity_cache_lookup(napi_env env,
                                              napi_callback_info info) {
  napi_value argv[3];
  if (nwep_napi_get_args(env, info, 3, 3, argv, NULL) != 0) return NULL;
  nwep_identity_cache *cache =
      (nwep_identity_cache *)nwep_napi_get_external(env, argv[0]);
  if (!cache) return NULL;

  nwep_nodeid nodeid;
  if (nwep_napi_js_to_nodeid(env, argv[1], &nodeid) != 0) return NULL;

  uint64_t now;
  if (nwep_napi_get_bigint_uint64(env, argv[2], &now) != 0) return NULL;

  nwep_cached_identity identity;
  int rv = nwep_identity_cache_lookup(cache, &nodeid, now, &identity);
  if (rv != 0) {
    napi_value null_val;
    napi_get_null(env, &null_val);
    return null_val;
  }

  napi_value obj;
  napi_create_object(env, &obj);

  nwep_napi_set_prop(env, obj, "nodeid",
                     nwep_napi_nodeid_to_js(env, &identity.nodeid));
  nwep_napi_set_prop(
      env, obj, "pubkey",
      nwep_napi_create_buffer(env, identity.pubkey, NWEP_ED25519_PUBKEY_LEN));
  nwep_napi_set_prop(env, obj, "logIndex",
                     nwep_napi_create_bigint(env, identity.log_index));
  nwep_napi_set_prop(env, obj, "verifiedAt",
                     nwep_napi_create_bigint(env, identity.verified_at));
  nwep_napi_set_prop(env, obj, "expiresAt",
                     nwep_napi_create_bigint(env, identity.expires_at));
  return obj;
}

static napi_value napi_identity_cache_store(napi_env env,
                                             napi_callback_info info) {
  napi_value argv[5];
  if (nwep_napi_get_args(env, info, 5, 5, argv, NULL) != 0) return NULL;
  nwep_identity_cache *cache =
      (nwep_identity_cache *)nwep_napi_get_external(env, argv[0]);
  if (!cache) return NULL;

  nwep_nodeid nodeid;
  if (nwep_napi_js_to_nodeid(env, argv[1], &nodeid) != 0) return NULL;

  uint8_t *pubkey;
  size_t pklen;
  if (nwep_napi_get_buffer(env, argv[2], &pubkey, &pklen) != 0) return NULL;
  if (pklen != NWEP_ED25519_PUBKEY_LEN)
    return nwep_napi_throw_type(env, "pubkey must be 32 bytes");

  uint64_t log_index;
  if (nwep_napi_get_bigint_uint64(env, argv[3], &log_index) != 0) return NULL;

  uint64_t now;
  if (nwep_napi_get_bigint_uint64(env, argv[4], &now) != 0) return NULL;

  int rv = nwep_identity_cache_store(cache, &nodeid, pubkey, log_index, now);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return NULL;
}

static napi_value napi_identity_cache_invalidate(napi_env env,
                                                  napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_identity_cache *cache =
      (nwep_identity_cache *)nwep_napi_get_external(env, argv[0]);
  if (!cache) return NULL;

  nwep_nodeid nodeid;
  if (nwep_napi_js_to_nodeid(env, argv[1], &nodeid) != 0) return NULL;

  int rv = nwep_identity_cache_invalidate(cache, &nodeid);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return NULL;
}

static napi_value napi_identity_cache_clear(napi_env env,
                                             napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_identity_cache *cache =
      (nwep_identity_cache *)nwep_napi_get_external(env, argv[0]);
  if (!cache) return NULL;

  nwep_identity_cache_clear(cache);
  return NULL;
}

static napi_value napi_identity_cache_size(napi_env env,
                                            napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_identity_cache *cache =
      (nwep_identity_cache *)nwep_napi_get_external(env, argv[0]);
  if (!cache) return NULL;

  napi_value result;
  napi_create_uint32(env, (uint32_t)nwep_identity_cache_size(cache), &result);
  return result;
}

static napi_value napi_identity_cache_capacity(napi_env env,
                                                napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_identity_cache *cache =
      (nwep_identity_cache *)nwep_napi_get_external(env, argv[0]);
  if (!cache) return NULL;

  napi_value result;
  napi_create_uint32(env, (uint32_t)nwep_identity_cache_capacity(cache),
                     &result);
  return result;
}

static void napi_log_server_pool_destructor(napi_env env, void *data,
                                             void *hint) {
  (void)env;
  (void)hint;
  nwep_log_server_pool_free((nwep_log_server_pool *)data);
}

static napi_value napi_log_server_pool_new(napi_env env,
                                            napi_callback_info info) {
  napi_value argv[1];
  size_t argc;
  if (nwep_napi_get_args(env, info, 0, 1, argv, &argc) != 0) return NULL;

  nwep_log_server_pool *pool;
  int rv = nwep_log_server_pool_new(&pool, NULL);
  if (rv != 0) return nwep_napi_throw(env, rv);

  napi_value external;
  NWEP_NAPI_CALL(env,
                  napi_create_external(env, pool,
                                       napi_log_server_pool_destructor, NULL,
                                       &external));
  return external;
}

static napi_value napi_log_server_pool_free(napi_env env,
                                             napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  return NULL;
}

static napi_value napi_log_server_pool_add(napi_env env,
                                            napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_log_server_pool *pool =
      (nwep_log_server_pool *)nwep_napi_get_external(env, argv[0]);
  if (!pool) return NULL;

  char url[256];
  size_t len;
  if (nwep_napi_get_string(env, argv[1], url, sizeof(url), &len) != 0)
    return NULL;

  int rv = nwep_log_server_pool_add(pool, url);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return NULL;
}

static napi_value napi_log_server_pool_remove(napi_env env,
                                               napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_log_server_pool *pool =
      (nwep_log_server_pool *)nwep_napi_get_external(env, argv[0]);
  if (!pool) return NULL;

  char url[256];
  size_t len;
  if (nwep_napi_get_string(env, argv[1], url, sizeof(url), &len) != 0)
    return NULL;

  int rv = nwep_log_server_pool_remove(pool, url);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return NULL;
}

static napi_value napi_pool_server_to_js(napi_env env,
                                          const nwep_pool_server *server) {
  napi_value obj;
  napi_create_object(env, &obj);

  napi_value url_val;
  napi_create_string_utf8(env, server->url, strlen(server->url), &url_val);
  nwep_napi_set_prop(env, obj, "url", url_val);

  napi_value health_val;
  napi_create_uint32(env, (uint32_t)server->health, &health_val);
  nwep_napi_set_prop(env, obj, "health", health_val);

  napi_value failures_val;
  napi_create_int32(env, server->consecutive_failures, &failures_val);
  nwep_napi_set_prop(env, obj, "consecutiveFailures", failures_val);

  nwep_napi_set_prop(env, obj, "lastSuccess",
                     nwep_napi_create_bigint(env, server->last_success));
  nwep_napi_set_prop(env, obj, "lastFailure",
                     nwep_napi_create_bigint(env, server->last_failure));

  return obj;
}

static napi_value napi_log_server_pool_select(napi_env env,
                                               napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_log_server_pool *pool =
      (nwep_log_server_pool *)nwep_napi_get_external(env, argv[0]);
  if (!pool) return NULL;

  nwep_pool_server server;
  int rv = nwep_log_server_pool_select(pool, &server);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return napi_pool_server_to_js(env, &server);
}

static napi_value napi_log_server_pool_mark_success(napi_env env,
                                                     napi_callback_info info) {
  napi_value argv[3];
  if (nwep_napi_get_args(env, info, 3, 3, argv, NULL) != 0) return NULL;
  nwep_log_server_pool *pool =
      (nwep_log_server_pool *)nwep_napi_get_external(env, argv[0]);
  if (!pool) return NULL;

  char url[256];
  size_t len;
  if (nwep_napi_get_string(env, argv[1], url, sizeof(url), &len) != 0)
    return NULL;

  uint64_t now;
  if (nwep_napi_get_bigint_uint64(env, argv[2], &now) != 0) return NULL;

  nwep_log_server_pool_mark_success(pool, url, now);
  return NULL;
}

static napi_value napi_log_server_pool_mark_failure(napi_env env,
                                                     napi_callback_info info) {
  napi_value argv[3];
  if (nwep_napi_get_args(env, info, 3, 3, argv, NULL) != 0) return NULL;
  nwep_log_server_pool *pool =
      (nwep_log_server_pool *)nwep_napi_get_external(env, argv[0]);
  if (!pool) return NULL;

  char url[256];
  size_t len;
  if (nwep_napi_get_string(env, argv[1], url, sizeof(url), &len) != 0)
    return NULL;

  uint64_t now;
  if (nwep_napi_get_bigint_uint64(env, argv[2], &now) != 0) return NULL;

  nwep_log_server_pool_mark_failure(pool, url, now);
  return NULL;
}

static napi_value napi_log_server_pool_size(napi_env env,
                                             napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_log_server_pool *pool =
      (nwep_log_server_pool *)nwep_napi_get_external(env, argv[0]);
  if (!pool) return NULL;

  napi_value result;
  napi_create_uint32(env, (uint32_t)nwep_log_server_pool_size(pool), &result);
  return result;
}

static napi_value napi_log_server_pool_healthy_count(napi_env env,
                                                      napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_log_server_pool *pool =
      (nwep_log_server_pool *)nwep_napi_get_external(env, argv[0]);
  if (!pool) return NULL;

  napi_value result;
  napi_create_uint32(env,
                     (uint32_t)nwep_log_server_pool_healthy_count(pool),
                     &result);
  return result;
}

napi_value nwep_napi_init_cache(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"identityCacheNew", NULL, napi_identity_cache_new, NULL, NULL, NULL,
       napi_default, NULL},
      {"identityCacheFree", NULL, napi_identity_cache_free, NULL, NULL, NULL,
       napi_default, NULL},
      {"identityCacheLookup", NULL, napi_identity_cache_lookup, NULL, NULL,
       NULL, napi_default, NULL},
      {"identityCacheStore", NULL, napi_identity_cache_store, NULL, NULL, NULL,
       napi_default, NULL},
      {"identityCacheInvalidate", NULL, napi_identity_cache_invalidate, NULL,
       NULL, NULL, napi_default, NULL},
      {"identityCacheClear", NULL, napi_identity_cache_clear, NULL, NULL, NULL,
       napi_default, NULL},
      {"identityCacheSize", NULL, napi_identity_cache_size, NULL, NULL, NULL,
       napi_default, NULL},
      {"identityCacheCapacity", NULL, napi_identity_cache_capacity, NULL, NULL,
       NULL, napi_default, NULL},
      {"logServerPoolNew", NULL, napi_log_server_pool_new, NULL, NULL, NULL,
       napi_default, NULL},
      {"logServerPoolFree", NULL, napi_log_server_pool_free, NULL, NULL, NULL,
       napi_default, NULL},
      {"logServerPoolAdd", NULL, napi_log_server_pool_add, NULL, NULL, NULL,
       napi_default, NULL},
      {"logServerPoolRemove", NULL, napi_log_server_pool_remove, NULL, NULL,
       NULL, napi_default, NULL},
      {"logServerPoolSelect", NULL, napi_log_server_pool_select, NULL, NULL,
       NULL, napi_default, NULL},
      {"logServerPoolMarkSuccess", NULL, napi_log_server_pool_mark_success,
       NULL, NULL, NULL, napi_default, NULL},
      {"logServerPoolMarkFailure", NULL, napi_log_server_pool_mark_failure,
       NULL, NULL, NULL, napi_default, NULL},
      {"logServerPoolSize", NULL, napi_log_server_pool_size, NULL, NULL, NULL,
       napi_default, NULL},
      {"logServerPoolHealthyCount", NULL, napi_log_server_pool_healthy_count,
       NULL, NULL, NULL, napi_default, NULL},
  };
  napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]),
                         props);
  return exports;
}
