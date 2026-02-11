#include "nwep_napi.h"
#include <stdlib.h>

typedef struct nwep_server_wrap {
  nwep_server *server;
  nwep_keypair kp;
} nwep_server_wrap;

static void server_wrap_free(napi_env env, void *data, void *hint) {
  nwep_server_wrap *wrap = (nwep_server_wrap *)data;
  if (wrap->server) {
    nwep_server_free(wrap->server);
  }
  free(wrap);
}

static napi_value napi_server_new(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 0, 1, argv, NULL) != 0) return NULL;

  nwep_settings settings;
  nwep_settings_default(&settings);

  napi_valuetype vt;
  if (napi_typeof(env, argv[0], &vt) == napi_ok && vt == napi_object) {
    napi_value val;
    uint32_t u32;

    if (napi_get_named_property(env, argv[0], "maxStreams", &val) == napi_ok) {
      if (napi_typeof(env, val, &vt) == napi_ok && vt == napi_number) {
        napi_get_value_uint32(env, val, &u32);
        settings.max_streams = u32;
      }
    }
    if (napi_get_named_property(env, argv[0], "maxMessageSize", &val) ==
        napi_ok) {
      if (napi_typeof(env, val, &vt) == napi_ok && vt == napi_number) {
        napi_get_value_uint32(env, val, &u32);
        settings.max_message_size = u32;
      }
    }
    if (napi_get_named_property(env, argv[0], "timeoutMs", &val) == napi_ok) {
      if (napi_typeof(env, val, &vt) == napi_ok && vt == napi_number) {
        napi_get_value_uint32(env, val, &u32);
        settings.timeout_ms = u32;
      }
    }
  }

  nwep_server_wrap *wrap =
      (nwep_server_wrap *)calloc(1, sizeof(nwep_server_wrap));
  if (!wrap) return nwep_napi_throw_msg(env, "Out of memory");

  int rv = nwep_keypair_generate(&wrap->kp);
  if (rv != 0) {
    free(wrap);
    return nwep_napi_throw(env, rv);
  }

  nwep_callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));

  rv = nwep_server_new(&wrap->server, &settings, &callbacks, &wrap->kp, NULL);
  if (rv != 0) {
    free(wrap);
    return nwep_napi_throw(env, rv);
  }

  napi_value external;
  NWEP_NAPI_CALL(env,
                  napi_create_external(env, wrap, server_wrap_free, NULL,
                                       &external));

  napi_value keypair_js = nwep_napi_keypair_to_js(env, &wrap->kp);
  if (!keypair_js) return NULL;

  napi_value result;
  napi_create_object(env, &result);
  nwep_napi_set_prop(env, result, "server", external);
  nwep_napi_set_prop(env, result, "keypair", keypair_js);
  return result;
}

static napi_value napi_server_free(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_server_wrap *wrap =
      (nwep_server_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;
  if (wrap->server) {
    nwep_server_free(wrap->server);
    wrap->server = NULL;
  }
  return NULL;
}

static napi_value napi_server_read(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  if (nwep_napi_get_args(env, info, 4, 4, argv, NULL) != 0) return NULL;
  nwep_server_wrap *wrap =
      (nwep_server_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;
  if (!wrap->server)
    return nwep_napi_throw_msg(env, "Server is freed");

  uint8_t *path_data;
  size_t path_len;
  if (nwep_napi_get_buffer(env, argv[1], &path_data, &path_len) != 0)
    return NULL;
  if (path_len != sizeof(nwep_path))
    return nwep_napi_throw_type(env, "Path buffer must be sizeof(nwep_path)");

  uint8_t *data;
  size_t datalen;
  if (nwep_napi_get_buffer(env, argv[2], &data, &datalen) != 0) return NULL;

  uint64_t ts;
  if (nwep_napi_get_bigint_uint64(env, argv[3], &ts) != 0) return NULL;

  int rv = nwep_server_read(wrap->server, (const nwep_path *)path_data, data,
                             datalen, ts);
  if (rv != 0) return nwep_napi_throw(env, rv);

  return NULL;
}

static napi_value napi_server_write(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_server_wrap *wrap =
      (nwep_server_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;
  if (!wrap->server)
    return nwep_napi_throw_msg(env, "Server is freed");

  uint64_t ts;
  if (nwep_napi_get_bigint_uint64(env, argv[1], &ts) != 0) return NULL;

  uint8_t buf[1500];
  nwep_path path;
  memset(&path, 0, sizeof(path));

  nwep_ssize n = nwep_server_write(wrap->server, &path, buf, sizeof(buf), ts);
  if (n < 0) return nwep_napi_throw(env, (int)n);
  if (n == 0) {
    napi_value null_val;
    napi_get_null(env, &null_val);
    return null_val;
  }

  napi_value data_buf = nwep_napi_create_buffer(env, buf, (size_t)n);
  if (!data_buf) return NULL;

  napi_value path_buf =
      nwep_napi_create_buffer(env, (const uint8_t *)&path, sizeof(path));
  if (!path_buf) return NULL;

  napi_value result;
  napi_create_object(env, &result);
  nwep_napi_set_prop(env, result, "data", data_buf);
  nwep_napi_set_prop(env, result, "path", path_buf);
  return result;
}

static napi_value napi_server_handle_expiry(napi_env env,
                                              napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_server_wrap *wrap =
      (nwep_server_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;
  if (!wrap->server)
    return nwep_napi_throw_msg(env, "Server is freed");

  uint64_t ts;
  if (nwep_napi_get_bigint_uint64(env, argv[1], &ts) != 0) return NULL;

  int rv = nwep_server_handle_expiry(wrap->server, ts);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return NULL;
}

static napi_value napi_server_get_expiry(napi_env env,
                                           napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_server_wrap *wrap =
      (nwep_server_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;
  if (!wrap->server)
    return nwep_napi_throw_msg(env, "Server is freed");

  nwep_tstamp expiry = nwep_server_get_expiry(wrap->server);
  return nwep_napi_create_bigint(env, expiry);
}

static napi_value napi_server_close(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_server_wrap *wrap =
      (nwep_server_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;
  if (!wrap->server)
    return nwep_napi_throw_msg(env, "Server is freed");

  nwep_server_close(wrap->server);
  return NULL;
}

napi_value nwep_napi_init_server(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"serverNew", NULL, napi_server_new, NULL, NULL, NULL, napi_default,
       NULL},
      {"serverFree", NULL, napi_server_free, NULL, NULL, NULL, napi_default,
       NULL},
      {"serverRead", NULL, napi_server_read, NULL, NULL, NULL, napi_default,
       NULL},
      {"serverWrite", NULL, napi_server_write, NULL, NULL, NULL, napi_default,
       NULL},
      {"serverHandleExpiry", NULL, napi_server_handle_expiry, NULL, NULL, NULL,
       napi_default, NULL},
      {"serverGetExpiry", NULL, napi_server_get_expiry, NULL, NULL, NULL,
       napi_default, NULL},
      {"serverClose", NULL, napi_server_close, NULL, NULL, NULL, napi_default,
       NULL},
  };
  napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]),
                         props);
  return exports;
}
