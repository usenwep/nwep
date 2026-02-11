#include "nwep_napi.h"
#include <stdlib.h>

typedef struct nwep_client_wrap {
  nwep_client *client;
  nwep_keypair kp;
} nwep_client_wrap;

static void client_wrap_free(napi_env env, void *data, void *hint) {
  nwep_client_wrap *wrap = (nwep_client_wrap *)data;
  if (wrap->client) {
    nwep_client_free(wrap->client);
  }
  free(wrap);
}

static napi_value napi_client_new(napi_env env, napi_callback_info info) {
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

  nwep_client_wrap *wrap =
      (nwep_client_wrap *)calloc(1, sizeof(nwep_client_wrap));
  if (!wrap) return nwep_napi_throw_msg(env, "Out of memory");

  int rv = nwep_keypair_generate(&wrap->kp);
  if (rv != 0) {
    free(wrap);
    return nwep_napi_throw(env, rv);
  }

  nwep_callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));

  rv = nwep_client_new(&wrap->client, &settings, &callbacks, &wrap->kp, NULL);
  if (rv != 0) {
    free(wrap);
    return nwep_napi_throw(env, rv);
  }

  napi_value external;
  NWEP_NAPI_CALL(env,
                  napi_create_external(env, wrap, client_wrap_free, NULL,
                                       &external));

  napi_value keypair_js = nwep_napi_keypair_to_js(env, &wrap->kp);
  if (!keypair_js) return NULL;

  napi_value result;
  napi_create_object(env, &result);
  nwep_napi_set_prop(env, result, "client", external);
  nwep_napi_set_prop(env, result, "keypair", keypair_js);
  return result;
}

static napi_value napi_client_free(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_client_wrap *wrap =
      (nwep_client_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;
  if (wrap->client) {
    nwep_client_free(wrap->client);
    wrap->client = NULL;
  }
  return NULL;
}

static napi_value napi_client_connect(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (nwep_napi_get_args(env, info, 3, 3, argv, NULL) != 0) return NULL;
  nwep_client_wrap *wrap =
      (nwep_client_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;
  if (!wrap->client)
    return nwep_napi_throw_msg(env, "Client is freed");

  char url_str[512];
  size_t url_len;
  if (nwep_napi_get_string(env, argv[1], url_str, sizeof(url_str), &url_len) !=
      0)
    return NULL;

  nwep_url url;
  int rv = nwep_url_parse(&url, url_str);
  if (rv != 0) return nwep_napi_throw(env, rv);

  uint64_t ts;
  if (nwep_napi_get_bigint_uint64(env, argv[2], &ts) != 0) return NULL;

  rv = nwep_client_connect(wrap->client, &url, NULL, 0, ts);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return NULL;
}

static napi_value napi_client_read(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (nwep_napi_get_args(env, info, 3, 3, argv, NULL) != 0) return NULL;
  nwep_client_wrap *wrap =
      (nwep_client_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;
  if (!wrap->client)
    return nwep_napi_throw_msg(env, "Client is freed");

  uint8_t *data;
  size_t datalen;
  if (nwep_napi_get_buffer(env, argv[1], &data, &datalen) != 0) return NULL;

  uint64_t ts;
  if (nwep_napi_get_bigint_uint64(env, argv[2], &ts) != 0) return NULL;

  nwep_path path;
  memset(&path, 0, sizeof(path));

  int rv = nwep_client_read(wrap->client, &path, data, datalen, ts);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return NULL;
}

static napi_value napi_client_write(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_client_wrap *wrap =
      (nwep_client_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;
  if (!wrap->client)
    return nwep_napi_throw_msg(env, "Client is freed");

  uint64_t ts;
  if (nwep_napi_get_bigint_uint64(env, argv[1], &ts) != 0) return NULL;

  uint8_t buf[1500];
  nwep_path path;
  memset(&path, 0, sizeof(path));

  nwep_ssize n = nwep_client_write(wrap->client, &path, buf, sizeof(buf), ts);
  if (n < 0) return nwep_napi_throw(env, (int)n);
  if (n == 0) {
    napi_value null_val;
    napi_get_null(env, &null_val);
    return null_val;
  }

  return nwep_napi_create_buffer(env, buf, (size_t)n);
}

static napi_value napi_client_handle_expiry(napi_env env,
                                              napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_client_wrap *wrap =
      (nwep_client_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;
  if (!wrap->client)
    return nwep_napi_throw_msg(env, "Client is freed");

  uint64_t ts;
  if (nwep_napi_get_bigint_uint64(env, argv[1], &ts) != 0) return NULL;

  int rv = nwep_client_handle_expiry(wrap->client, ts);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return NULL;
}

static napi_value napi_client_get_expiry(napi_env env,
                                           napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_client_wrap *wrap =
      (nwep_client_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;
  if (!wrap->client)
    return nwep_napi_throw_msg(env, "Client is freed");

  nwep_tstamp expiry = nwep_client_get_expiry(wrap->client);
  return nwep_napi_create_bigint(env, expiry);
}

static napi_value napi_client_close(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_client_wrap *wrap =
      (nwep_client_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;
  if (!wrap->client)
    return nwep_napi_throw_msg(env, "Client is freed");

  nwep_client_close(wrap->client);
  return NULL;
}

static napi_value napi_client_get_conn(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_client_wrap *wrap =
      (nwep_client_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;
  if (!wrap->client)
    return nwep_napi_throw_msg(env, "Client is freed");

  nwep_conn *conn = nwep_client_get_conn(wrap->client);
  if (!conn) {
    napi_value null_val;
    napi_get_null(env, &null_val);
    return null_val;
  }

  napi_value external;
  NWEP_NAPI_CALL(env,
                  napi_create_external(env, conn, NULL, NULL, &external));
  return external;
}

napi_value nwep_napi_init_client(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"clientNew", NULL, napi_client_new, NULL, NULL, NULL, napi_default,
       NULL},
      {"clientFree", NULL, napi_client_free, NULL, NULL, NULL, napi_default,
       NULL},
      {"clientConnect", NULL, napi_client_connect, NULL, NULL, NULL,
       napi_default, NULL},
      {"clientRead", NULL, napi_client_read, NULL, NULL, NULL, napi_default,
       NULL},
      {"clientWrite", NULL, napi_client_write, NULL, NULL, NULL, napi_default,
       NULL},
      {"clientHandleExpiry", NULL, napi_client_handle_expiry, NULL, NULL, NULL,
       napi_default, NULL},
      {"clientGetExpiry", NULL, napi_client_get_expiry, NULL, NULL, NULL,
       napi_default, NULL},
      {"clientClose", NULL, napi_client_close, NULL, NULL, NULL, napi_default,
       NULL},
      {"clientGetConn", NULL, napi_client_get_conn, NULL, NULL, NULL,
       napi_default, NULL},
  };
  napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]),
                         props);
  return exports;
}
