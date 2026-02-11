#include "nwep_napi.h"
#include <stdlib.h>

typedef struct nwep_napi_hs_wrap {
  nwep_handshake hs;
  nwep_keypair kp;
} nwep_napi_hs_wrap;

static void napi_hs_destructor(napi_env env, void *data, void *hint) {
  (void)env;
  (void)hint;
  nwep_napi_hs_wrap *wrap = (nwep_napi_hs_wrap *)data;
  nwep_handshake_free(&wrap->hs);
  free(wrap);
}

static napi_value napi_handshake_client_init(napi_env env,
                                              napi_callback_info info) {
  napi_value argv[2];
  size_t argc;
  if (nwep_napi_get_args(env, info, 1, 2, argv, &argc) != 0) return NULL;

  nwep_napi_hs_wrap *wrap =
      (nwep_napi_hs_wrap *)calloc(1, sizeof(nwep_napi_hs_wrap));
  if (!wrap) return nwep_napi_throw_msg(env, "Out of memory");

  if (nwep_napi_js_to_keypair(env, argv[0], &wrap->kp) != 0) {
    free(wrap);
    return NULL;
  }

  const nwep_nodeid *expected = NULL;
  nwep_nodeid nid;
  if (argc >= 2) {
    napi_valuetype vt;
    napi_typeof(env, argv[1], &vt);
    if (vt != napi_undefined && vt != napi_null) {
      if (nwep_napi_js_to_nodeid(env, argv[1], &nid) != 0) {
        free(wrap);
        return NULL;
      }
      expected = &nid;
    }
  }

  int rv = nwep_handshake_client_init(&wrap->hs, &wrap->kp, expected);
  if (rv != 0) {
    free(wrap);
    return nwep_napi_throw(env, rv);
  }

  napi_value ext;
  NWEP_NAPI_CALL(env,
                  napi_create_external(env, wrap, napi_hs_destructor, NULL,
                                       &ext));
  return ext;
}

static napi_value napi_handshake_server_init(napi_env env,
                                              napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  nwep_napi_hs_wrap *wrap =
      (nwep_napi_hs_wrap *)calloc(1, sizeof(nwep_napi_hs_wrap));
  if (!wrap) return nwep_napi_throw_msg(env, "Out of memory");

  if (nwep_napi_js_to_keypair(env, argv[0], &wrap->kp) != 0) {
    free(wrap);
    return NULL;
  }

  int rv = nwep_handshake_server_init(&wrap->hs, &wrap->kp);
  if (rv != 0) {
    free(wrap);
    return nwep_napi_throw(env, rv);
  }

  napi_value ext;
  NWEP_NAPI_CALL(env,
                  napi_create_external(env, wrap, napi_hs_destructor, NULL,
                                       &ext));
  return ext;
}

static napi_value napi_handshake_free(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  nwep_napi_hs_wrap *wrap =
      (nwep_napi_hs_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;

  nwep_handshake_free(&wrap->hs);
  memset(&wrap->hs, 0, sizeof(wrap->hs));
  return NULL;
}

static napi_value napi_handshake_set_params(napi_env env,
                                             napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;

  nwep_napi_hs_wrap *wrap =
      (nwep_napi_hs_wrap *)nwep_napi_get_external(env, argv[0]);
  if (!wrap) return NULL;

  nwep_handshake_params params = {0};

  napi_value val;
  napi_valuetype vt;

  if (napi_get_named_property(env, argv[1], "maxStreams", &val) == napi_ok) {
    napi_typeof(env, val, &vt);
    if (vt == napi_number) {
      if (nwep_napi_get_uint32(env, val, &params.max_streams) != 0)
        return NULL;
    }
  }

  if (napi_get_named_property(env, argv[1], "maxMessageSize", &val) ==
      napi_ok) {
    napi_typeof(env, val, &vt);
    if (vt == napi_number) {
      if (nwep_napi_get_uint32(env, val, &params.max_message_size) != 0)
        return NULL;
    }
  }

  static char compression_buf[64];
  if (napi_get_named_property(env, argv[1], "compression", &val) == napi_ok) {
    napi_typeof(env, val, &vt);
    if (vt == napi_string) {
      size_t len;
      if (nwep_napi_get_string(env, val, compression_buf,
                                sizeof(compression_buf), &len) != 0)
        return NULL;
      params.compression = compression_buf;
    }
  }

  static char role_buf[64];
  if (napi_get_named_property(env, argv[1], "role", &val) == napi_ok) {
    napi_typeof(env, val, &vt);
    if (vt == napi_string) {
      size_t len;
      if (nwep_napi_get_string(env, val, role_buf, sizeof(role_buf), &len) !=
          0)
        return NULL;
      params.role = role_buf;
    }
  }

  nwep_handshake_set_params(&wrap->hs, &params);
  return NULL;
}

static napi_value napi_client_state_str(napi_env env,
                                         napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint32_t state;
  if (nwep_napi_get_uint32(env, argv[0], &state) != 0) return NULL;
  const char *str = nwep_client_state_str((nwep_client_state)state);
  napi_value result;
  NWEP_NAPI_CALL(env,
                  napi_create_string_utf8(env, str, strlen(str), &result));
  return result;
}

static napi_value napi_server_state_str(napi_env env,
                                         napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint32_t state;
  if (nwep_napi_get_uint32(env, argv[0], &state) != 0) return NULL;
  const char *str = nwep_server_state_str((nwep_server_state)state);
  napi_value result;
  NWEP_NAPI_CALL(env,
                  napi_create_string_utf8(env, str, strlen(str), &result));
  return result;
}

napi_value nwep_napi_init_handshake(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"handshakeClientInit", NULL, napi_handshake_client_init, NULL, NULL,
       NULL, napi_default, NULL},
      {"handshakeServerInit", NULL, napi_handshake_server_init, NULL, NULL,
       NULL, napi_default, NULL},
      {"handshakeFree", NULL, napi_handshake_free, NULL, NULL, NULL,
       napi_default, NULL},
      {"handshakeSetParams", NULL, napi_handshake_set_params, NULL, NULL, NULL,
       napi_default, NULL},
      {"clientStateStr", NULL, napi_client_state_str, NULL, NULL, NULL,
       napi_default, NULL},
      {"serverStateStr", NULL, napi_server_state_str, NULL, NULL, NULL,
       napi_default, NULL},
  };
  napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]),
                         props);
  return exports;
}
