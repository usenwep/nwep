#include "nwep_napi.h"

static napi_value napi_nwep_init(napi_env env, napi_callback_info info) {
  int rv = nwep_init();
  if (rv != 0) return nwep_napi_throw(env, rv);
  napi_value result;
  napi_get_undefined(env, &result);
  return result;
}

static napi_value napi_nwep_version(napi_env env, napi_callback_info info) {
  const char *ver = nwep_version();
  napi_value result;
  napi_create_string_utf8(env, ver, strlen(ver), &result);
  return result;
}

static napi_value nwep_napi_module_init(napi_env env, napi_value exports) {
  napi_value init_fn, version_fn;
  napi_create_function(env, "init", NAPI_AUTO_LENGTH, napi_nwep_init, NULL,
                       &init_fn);
  napi_create_function(env, "version", NAPI_AUTO_LENGTH, napi_nwep_version,
                       NULL, &version_fn);
  napi_set_named_property(env, exports, "init", init_fn);
  napi_set_named_property(env, exports, "version", version_fn);

  nwep_napi_init_constants(env, exports);
  nwep_napi_init_error(env, exports);
  nwep_napi_init_crypto(env, exports);
  nwep_napi_init_encoding(env, exports);
  nwep_napi_init_addr(env, exports);
  nwep_napi_init_msg(env, exports);
  nwep_napi_init_handshake(env, exports);
  nwep_napi_init_log(env, exports);
  nwep_napi_init_identity(env, exports);
  nwep_napi_init_server(env, exports);
  nwep_napi_init_client(env, exports);
  nwep_napi_init_conn(env, exports);
  nwep_napi_init_stream(env, exports);
  nwep_napi_init_merkle(env, exports);
  nwep_napi_init_anchor(env, exports);
  nwep_napi_init_trust(env, exports);
  nwep_napi_init_role(env, exports);
  nwep_napi_init_cache(env, exports);

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, nwep_napi_module_init)
