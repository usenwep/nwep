#include "nwep_napi.h"

static napi_value napi_role_from_str(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  char buf[64];
  size_t len;
  if (nwep_napi_get_string(env, argv[0], buf, sizeof(buf), &len) != 0)
    return NULL;

  nwep_server_role role = nwep_role_from_str(buf);
  napi_value result;
  napi_create_uint32(env, (uint32_t)role, &result);
  return result;
}

static napi_value napi_role_to_str(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  uint32_t role;
  if (nwep_napi_get_uint32(env, argv[0], &role) != 0) return NULL;

  const char *str = nwep_role_to_str((nwep_server_role)role);
  napi_value result;
  NWEP_NAPI_CALL(env,
                  napi_create_string_utf8(env, str, strlen(str), &result));
  return result;
}

napi_value nwep_napi_init_role(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"roleFromStr", NULL, napi_role_from_str, NULL, NULL, NULL, napi_default,
       NULL},
      {"roleToStr", NULL, napi_role_to_str, NULL, NULL, NULL, napi_default,
       NULL},
  };
  napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]),
                         props);
  return exports;
}
