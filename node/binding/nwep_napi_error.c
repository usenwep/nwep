#include "nwep_napi.h"

static napi_value napi_strerror(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  int32_t code;
  NWEP_NAPI_CALL(env, napi_get_value_int32(env, argv[0], &code));
  const char *s = nwep_strerror(code);
  napi_value result;
  napi_create_string_utf8(env, s, strlen(s), &result);
  return result;
}

static napi_value napi_err_is_fatal(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  int32_t code;
  NWEP_NAPI_CALL(env, napi_get_value_int32(env, argv[0], &code));
  napi_value result;
  napi_get_boolean(env, nwep_err_is_fatal(code), &result);
  return result;
}

static napi_value napi_err_category(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  int32_t code;
  NWEP_NAPI_CALL(env, napi_get_value_int32(env, argv[0], &code));
  napi_value result;
  napi_create_uint32(env, (uint32_t)nwep_err_category(code), &result);
  return result;
}

static napi_value napi_err_category_str(napi_env env,
                                         napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint32_t cat;
  NWEP_NAPI_CALL(env, napi_get_value_uint32(env, argv[0], &cat));
  const char *s = nwep_err_category_str((nwep_error_category)cat);
  napi_value result;
  napi_create_string_utf8(env, s, strlen(s), &result);
  return result;
}

static napi_value napi_err_to_status(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  int32_t code;
  NWEP_NAPI_CALL(env, napi_get_value_int32(env, argv[0], &code));
  const char *s = nwep_err_to_status(code);
  napi_value result;
  napi_create_string_utf8(env, s, strlen(s), &result);
  return result;
}

static napi_value napi_error_format(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  /* argv[0] is { code: number, context: string[] } */
  napi_value code_val;
  NWEP_NAPI_CALL(env,
                 napi_get_named_property(env, argv[0], "code", &code_val));
  int32_t code;
  NWEP_NAPI_CALL(env, napi_get_value_int32(env, code_val, &code));

  nwep_error err;
  nwep_error_init(&err, code);

  napi_value ctx_val;
  if (napi_get_named_property(env, argv[0], "context", &ctx_val) == napi_ok) {
    bool is_arr;
    napi_is_array(env, ctx_val, &is_arr);
    if (is_arr) {
      uint32_t len;
      napi_get_array_length(env, ctx_val, &len);
      for (uint32_t i = 0; i < len && i < NWEP_ERR_CONTEXT_MAX; i++) {
        napi_value elem;
        napi_get_element(env, ctx_val, i, &elem);
        char buf[256];
        size_t written;
        napi_get_value_string_utf8(env, elem, buf, sizeof(buf), &written);
        nwep_error_set_context(&err, buf);
      }
    }
  }

  char buf[1024];
  nwep_error_format(&err, buf, sizeof(buf));
  napi_value result;
  napi_create_string_utf8(env, buf, strlen(buf), &result);
  return result;
}

napi_value nwep_napi_init_error(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"strerror", NULL, napi_strerror, NULL, NULL, NULL, napi_default, NULL},
      {"errIsFatal", NULL, napi_err_is_fatal, NULL, NULL, NULL, napi_default,
       NULL},
      {"errCategory", NULL, napi_err_category, NULL, NULL, NULL, napi_default,
       NULL},
      {"errCategoryStr", NULL, napi_err_category_str, NULL, NULL, NULL,
       napi_default, NULL},
      {"errToStatus", NULL, napi_err_to_status, NULL, NULL, NULL, napi_default,
       NULL},
      {"errorFormat", NULL, napi_error_format, NULL, NULL, NULL, napi_default,
       NULL},
  };
  napi_define_properties(env, exports,
                         sizeof(props) / sizeof(props[0]), props);
  return exports;
}
