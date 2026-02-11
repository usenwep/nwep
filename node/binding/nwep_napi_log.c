#include "nwep_napi.h"

static napi_value napi_log_level_str(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint32_t level;
  if (nwep_napi_get_uint32(env, argv[0], &level) != 0) return NULL;
  const char *s = nwep_log_level_str((nwep_log_level)level);
  napi_value result;
  napi_create_string_utf8(env, s, strlen(s), &result);
  return result;
}

static napi_value napi_log_set_level(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint32_t level;
  if (nwep_napi_get_uint32(env, argv[0], &level) != 0) return NULL;
  nwep_log_set_level((nwep_log_level)level);
  napi_value undef;
  napi_get_undefined(env, &undef);
  return undef;
}

static napi_value napi_log_get_level(napi_env env, napi_callback_info info) {
  (void)info;
  napi_value result;
  napi_create_uint32(env, (uint32_t)nwep_log_get_level(), &result);
  return result;
}

static napi_value napi_log_set_json(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  bool enabled;
  napi_get_value_bool(env, argv[0], &enabled);
  nwep_log_set_json(enabled ? 1 : 0);
  napi_value undef;
  napi_get_undefined(env, &undef);
  return undef;
}

static napi_value napi_log_set_stderr(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  bool enabled;
  napi_get_value_bool(env, argv[0], &enabled);
  nwep_log_set_stderr(enabled ? 1 : 0);
  napi_value undef;
  napi_get_undefined(env, &undef);
  return undef;
}

static napi_value napi_log_write(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc;
  if (nwep_napi_get_args(env, info, 3, 4, argv, &argc) != 0) return NULL;

  uint32_t level;
  if (nwep_napi_get_uint32(env, argv[0], &level) != 0) return NULL;

  char component[128], message[1024];
  size_t clen, mlen;
  if (nwep_napi_get_string(env, argv[1], component, sizeof(component),
                           &clen) != 0)
    return NULL;
  if (nwep_napi_get_string(env, argv[2], message, sizeof(message), &mlen) !=
      0)
    return NULL;

  nwep_log_write((nwep_log_level)level, NULL, component, "%s", message);

  napi_value undef;
  napi_get_undefined(env, &undef);
  return undef;
}

static napi_value napi_log_format_json(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  napi_value level_val, component_val, message_val;
  napi_get_named_property(env, argv[0], "level", &level_val);
  napi_get_named_property(env, argv[0], "component", &component_val);
  napi_get_named_property(env, argv[0], "message", &message_val);

  uint32_t level;
  napi_get_value_uint32(env, level_val, &level);

  char component[128], message[1024];
  size_t clen, mlen;
  napi_get_value_string_utf8(env, component_val, component, sizeof(component),
                             &clen);
  napi_get_value_string_utf8(env, message_val, message, sizeof(message), &mlen);

  nwep_log_entry entry;
  memset(&entry, 0, sizeof(entry));
  entry.level = (nwep_log_level)level;
  entry.component = component;
  entry.message = message;

  char buf[4096];
  size_t written = nwep_log_format_json(buf, sizeof(buf), &entry);
  napi_value result;
  napi_create_string_utf8(env, buf, written, &result);
  return result;
}

napi_value nwep_napi_init_log(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"logLevelStr", NULL, napi_log_level_str, NULL, NULL, NULL, napi_default,
       NULL},
      {"logSetLevel", NULL, napi_log_set_level, NULL, NULL, NULL, napi_default,
       NULL},
      {"logGetLevel", NULL, napi_log_get_level, NULL, NULL, NULL, napi_default,
       NULL},
      {"logSetJson", NULL, napi_log_set_json, NULL, NULL, NULL, napi_default,
       NULL},
      {"logSetStderr", NULL, napi_log_set_stderr, NULL, NULL, NULL,
       napi_default, NULL},
      {"logWrite", NULL, napi_log_write, NULL, NULL, NULL, napi_default, NULL},
      {"logFormatJson", NULL, napi_log_format_json, NULL, NULL, NULL,
       napi_default, NULL},
  };
  napi_define_properties(env, exports,
                         sizeof(props) / sizeof(props[0]), props);
  return exports;
}
