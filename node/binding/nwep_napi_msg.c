#include "nwep_napi.h"

static napi_value nwep_napi_headers_to_js(napi_env env,
                                            const nwep_header *headers,
                                            size_t count) {
  napi_value arr;
  napi_create_array_with_length(env, count, &arr);
  for (size_t i = 0; i < count; i++) {
    napi_value obj, name_val, value_val;
    napi_create_object(env, &obj);
    napi_create_string_utf8(env, (const char *)headers[i].name,
                            headers[i].name_len, &name_val);
    value_val =
        nwep_napi_create_buffer(env, headers[i].value, headers[i].value_len);
    napi_set_named_property(env, obj, "name", name_val);
    napi_set_named_property(env, obj, "value", value_val);
    napi_set_element(env, arr, (uint32_t)i, obj);
  }
  return arr;
}

static napi_value napi_msg_encode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  /* Extract type */
  napi_value type_val;
  napi_get_named_property(env, argv[0], "type", &type_val);
  uint32_t type;
  napi_get_value_uint32(env, type_val, &type);

  /* Extract headers array */
  napi_value headers_val;
  napi_get_named_property(env, argv[0], "headers", &headers_val);
  uint32_t header_count = 0;
  bool is_arr;
  napi_is_array(env, headers_val, &is_arr);
  if (is_arr) napi_get_array_length(env, headers_val, &header_count);

  nwep_header headers[NWEP_MAX_HEADERS];
  /* Temp storage for header strings */
  char names[NWEP_MAX_HEADERS][256];
  uint8_t *values[NWEP_MAX_HEADERS];
  size_t value_lens[NWEP_MAX_HEADERS];

  for (uint32_t i = 0; i < header_count && i < NWEP_MAX_HEADERS; i++) {
    napi_value elem, n_val, v_val;
    napi_get_element(env, headers_val, i, &elem);
    napi_get_named_property(env, elem, "name", &n_val);
    napi_get_named_property(env, elem, "value", &v_val);
    size_t nlen;
    napi_get_value_string_utf8(env, n_val, names[i], sizeof(names[i]), &nlen);
    nwep_napi_get_buffer(env, v_val, &values[i], &value_lens[i]);
    nwep_header_set_n(&headers[i], (const uint8_t *)names[i], nlen, values[i],
                      value_lens[i]);
  }

  /* Extract body */
  napi_value body_val;
  napi_get_named_property(env, argv[0], "body", &body_val);
  uint8_t *body = NULL;
  size_t body_len = 0;
  napi_valuetype body_type;
  napi_typeof(env, body_val, &body_type);
  if (body_type != napi_undefined && body_type != napi_null) {
    nwep_napi_get_buffer(env, body_val, &body, &body_len);
  }

  nwep_msg msg;
  nwep_msg_init(&msg, (uint8_t)type);
  msg.headers = headers;
  msg.header_count = header_count;
  msg.body = body;
  msg.body_len = body_len;

  size_t enc_len = nwep_msg_encode_len(&msg);
  napi_value buf;
  void *dest;
  napi_create_buffer(env, enc_len, &dest, &buf);
  size_t written = nwep_msg_encode((uint8_t *)dest, enc_len, &msg);
  if (written == 0) return nwep_napi_throw_msg(env, "msg_encode failed");
  return buf;
}

static napi_value napi_msg_decode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint8_t *data;
  size_t len;
  if (nwep_napi_get_buffer(env, argv[0], &data, &len) != 0) return NULL;

  nwep_header headers[NWEP_MAX_HEADERS];
  nwep_msg msg;
  int rv = nwep_msg_decode(&msg, data, len, headers, NWEP_MAX_HEADERS);
  if (rv != 0) return nwep_napi_throw(env, rv);

  napi_value obj, type_val, hdrs_val, body_val;
  napi_create_object(env, &obj);
  napi_create_uint32(env, msg.type, &type_val);
  hdrs_val = nwep_napi_headers_to_js(env, msg.headers, msg.header_count);
  body_val = nwep_napi_create_buffer(env, msg.body, msg.body_len);
  napi_set_named_property(env, obj, "type", type_val);
  napi_set_named_property(env, obj, "headers", hdrs_val);
  napi_set_named_property(env, obj, "body", body_val);
  return obj;
}

static napi_value napi_msg_decode_header(napi_env env,
                                          napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint8_t *data;
  size_t len;
  if (nwep_napi_get_buffer(env, argv[0], &data, &len) != 0) return NULL;
  uint32_t payload_len;
  int rv = nwep_msg_decode_header(&payload_len, data, len);
  if (rv != 0) return nwep_napi_throw(env, rv);
  napi_value result;
  napi_create_uint32(env, payload_len, &result);
  return result;
}

static napi_value napi_msg_encode_len(napi_env env, napi_callback_info info) {
  /* This is a helper - takes type + header_count + body_len */
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  /* Minimal: just compute from type */
  nwep_msg msg;
  memset(&msg, 0, sizeof(msg));
  napi_value type_val;
  napi_get_named_property(env, argv[0], "type", &type_val);
  uint32_t type;
  napi_get_value_uint32(env, type_val, &type);
  msg.type = (uint8_t)type;

  size_t len = nwep_msg_encode_len(&msg);
  napi_value result;
  napi_create_uint32(env, (uint32_t)len, &result);
  return result;
}

static napi_value napi_request_build(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc;
  if (nwep_napi_get_args(env, info, 2, 4, argv, &argc) != 0) return NULL;

  char method[32], path[256];
  size_t mlen, plen;
  if (nwep_napi_get_string(env, argv[0], method, sizeof(method), &mlen) != 0)
    return NULL;
  if (nwep_napi_get_string(env, argv[1], path, sizeof(path), &plen) != 0)
    return NULL;

  uint8_t *body = NULL;
  size_t body_len = 0;
  if (argc > 2) {
    napi_valuetype bt;
    napi_typeof(env, argv[2], &bt);
    if (bt != napi_undefined && bt != napi_null) {
      nwep_napi_get_buffer(env, argv[2], &body, &body_len);
    }
  }

  nwep_header headers[NWEP_MAX_HEADERS];
  nwep_msg msg;
  int rv = nwep_request_build(&msg, headers, NWEP_MAX_HEADERS, method, path,
                              body, body_len);
  if (rv != 0) return nwep_napi_throw(env, rv);

  size_t enc_len = nwep_msg_encode_len(&msg);
  napi_value buf;
  void *dest;
  napi_create_buffer(env, enc_len, &dest, &buf);
  nwep_msg_encode((uint8_t *)dest, enc_len, &msg);
  return buf;
}

static napi_value napi_response_build(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc;
  if (nwep_napi_get_args(env, info, 1, 4, argv, &argc) != 0) return NULL;

  char status[64];
  size_t slen;
  if (nwep_napi_get_string(env, argv[0], status, sizeof(status), &slen) != 0)
    return NULL;

  const char *details = NULL;
  char details_buf[256];
  if (argc > 1) {
    napi_valuetype dt;
    napi_typeof(env, argv[1], &dt);
    if (dt == napi_string) {
      size_t dlen;
      nwep_napi_get_string(env, argv[1], details_buf, sizeof(details_buf),
                           &dlen);
      details = details_buf;
    }
  }

  uint8_t *body = NULL;
  size_t body_len = 0;
  if (argc > 2) {
    napi_valuetype bt;
    napi_typeof(env, argv[2], &bt);
    if (bt != napi_undefined && bt != napi_null) {
      nwep_napi_get_buffer(env, argv[2], &body, &body_len);
    }
  }

  nwep_header headers[NWEP_MAX_HEADERS];
  nwep_msg msg;
  int rv = nwep_response_build(&msg, headers, NWEP_MAX_HEADERS, status,
                               details, body, body_len);
  if (rv != 0) return nwep_napi_throw(env, rv);

  size_t enc_len = nwep_msg_encode_len(&msg);
  napi_value buf;
  void *dest;
  napi_create_buffer(env, enc_len, &dest, &buf);
  nwep_msg_encode((uint8_t *)dest, enc_len, &msg);
  return buf;
}

static napi_value napi_method_is_valid(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  char method[64];
  size_t len;
  if (nwep_napi_get_string(env, argv[0], method, sizeof(method), &len) != 0)
    return NULL;
  napi_value result;
  napi_get_boolean(env, nwep_method_is_valid(method), &result);
  return result;
}

static napi_value napi_method_is_idempotent(napi_env env,
                                             napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  char method[64];
  size_t len;
  if (nwep_napi_get_string(env, argv[0], method, sizeof(method), &len) != 0)
    return NULL;
  napi_value result;
  napi_get_boolean(env, nwep_method_is_idempotent(method), &result);
  return result;
}

static napi_value napi_method_allowed_0rtt(napi_env env,
                                            napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  char method[64];
  size_t len;
  if (nwep_napi_get_string(env, argv[0], method, sizeof(method), &len) != 0)
    return NULL;
  napi_value result;
  napi_get_boolean(env, nwep_method_allowed_0rtt(method), &result);
  return result;
}

static napi_value napi_status_is_valid(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  char status[64];
  size_t len;
  if (nwep_napi_get_string(env, argv[0], status, sizeof(status), &len) != 0)
    return NULL;
  napi_value result;
  napi_get_boolean(env, nwep_status_is_valid(status), &result);
  return result;
}

static napi_value napi_status_is_success(napi_env env,
                                          napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  char status[64];
  size_t len;
  if (nwep_napi_get_string(env, argv[0], status, sizeof(status), &len) != 0)
    return NULL;
  napi_value result;
  napi_get_boolean(env, nwep_status_is_success(status), &result);
  return result;
}

static napi_value napi_status_is_error(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  char status[64];
  size_t len;
  if (nwep_napi_get_string(env, argv[0], status, sizeof(status), &len) != 0)
    return NULL;
  napi_value result;
  napi_get_boolean(env, nwep_status_is_error(status), &result);
  return result;
}

napi_value nwep_napi_init_msg(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"msgEncode", NULL, napi_msg_encode, NULL, NULL, NULL, napi_default,
       NULL},
      {"msgDecode", NULL, napi_msg_decode, NULL, NULL, NULL, napi_default,
       NULL},
      {"msgDecodeHeader", NULL, napi_msg_decode_header, NULL, NULL, NULL,
       napi_default, NULL},
      {"msgEncodeLen", NULL, napi_msg_encode_len, NULL, NULL, NULL,
       napi_default, NULL},
      {"requestBuild", NULL, napi_request_build, NULL, NULL, NULL,
       napi_default, NULL},
      {"responseBuild", NULL, napi_response_build, NULL, NULL, NULL,
       napi_default, NULL},
      {"methodIsValid", NULL, napi_method_is_valid, NULL, NULL, NULL,
       napi_default, NULL},
      {"methodIsIdempotent", NULL, napi_method_is_idempotent, NULL, NULL, NULL,
       napi_default, NULL},
      {"methodAllowed0rtt", NULL, napi_method_allowed_0rtt, NULL, NULL, NULL,
       napi_default, NULL},
      {"statusIsValid", NULL, napi_status_is_valid, NULL, NULL, NULL,
       napi_default, NULL},
      {"statusIsSuccess", NULL, napi_status_is_success, NULL, NULL, NULL,
       napi_default, NULL},
      {"statusIsError", NULL, napi_status_is_error, NULL, NULL, NULL,
       napi_default, NULL},
  };
  napi_define_properties(env, exports,
                         sizeof(props) / sizeof(props[0]), props);
  return exports;
}
