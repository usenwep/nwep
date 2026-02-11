#include "nwep_napi.h"

static napi_value napi_stream_respond(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_stream *stream = (nwep_stream *)nwep_napi_get_external(env, argv[0]);
  if (!stream) return NULL;

  /* argv[1] = { status, statusDetails, body } */
  napi_value status_val, details_val, body_val;
  NWEP_NAPI_CALL(env,
                  napi_get_named_property(env, argv[1], "status", &status_val));

  char status[64];
  size_t status_len;
  if (nwep_napi_get_string(env, status_val, status, sizeof(status),
                            &status_len) != 0)
    return NULL;

  nwep_response resp;
  memset(&resp, 0, sizeof(resp));
  resp.status = status;
  resp.status_len = status_len;

  char details[256];
  size_t details_len = 0;
  if (napi_get_named_property(env, argv[1], "statusDetails", &details_val) ==
      napi_ok) {
    napi_valuetype vt;
    if (napi_typeof(env, details_val, &vt) == napi_ok && vt == napi_string) {
      if (nwep_napi_get_string(env, details_val, details, sizeof(details),
                                &details_len) == 0) {
        resp.status_details = details;
        resp.status_details_len = details_len;
      }
    }
  }

  if (napi_get_named_property(env, argv[1], "body", &body_val) == napi_ok) {
    napi_valuetype vt;
    if (napi_typeof(env, body_val, &vt) == napi_ok && vt != napi_undefined &&
        vt != napi_null) {
      uint8_t *body_data;
      size_t body_len;
      if (nwep_napi_get_buffer(env, body_val, &body_data, &body_len) != 0)
        return NULL;
      resp.body = body_data;
      resp.body_len = body_len;
    }
  }

  int rv = nwep_stream_respond(stream, &resp);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return NULL;
}

static napi_value napi_stream_write(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_stream *stream = (nwep_stream *)nwep_napi_get_external(env, argv[0]);
  if (!stream) return NULL;

  uint8_t *data;
  size_t len;
  if (nwep_napi_get_buffer(env, argv[1], &data, &len) != 0) return NULL;

  nwep_ssize n = nwep_stream_write(stream, data, len);
  if (n < 0) return nwep_napi_throw(env, (int)n);

  napi_value result;
  NWEP_NAPI_CALL(env, napi_create_int64(env, (int64_t)n, &result));
  return result;
}

static napi_value napi_stream_end(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_stream *stream = (nwep_stream *)nwep_napi_get_external(env, argv[0]);
  if (!stream) return NULL;

  int rv = nwep_stream_end(stream);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return NULL;
}

static napi_value napi_stream_close(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_stream *stream = (nwep_stream *)nwep_napi_get_external(env, argv[0]);
  if (!stream) return NULL;

  int32_t error;
  if (napi_get_value_int32(env, argv[1], &error) != napi_ok)
    return nwep_napi_throw_type(env, "Expected integer error code");

  nwep_stream_close(stream, (int)error);
  return NULL;
}

static napi_value napi_stream_get_id(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_stream *stream = (nwep_stream *)nwep_napi_get_external(env, argv[0]);
  if (!stream) return NULL;

  int64_t id = nwep_stream_get_id(stream);

  napi_value result;
  NWEP_NAPI_CALL(env, napi_create_int64(env, id, &result));
  return result;
}

static napi_value napi_stream_is_server_initiated(napi_env env,
                                                     napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_stream *stream = (nwep_stream *)nwep_napi_get_external(env, argv[0]);
  if (!stream) return NULL;

  int is_server = nwep_stream_is_server_initiated(stream);

  napi_value result;
  NWEP_NAPI_CALL(env, napi_get_boolean(env, is_server != 0, &result));
  return result;
}

static napi_value napi_stream_get_conn(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_stream *stream = (nwep_stream *)nwep_napi_get_external(env, argv[0]);
  if (!stream) return NULL;

  nwep_conn *conn = nwep_stream_get_conn(stream);
  if (!conn) {
    napi_value null_val;
    napi_get_null(env, &null_val);
    return null_val;
  }

  /* conn is NOT owned by us; no destructor */
  napi_value external;
  NWEP_NAPI_CALL(env,
                  napi_create_external(env, conn, NULL, NULL, &external));
  return external;
}

napi_value nwep_napi_init_stream(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"streamRespond", NULL, napi_stream_respond, NULL, NULL, NULL,
       napi_default, NULL},
      {"streamWrite", NULL, napi_stream_write, NULL, NULL, NULL, napi_default,
       NULL},
      {"streamEnd", NULL, napi_stream_end, NULL, NULL, NULL, napi_default,
       NULL},
      {"streamClose", NULL, napi_stream_close, NULL, NULL, NULL, napi_default,
       NULL},
      {"streamGetId", NULL, napi_stream_get_id, NULL, NULL, NULL, napi_default,
       NULL},
      {"streamIsServerInitiated", NULL, napi_stream_is_server_initiated, NULL,
       NULL, NULL, napi_default, NULL},
      {"streamGetConn", NULL, napi_stream_get_conn, NULL, NULL, NULL,
       napi_default, NULL},
  };
  napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]),
                         props);
  return exports;
}
