/*
 * nwep
 *
 * Copyright (c) 2026 nwep contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "nwep_internal.h"

#include <stdlib.h>
#include <string.h>

/*
 * Helper for length-aware string comparison (header values aren't null-terminated)
 */
static int streq_n(const uint8_t *s, size_t slen, const char *expected) {
  size_t expected_len = strlen(expected);
  return slen == expected_len && memcmp(s, expected, slen) == 0;
}

int nwep_method_is_valid(const char *method) {
  if (method == NULL) {
    return 0;
  }

  return strcmp(method, NWEP_METHOD_READ) == 0 ||
         strcmp(method, NWEP_METHOD_WRITE) == 0 ||
         strcmp(method, NWEP_METHOD_UPDATE) == 0 ||
         strcmp(method, NWEP_METHOD_DELETE) == 0 ||
         strcmp(method, NWEP_METHOD_CONNECT) == 0 ||
         strcmp(method, NWEP_METHOD_HEARTBEAT) == 0;
}

int nwep_method_is_idempotent(const char *method) {
  if (method == NULL) {
    return 0;
  }

  return strcmp(method, NWEP_METHOD_READ) == 0 ||
         strcmp(method, NWEP_METHOD_DELETE) == 0 ||
         strcmp(method, NWEP_METHOD_HEARTBEAT) == 0;
}

int nwep_method_allowed_0rtt(const char *method) {
  if (method == NULL) {
    return 0;
  }

  /* Only READ is allowed in 0-RTT for replay safety */
  return strcmp(method, NWEP_METHOD_READ) == 0;
}

/*
 * Length-aware 0-RTT check for parsing (header values aren't null-terminated)
 */
static int method_allowed_0rtt_n(const uint8_t *method, size_t len) {
  if (method == NULL || len == 0) {
    return 0;
  }
  /* Only READ is allowed in 0-RTT for replay safety */
  return streq_n(method, len, NWEP_METHOD_READ);
}

int nwep_status_is_valid(const char *status) {
  if (status == NULL) {
    return 0;
  }

  if (strcmp(status, NWEP_STATUS_OK) == 0 ||
      strcmp(status, NWEP_STATUS_CREATED) == 0 ||
      strcmp(status, NWEP_STATUS_ACCEPTED) == 0 ||
      strcmp(status, NWEP_STATUS_NO_CONTENT) == 0) {
    return 1;
  }

  if (strcmp(status, NWEP_STATUS_BAD_REQUEST) == 0 ||
      strcmp(status, NWEP_STATUS_UNAUTHORIZED) == 0 ||
      strcmp(status, NWEP_STATUS_FORBIDDEN) == 0 ||
      strcmp(status, NWEP_STATUS_NOT_FOUND) == 0 ||
      strcmp(status, NWEP_STATUS_CONFLICT) == 0 ||
      strcmp(status, NWEP_STATUS_RATE_LIMITED) == 0) {
    return 1;
  }

  if (strcmp(status, NWEP_STATUS_INTERNAL_ERROR) == 0 ||
      strcmp(status, NWEP_STATUS_UNAVAILABLE) == 0) {
    return 1;
  }

  return 0;
}

int nwep_status_is_success(const char *status) {
  if (status == NULL) {
    return 0;
  }

  return strcmp(status, NWEP_STATUS_OK) == 0 ||
         strcmp(status, NWEP_STATUS_CREATED) == 0 ||
         strcmp(status, NWEP_STATUS_ACCEPTED) == 0 ||
         strcmp(status, NWEP_STATUS_NO_CONTENT) == 0;
}

int nwep_status_is_error(const char *status) {
  if (status == NULL) {
    return 0;
  }

  return !nwep_status_is_success(status);
}

/*
 * Length-aware method validation for parsing (header values aren't null-terminated)
 */
static int method_is_valid_n(const uint8_t *method, size_t len) {
  if (method == NULL || len == 0) {
    return 0;
  }

  return streq_n(method, len, NWEP_METHOD_READ) ||
         streq_n(method, len, NWEP_METHOD_WRITE) ||
         streq_n(method, len, NWEP_METHOD_UPDATE) ||
         streq_n(method, len, NWEP_METHOD_DELETE) ||
         streq_n(method, len, NWEP_METHOD_CONNECT) ||
         streq_n(method, len, NWEP_METHOD_HEARTBEAT);
}

int nwep_request_parse(nwep_request *req, const nwep_msg *msg) {
  const nwep_header *hdr;
  const nwep_header *method_hdr;

  if (req == NULL || msg == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(req, 0, sizeof(*req));
  if (msg->type != NWEP_MSG_REQUEST) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  method_hdr = nwep_msg_find_header(msg, NWEP_HDR_METHOD);
  if (method_hdr == NULL || method_hdr->value_len == 0) {
    return NWEP_ERR_PROTO_MISSING_HEADER;
  }

  req->method = (const char *)method_hdr->value;
  req->method_len = method_hdr->value_len;
  if (!method_is_valid_n(method_hdr->value, method_hdr->value_len)) {
    return NWEP_ERR_PROTO_INVALID_METHOD;
  }

  hdr = nwep_msg_find_header(msg, NWEP_HDR_PATH);
  if (hdr != NULL && hdr->value_len > 0) {
    req->path = (const char *)hdr->value;
    req->path_len = hdr->value_len;
  } else if (!streq_n(method_hdr->value, method_hdr->value_len, NWEP_METHOD_CONNECT) &&
             !streq_n(method_hdr->value, method_hdr->value_len, NWEP_METHOD_HEARTBEAT)) {
    return NWEP_ERR_PROTO_MISSING_HEADER;
  }
  hdr = nwep_msg_find_header(msg, NWEP_HDR_REQUEST_ID);
  if (hdr != NULL && hdr->value_len == NWEP_REQUEST_ID_LEN) {
    memcpy(req->request_id, hdr->value, NWEP_REQUEST_ID_LEN);
  }
  hdr = nwep_msg_find_header(msg, NWEP_HDR_TRACE_ID);
  if (hdr != NULL && hdr->value_len == NWEP_TRACE_ID_LEN) {
    memcpy(req->trace_id, hdr->value, NWEP_TRACE_ID_LEN);
  }
  req->headers = msg->headers;
  req->header_count = msg->header_count;
  req->body = msg->body;
  req->body_len = msg->body_len;

  return 0;
}

/*
 * Length-aware status validation for parsing (header values aren't null-terminated)
 */
static int status_is_valid_n(const uint8_t *status, size_t len) {
  if (status == NULL || len == 0) {
    return 0;
  }

  /* Success statuses */
  if (streq_n(status, len, NWEP_STATUS_OK) ||
      streq_n(status, len, NWEP_STATUS_CREATED) ||
      streq_n(status, len, NWEP_STATUS_ACCEPTED) ||
      streq_n(status, len, NWEP_STATUS_NO_CONTENT)) {
    return 1;
  }

  /* Client error statuses */
  if (streq_n(status, len, NWEP_STATUS_BAD_REQUEST) ||
      streq_n(status, len, NWEP_STATUS_UNAUTHORIZED) ||
      streq_n(status, len, NWEP_STATUS_FORBIDDEN) ||
      streq_n(status, len, NWEP_STATUS_NOT_FOUND) ||
      streq_n(status, len, NWEP_STATUS_CONFLICT) ||
      streq_n(status, len, NWEP_STATUS_RATE_LIMITED)) {
    return 1;
  }

  /* Server error statuses */
  if (streq_n(status, len, NWEP_STATUS_INTERNAL_ERROR) ||
      streq_n(status, len, NWEP_STATUS_UNAVAILABLE)) {
    return 1;
  }

  return 0;
}

int nwep_response_parse(nwep_response *resp, const nwep_msg *msg) {
  const nwep_header *hdr;

  if (resp == NULL || msg == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(resp, 0, sizeof(*resp));
  if (msg->type != NWEP_MSG_RESPONSE) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  hdr = nwep_msg_find_header(msg, NWEP_HDR_STATUS);
  if (hdr == NULL || hdr->value_len == 0) {
    return NWEP_ERR_PROTO_MISSING_HEADER;
  }
  resp->status = (const char *)hdr->value;
  resp->status_len = hdr->value_len;
  if (!status_is_valid_n(hdr->value, hdr->value_len)) {
    return NWEP_ERR_PROTO_INVALID_STATUS;
  }

  hdr = nwep_msg_find_header(msg, NWEP_HDR_STATUS_DETAILS);
  if (hdr != NULL && hdr->value_len > 0) {
    resp->status_details = (const char *)hdr->value;
    resp->status_details_len = hdr->value_len;
  }
  resp->headers = msg->headers;
  resp->header_count = msg->header_count;
  resp->body = msg->body;
  resp->body_len = msg->body_len;

  return 0;
}

int nwep_request_build(nwep_msg *msg, nwep_header *headers, size_t max_headers,
                       const char *method, const char *path,
                       const uint8_t *body, size_t body_len) {
  size_t hdr_count = 0;

  if (msg == NULL || headers == NULL || method == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (max_headers < 4) {
    return NWEP_ERR_PROTO_TOO_MANY_HEADERS;
  }
  if (!nwep_method_is_valid(method)) {
    return NWEP_ERR_PROTO_INVALID_METHOD;
  }

  nwep_msg_init(msg, NWEP_MSG_REQUEST);
  msg->headers = headers;
  nwep_header_set(&headers[hdr_count++], NWEP_HDR_METHOD, method);
  if (path != NULL) {
    nwep_header_set(&headers[hdr_count++], NWEP_HDR_PATH, path);
  } else if (strcmp(method, NWEP_METHOD_CONNECT) != 0 &&
             strcmp(method, NWEP_METHOD_HEARTBEAT) != 0) {
    return NWEP_ERR_PROTO_MISSING_HEADER;
  }
  if (hdr_count < max_headers) {
    uint8_t request_id[NWEP_REQUEST_ID_LEN];
    if (nwep_request_id_generate(request_id) == 0) {
      headers[hdr_count].name = (const uint8_t *)NWEP_HDR_REQUEST_ID;
      headers[hdr_count].name_len = strlen(NWEP_HDR_REQUEST_ID);
      headers[hdr_count].value = request_id;
      headers[hdr_count].value_len = NWEP_REQUEST_ID_LEN;
      hdr_count++;
    }
  }
  if (hdr_count < max_headers) {
    uint8_t trace_id[NWEP_TRACE_ID_LEN];
    if (nwep_trace_id_generate(trace_id) == 0) {
      headers[hdr_count].name = (const uint8_t *)NWEP_HDR_TRACE_ID;
      headers[hdr_count].name_len = strlen(NWEP_HDR_TRACE_ID);
      headers[hdr_count].value = trace_id;
      headers[hdr_count].value_len = NWEP_TRACE_ID_LEN;
      hdr_count++;
    }
  }

  msg->header_count = hdr_count;
  msg->body = body;
  msg->body_len = body_len;

  return 0;
}

int nwep_response_build(nwep_msg *msg, nwep_header *headers, size_t max_headers,
                        const char *status, const char *status_details,
                        const uint8_t *body, size_t body_len) {
  size_t hdr_count = 0;

  if (msg == NULL || headers == NULL || status == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (max_headers < 2) {
    return NWEP_ERR_PROTO_TOO_MANY_HEADERS;
  }
  if (!nwep_status_is_valid(status)) {
    return NWEP_ERR_PROTO_INVALID_STATUS;
  }

  nwep_msg_init(msg, NWEP_MSG_RESPONSE);
  msg->headers = headers;
  nwep_header_set(&headers[hdr_count++], NWEP_HDR_STATUS, status);
  if (status_details != NULL && hdr_count < max_headers) {
    nwep_header_set(&headers[hdr_count++], NWEP_HDR_STATUS_DETAILS,
                    status_details);
  }

  msg->header_count = hdr_count;
  msg->body = body;
  msg->body_len = body_len;

  return 0;
}

int nwep_stream_msg_build(nwep_msg *msg, const uint8_t *data, size_t data_len,
                          int is_final) {
  if (msg == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  nwep_msg_init(msg, NWEP_MSG_STREAM);
  msg->headers = NULL;
  msg->header_count = 0;
  msg->body = data;
  msg->body_len = data_len;
  (void)is_final;

  return 0;
}

int nwep_stream_process_request(nwep_stream *stream, const uint8_t *data,
                                size_t data_len, int is_0rtt) {
  nwep_msg msg;
  nwep_header headers[NWEP_MAX_HEADERS];
  nwep_request req;
  nwep_conn *conn;
  const nwep_header *method_hdr;
  int rv;

  if (stream == NULL || data == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  conn = stream->conn;
  if (conn == NULL) {
    return NWEP_ERR_INTERNAL_INVALID_STATE;
  }

  rv = nwep_msg_decode(&msg, data, data_len, headers, NWEP_MAX_HEADERS);
  if (rv != 0) {
    return rv;
  }
  rv = nwep_request_parse(&req, &msg);
  if (rv != 0) {
    return rv;
  }
  /* Use length-aware check since header values aren't null-terminated */
  method_hdr = nwep_msg_find_header(&msg, NWEP_HDR_METHOD);
  if (is_0rtt && method_hdr != NULL &&
      !method_allowed_0rtt_n(method_hdr->value, method_hdr->value_len)) {
    return NWEP_ERR_PROTO_0RTT_REJECTED;
  }
  stream->method = req.method;
  stream->path = req.path;
  stream->msg.type = NWEP_MSG_REQUEST;
  memcpy(stream->headers, headers, msg.header_count * sizeof(nwep_header));
  stream->msg.headers = stream->headers;
  stream->msg.header_count = msg.header_count;
  memcpy(stream->trace_id, req.trace_id, NWEP_TRACE_ID_LEN);
  if (conn->callbacks.on_request != NULL) {
    rv = conn->callbacks.on_request(conn, stream, &req, conn->user_data);
    if (rv != 0) {
      return rv;
    }
  }

  return 0;
}

int nwep_stream_process_response(nwep_stream *stream, const uint8_t *data,
                                 size_t data_len) {
  nwep_msg msg;
  nwep_header headers[NWEP_MAX_HEADERS];
  nwep_response resp;
  nwep_conn *conn;
  int rv;

  if (stream == NULL || data == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  conn = stream->conn;
  if (conn == NULL) {
    return NWEP_ERR_INTERNAL_INVALID_STATE;
  }

  rv = nwep_msg_decode(&msg, data, data_len, headers, NWEP_MAX_HEADERS);
#ifdef NWEP_DEBUG
  fprintf(stderr, "[process_response] msg_decode returned %d\n", rv);
#endif
  if (rv != 0) {
    return rv;
  }
  rv = nwep_response_parse(&resp, &msg);
#ifdef NWEP_DEBUG
  fprintf(stderr, "[process_response] response_parse returned %d, status=%.*s\n",
          rv, (int)(resp.status ? 20 : 0), resp.status ? resp.status : "");
#endif
  if (rv != 0) {
    return rv;
  }
  stream->status = resp.status;
  stream->msg.type = NWEP_MSG_RESPONSE;
  memcpy(stream->headers, headers, msg.header_count * sizeof(nwep_header));
  stream->msg.headers = stream->headers;
  stream->msg.header_count = msg.header_count;
  if (conn->callbacks.on_response != NULL) {
    rv = conn->callbacks.on_response(conn, stream, &resp, conn->user_data);
    if (rv != 0) {
      return rv;
    }
  }

  return 0;
}

int nwep_stream_process_data(nwep_stream *stream, const uint8_t *data,
                             size_t data_len) {
  nwep_conn *conn;
  int rv;

  if (stream == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  conn = stream->conn;
  if (conn == NULL) {
    return NWEP_ERR_INTERNAL_INVALID_STATE;
  }

  if (data == NULL || data_len == 0) {
    return 0;
  }
  if (conn->callbacks.on_stream_data != NULL) {
    rv = conn->callbacks.on_stream_data(conn, stream, data, data_len,
                                        conn->user_data);
    if (rv != 0) {
      return rv;
    }
  }

  return 0;
}

int nwep_stream_process_end(nwep_stream *stream) {
  nwep_conn *conn;
  int rv;

  if (stream == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  conn = stream->conn;
  if (conn == NULL) {
    return NWEP_ERR_INTERNAL_INVALID_STATE;
  }

  if (stream->state == NWEP_STREAM_STATE_OPEN) {
    stream->state = NWEP_STREAM_STATE_HALF_CLOSED_REMOTE;
  } else if (stream->state == NWEP_STREAM_STATE_HALF_CLOSED_LOCAL) {
    stream->state = NWEP_STREAM_STATE_CLOSED;
  }
  if (conn->callbacks.on_stream_end != NULL) {
    rv = conn->callbacks.on_stream_end(conn, stream, conn->user_data);
    if (rv != 0) {
      return rv;
    }
  }

  return 0;
}

int nwep_stream_send_response(nwep_stream *stream, const char *status,
                              const char *status_details,
                              const nwep_header *extra_headers,
                              size_t extra_header_count, const uint8_t *body,
                              size_t body_len) {
  nwep_msg msg;
  nwep_header headers[NWEP_MAX_HEADERS];
  size_t hdr_count = 0;
  size_t i;
  uint8_t *encode_buf;
  size_t encode_len;
  nwep_ssize written;

  if (stream == NULL || status == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  nwep_msg_init(&msg, NWEP_MSG_RESPONSE);
  msg.headers = headers;
  nwep_header_set(&headers[hdr_count++], NWEP_HDR_STATUS, status);
  if (status_details != NULL) {
    nwep_header_set(&headers[hdr_count++], NWEP_HDR_STATUS_DETAILS,
                    status_details);
  }
  for (i = 0; i < extra_header_count && hdr_count < NWEP_MAX_HEADERS; i++) {
    headers[hdr_count++] = extra_headers[i];
  }

  msg.header_count = hdr_count;
  msg.body = body;
  msg.body_len = body_len;

  /* Encode message */
  encode_len = nwep_msg_encode_len(&msg);
  if (encode_len == 0) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  encode_buf = (uint8_t *)malloc(encode_len);
  if (encode_buf == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  if (nwep_msg_encode(encode_buf, encode_len, &msg) != encode_len) {
    free(encode_buf);
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }
  written = nwep_stream_write(stream, encode_buf, encode_len);
  free(encode_buf);
  if (written < 0) {
    return (int)written;
  }
  stream->status = status;

  return 0;
}

int nwep_stream_send_request(nwep_stream *stream, const char *method,
                             const char *path,
                             const nwep_header *extra_headers,
                             size_t extra_header_count, const uint8_t *body,
                             size_t body_len) {
  nwep_msg msg;
  nwep_header headers[NWEP_MAX_HEADERS];
  size_t hdr_count = 0;
  size_t i;
  uint8_t request_id[NWEP_REQUEST_ID_LEN];
  uint8_t trace_id[NWEP_TRACE_ID_LEN];
  uint8_t *encode_buf;
  size_t encode_len;
  nwep_ssize written;

  if (stream == NULL || method == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (!nwep_method_is_valid(method)) {
    return NWEP_ERR_PROTO_INVALID_METHOD;
  }
  nwep_msg_init(&msg, NWEP_MSG_REQUEST);
  msg.headers = headers;
  nwep_header_set(&headers[hdr_count++], NWEP_HDR_METHOD, method);
  if (path != NULL) {
    nwep_header_set(&headers[hdr_count++], NWEP_HDR_PATH, path);
  }
  if (nwep_request_id_generate(request_id) == 0) {
    headers[hdr_count].name = (const uint8_t *)NWEP_HDR_REQUEST_ID;
    headers[hdr_count].name_len = strlen(NWEP_HDR_REQUEST_ID);
    headers[hdr_count].value = request_id;
    headers[hdr_count].value_len = NWEP_REQUEST_ID_LEN;
    hdr_count++;
  }
  if (nwep_trace_id_generate(trace_id) == 0) {
    headers[hdr_count].name = (const uint8_t *)NWEP_HDR_TRACE_ID;
    headers[hdr_count].name_len = strlen(NWEP_HDR_TRACE_ID);
    headers[hdr_count].value = trace_id;
    headers[hdr_count].value_len = NWEP_TRACE_ID_LEN;
    hdr_count++;
  }
  for (i = 0; i < extra_header_count && hdr_count < NWEP_MAX_HEADERS; i++) {
    headers[hdr_count++] = extra_headers[i];
  }
  msg.header_count = hdr_count;
  msg.body = body;
  msg.body_len = body_len;
  encode_len = nwep_msg_encode_len(&msg);
  if (encode_len == 0) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  encode_buf = (uint8_t *)malloc(encode_len);
  if (encode_buf == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  if (nwep_msg_encode(encode_buf, encode_len, &msg) != encode_len) {
    free(encode_buf);
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }
  written = nwep_stream_write(stream, encode_buf, encode_len);
  free(encode_buf);
  if (written < 0) {
    return (int)written;
  }
  stream->method = method;
  stream->path = path;

  return 0;
}

int nwep_stream_send_error(nwep_stream *stream, const char *status,
                           const char *details) {
  return nwep_stream_send_response(stream, status, details, NULL, 0, NULL, 0);
}

int nwep_notify_parse(nwep_notify *notify, const nwep_msg *msg) {
  const nwep_header *hdr;

  if (notify == NULL || msg == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(notify, 0, sizeof(*notify));

  if (msg->type != NWEP_MSG_NOTIFY) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  hdr = nwep_msg_find_header(msg, NWEP_HDR_EVENT);
  if (hdr == NULL || hdr->value_len == 0) {
    return NWEP_ERR_PROTO_MISSING_HEADER;
  }
  notify->event = (const char *)hdr->value;

  hdr = nwep_msg_find_header(msg, NWEP_HDR_PATH);
  if (hdr != NULL && hdr->value_len > 0) {
    notify->path = (const char *)hdr->value;
  }

  hdr = nwep_msg_find_header(msg, NWEP_HDR_NOTIFY_ID);
  if (hdr != NULL && hdr->value_len == NWEP_NOTIFY_ID_LEN) {
    memcpy(notify->notify_id, hdr->value, NWEP_NOTIFY_ID_LEN);
    notify->has_notify_id = 1;
  }

  notify->headers = msg->headers;
  notify->header_count = msg->header_count;
  notify->body = msg->body;
  notify->body_len = msg->body_len;

  return 0;
}

int nwep_notify_build(nwep_msg *msg, nwep_header *headers, size_t max_headers,
                      const char *event, const char *path,
                      const uint8_t *notify_id, const uint8_t *body,
                      size_t body_len) {
  size_t hdr_count = 0;

  if (msg == NULL || headers == NULL || event == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (max_headers < 4) {
    return NWEP_ERR_PROTO_TOO_MANY_HEADERS;
  }

  nwep_msg_init(msg, NWEP_MSG_NOTIFY);
  msg->headers = headers;

  nwep_header_set(&headers[hdr_count++], NWEP_HDR_EVENT, event);

  if (path != NULL) {
    nwep_header_set(&headers[hdr_count++], NWEP_HDR_PATH, path);
  }

  if (notify_id != NULL && hdr_count < max_headers) {
    headers[hdr_count].name = (const uint8_t *)NWEP_HDR_NOTIFY_ID;
    headers[hdr_count].name_len = strlen(NWEP_HDR_NOTIFY_ID);
    headers[hdr_count].value = notify_id;
    headers[hdr_count].value_len = NWEP_NOTIFY_ID_LEN;
    hdr_count++;
  }

  if (hdr_count < max_headers) {
    uint8_t trace_id[NWEP_TRACE_ID_LEN];
    if (nwep_trace_id_generate(trace_id) == 0) {
      headers[hdr_count].name = (const uint8_t *)NWEP_HDR_TRACE_ID;
      headers[hdr_count].name_len = strlen(NWEP_HDR_TRACE_ID);
      headers[hdr_count].value = trace_id;
      headers[hdr_count].value_len = NWEP_TRACE_ID_LEN;
      hdr_count++;
    }
  }

  msg->header_count = hdr_count;
  msg->body = body;
  msg->body_len = body_len;

  return 0;
}

int nwep_stream_process_notify(nwep_stream *stream, const uint8_t *data,
                               size_t data_len) {
  nwep_msg msg;
  nwep_header headers[NWEP_MAX_HEADERS];
  nwep_notify notify;
  nwep_conn *conn;
  const nwep_header *trace_hdr;
  int rv;

  if (stream == NULL || data == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  conn = stream->conn;
  if (conn == NULL) {
    return NWEP_ERR_INTERNAL_INVALID_STATE;
  }

  rv = nwep_msg_decode(&msg, data, data_len, headers, NWEP_MAX_HEADERS);
  if (rv != 0) {
    return rv;
  }

  rv = nwep_notify_parse(&notify, &msg);
  if (rv != 0) {
    return rv;
  }

  stream->event = notify.event;
  stream->path = notify.path;
  stream->msg.type = NWEP_MSG_NOTIFY;
  memcpy(stream->headers, headers, msg.header_count * sizeof(nwep_header));
  stream->msg.headers = stream->headers;
  stream->msg.header_count = msg.header_count;

  trace_hdr = nwep_msg_find_header(&msg, NWEP_HDR_TRACE_ID);
  if (trace_hdr != NULL && trace_hdr->value_len == NWEP_TRACE_ID_LEN) {
    memcpy(stream->trace_id, trace_hdr->value, NWEP_TRACE_ID_LEN);
  }

  if (conn->callbacks.on_notify != NULL) {
    rv = conn->callbacks.on_notify(conn, stream, &notify, conn->user_data);
    if (rv != 0) {
      return rv;
    }
  }

  return 0;
}

int nwep_stream_send_notify(nwep_stream *stream, const char *event,
                            const char *path, const uint8_t *notify_id,
                            const nwep_header *extra_headers,
                            size_t extra_header_count, const uint8_t *body,
                            size_t body_len) {
  nwep_msg msg;
  nwep_header headers[NWEP_MAX_HEADERS];
  size_t hdr_count = 0;
  size_t i;
  uint8_t *encode_buf;
  size_t encode_len;
  nwep_ssize written;

  if (stream == NULL || event == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  nwep_msg_init(&msg, NWEP_MSG_NOTIFY);
  msg.headers = headers;

  nwep_header_set(&headers[hdr_count++], NWEP_HDR_EVENT, event);

  if (path != NULL) {
    nwep_header_set(&headers[hdr_count++], NWEP_HDR_PATH, path);
  }

  if (notify_id != NULL) {
    headers[hdr_count].name = (const uint8_t *)NWEP_HDR_NOTIFY_ID;
    headers[hdr_count].name_len = strlen(NWEP_HDR_NOTIFY_ID);
    headers[hdr_count].value = notify_id;
    headers[hdr_count].value_len = NWEP_NOTIFY_ID_LEN;
    hdr_count++;
  }

  for (i = 0; i < extra_header_count && hdr_count < NWEP_MAX_HEADERS; i++) {
    headers[hdr_count++] = extra_headers[i];
  }

  msg.header_count = hdr_count;
  msg.body = body;
  msg.body_len = body_len;

  encode_len = nwep_msg_encode_len(&msg);
  if (encode_len == 0) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  encode_buf = (uint8_t *)malloc(encode_len);
  if (encode_buf == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  if (nwep_msg_encode(encode_buf, encode_len, &msg) != encode_len) {
    free(encode_buf);
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  written = nwep_stream_write(stream, encode_buf, encode_len);
  free(encode_buf);

  if (written < 0) {
    return (int)written;
  }

  stream->event = event;
  stream->path = path;

  return 0;
}

int nwep_heartbeat_build(nwep_msg *msg, nwep_header *headers,
                         size_t max_headers) {
  if (msg == NULL || headers == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }
  if (max_headers < 1) {
    return NWEP_ERR_PROTO_TOO_MANY_HEADERS;
  }
  nwep_msg_init(msg, NWEP_MSG_REQUEST);
  msg->headers = headers;
  nwep_header_set(&headers[0], NWEP_HDR_METHOD, NWEP_METHOD_HEARTBEAT);
  msg->header_count = 1;

  return 0;
}

int nwep_heartbeat_response_build(nwep_msg *msg, nwep_header *headers,
                                  size_t max_headers) {
  if (msg == NULL || headers == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }
  if (max_headers < 1) {
    return NWEP_ERR_PROTO_TOO_MANY_HEADERS;
  }
  nwep_msg_init(msg, NWEP_MSG_RESPONSE);
  msg->headers = headers;
  nwep_header_set(&headers[0], NWEP_HDR_STATUS, NWEP_STATUS_OK);
  msg->header_count = 1;

  return 0;
}
