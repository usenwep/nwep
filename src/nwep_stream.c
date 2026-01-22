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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "nwep_internal.h"

#include <stdlib.h>
#include <string.h>

#define INITIAL_BUF_SIZE 4096

/*
 * Stream management implementation
 */

nwep_stream *nwep_stream_new(nwep_conn *conn, int64_t id) {
  nwep_stream *stream;

  if (conn == NULL) {
    return NULL;
  }

  stream = (nwep_stream *)calloc(1, sizeof(*stream));
  if (stream == NULL) {
    return NULL;
  }

  stream->id = id;
  stream->conn = conn;
  stream->state = NWEP_STREAM_STATE_IDLE;

  /* Initialize message structure */
  stream->msg.headers = stream->headers;
  stream->msg.header_count = 0;

  return stream;
}

void nwep_stream_free(nwep_stream *stream) {
  if (stream == NULL) {
    return;
  }

  /* Free buffers */
  free(stream->recv_buf);
  free(stream->send_buf);

  free(stream);
}

nwep_stream *nwep_conn_find_stream(nwep_conn *conn, int64_t id) {
  nwep_stream *stream;

  if (conn == NULL) {
    return NULL;
  }

  for (stream = conn->streams; stream != NULL; stream = stream->next) {
    if (stream->id == id) {
      return stream;
    }
  }

  return NULL;
}

int nwep_conn_add_stream(nwep_conn *conn, nwep_stream *stream) {
  if (conn == NULL || stream == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Add to head of list */
  stream->next = conn->streams;
  conn->streams = stream;

  return 0;
}

void nwep_conn_remove_stream(nwep_conn *conn, nwep_stream *stream) {
  nwep_stream **pp;

  if (conn == NULL || stream == NULL) {
    return;
  }

  for (pp = &conn->streams; *pp != NULL; pp = &(*pp)->next) {
    if (*pp == stream) {
      *pp = stream->next;
      stream->next = NULL;
      return;
    }
  }
}

/*
 * Public stream API
 */

int nwep_stream_request(nwep_conn *conn, const nwep_request *req,
                        nwep_stream **pstream) {
  nwep_stream *stream;
  int64_t stream_id;
  int rv;

  if (conn == NULL || req == NULL || pstream == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (conn->state != NWEP_CONN_STATE_CONNECTED) {
    return NWEP_ERR_INTERNAL_INVALID_STATE;
  }

  /* Open a real QUIC stream */
  rv = nwep_quic_open_stream(conn, &stream_id);
  if (rv != 0) {
    return rv;
  }

  stream = nwep_stream_new(conn, stream_id);
  if (stream == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  stream->state = NWEP_STREAM_STATE_OPEN;

  /* Store request info */
  stream->msg.type = NWEP_MSG_REQUEST;
  stream->method = req->method;
  stream->path = req->path;

  /* Copy headers */
  if (req->headers != NULL && req->header_count > 0) {
    size_t count = req->header_count;
    if (count > NWEP_MAX_HEADERS) {
      count = NWEP_MAX_HEADERS;
    }
    memcpy(stream->headers, req->headers, count * sizeof(nwep_header));
    stream->msg.header_count = count;
  }

  /* Add to connection */
  if (nwep_conn_add_stream(conn, stream) != 0) {
    nwep_stream_free(stream);
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  /* Encode and buffer request for sending */
  rv = nwep_stream_send_request(stream, req->method, req->path, req->headers,
                                req->header_count, req->body, req->body_len);
  if (rv != 0) {
    nwep_conn_remove_stream(conn, stream);
    nwep_stream_free(stream);
    return rv;
  }

  *pstream = stream;
  return 0;
}

int nwep_stream_respond(nwep_stream *stream, const nwep_response *resp) {
  int rv;

  if (stream == NULL || resp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (stream->state != NWEP_STREAM_STATE_OPEN &&
      stream->state != NWEP_STREAM_STATE_HALF_CLOSED_REMOTE) {
    return NWEP_ERR_INTERNAL_INVALID_STATE;
  }

  /* Store response info */
  stream->msg.type = NWEP_MSG_RESPONSE;
  stream->status = resp->status;

  /* Copy headers */
  if (resp->headers != NULL && resp->header_count > 0) {
    size_t count = resp->header_count;
    if (count > NWEP_MAX_HEADERS) {
      count = NWEP_MAX_HEADERS;
    }
    memcpy(stream->headers, resp->headers, count * sizeof(nwep_header));
    stream->msg.header_count = count;
  }

  /* Encode and buffer response for sending */
  rv = nwep_stream_send_response(stream, resp->status, resp->status_details,
                                 resp->headers, resp->header_count, resp->body,
                                 resp->body_len);
  if (rv != 0) {
    return rv;
  }

  return 0;
}

nwep_ssize nwep_stream_write(nwep_stream *stream, const uint8_t *data,
                             size_t datalen) {
  uint8_t *new_buf;
  size_t new_cap;

  if (stream == NULL || data == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (stream->state != NWEP_STREAM_STATE_OPEN &&
      stream->state != NWEP_STREAM_STATE_HALF_CLOSED_REMOTE) {
    return NWEP_ERR_INTERNAL_INVALID_STATE;
  }

  /* Grow send buffer if needed */
  if (stream->send_len + datalen > stream->send_cap) {
    new_cap = stream->send_cap == 0 ? INITIAL_BUF_SIZE : stream->send_cap * 2;
    while (new_cap < stream->send_len + datalen) {
      new_cap *= 2;
    }

    new_buf = (uint8_t *)realloc(stream->send_buf, new_cap);
    if (new_buf == NULL) {
      return NWEP_ERR_INTERNAL_NOMEM;
    }

    stream->send_buf = new_buf;
    stream->send_cap = new_cap;
  }

  /* Copy data to send buffer */
  memcpy(stream->send_buf + stream->send_len, data, datalen);
  stream->send_len += datalen;

  /*
   * Note: Data is buffered here. The caller retrieves it via
   * nwep_server_write() or nwep_client_write() which internally
   * calls ngtcp2_conn_write_stream() to send on the QUIC stream.
   */

  return (nwep_ssize)datalen;
}

int nwep_stream_end(nwep_stream *stream) {
  if (stream == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (stream->state == NWEP_STREAM_STATE_OPEN) {
    stream->state = NWEP_STREAM_STATE_HALF_CLOSED_LOCAL;
  } else if (stream->state == NWEP_STREAM_STATE_HALF_CLOSED_REMOTE) {
    stream->state = NWEP_STREAM_STATE_CLOSED;
  } else {
    return NWEP_ERR_INTERNAL_INVALID_STATE;
  }

  /*
   * Note: Stream state is updated. The FIN flag is sent when
   * nwep_*_write() calls ngtcp2_conn_write_stream() with fin=1.
   */

  return 0;
}

void nwep_stream_close(nwep_stream *stream, int error) {
  if (stream == NULL) {
    return;
  }

  stream->state = NWEP_STREAM_STATE_CLOSED;

  /*
   * Note: Stream state is updated. RESET_STREAM would be sent via
   * ngtcp2_conn_shutdown_stream() with the application error code.
   */

  (void)error;
}

int64_t nwep_stream_get_id(const nwep_stream *stream) {
  if (stream == NULL) {
    return -1;
  }
  return stream->id;
}

void *nwep_stream_get_user_data(const nwep_stream *stream) {
  if (stream == NULL) {
    return NULL;
  }
  return stream->user_data;
}

void nwep_stream_set_user_data(nwep_stream *stream, void *user_data) {
  if (stream == NULL) {
    return;
  }
  stream->user_data = user_data;
}

nwep_conn *nwep_stream_get_conn(const nwep_stream *stream) {
  if (stream == NULL) {
    return NULL;
  }
  return stream->conn;
}

int nwep_stream_is_server_initiated(const nwep_stream *stream) {
  if (stream == NULL) {
    return 0;
  }
  return stream->is_server_initiated;
}

int nwep_conn_notify(nwep_conn *conn, const nwep_notify *notify,
                     nwep_stream **pstream) {
  nwep_stream *stream;
  int64_t stream_id;
  int rv;

  if (conn == NULL || notify == NULL || pstream == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (!conn->is_server) {
    return NWEP_ERR_INTERNAL_INVALID_STATE;
  }

  if (conn->state != NWEP_CONN_STATE_CONNECTED) {
    return NWEP_ERR_INTERNAL_INVALID_STATE;
  }

  rv = nwep_quic_open_stream(conn, &stream_id);
  if (rv != 0) {
    return rv;
  }

  stream = nwep_stream_new(conn, stream_id);
  if (stream == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  stream->state = NWEP_STREAM_STATE_OPEN;
  stream->is_server_initiated = 1;
  stream->msg.type = NWEP_MSG_NOTIFY;
  stream->event = notify->event;
  stream->path = notify->path;

  if (nwep_conn_add_stream(conn, stream) != 0) {
    nwep_stream_free(stream);
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  rv = nwep_stream_send_notify(stream, notify->event, notify->path,
                               notify->has_notify_id ? notify->notify_id : NULL,
                               notify->headers, notify->header_count,
                               notify->body, notify->body_len);
  if (rv != 0) {
    nwep_conn_remove_stream(conn, stream);
    nwep_stream_free(stream);
    return rv;
  }

  *pstream = stream;
  return 0;
}

/*
 * Aliases for consistency with internal header declarations
 */

nwep_stream *nwep_stream_find(nwep_conn *conn, int64_t stream_id) {
  return nwep_conn_find_stream(conn, stream_id);
}

void nwep_stream_remove(nwep_conn *conn, nwep_stream *stream) {
  nwep_conn_remove_stream(conn, stream);
}
