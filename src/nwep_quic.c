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

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <stdlib.h>
#include <string.h>

/*
 * QUIC version to use (v1)
 */
#define NWEP_QUIC_VERSION NGTCP2_PROTO_VER_V1

/*
 * Maximum UDP payload size
 */
#define NWEP_MAX_UDP_PAYLOAD_SIZE 1200

/*
 * Connection ID length
 */
#define NWEP_CID_LEN 16

/*
 * ngtcp2 callback: Generate random data
 */
static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  (void)rand_ctx;
  RAND_bytes(dest, (int)destlen);
}

/*
 * ngtcp2 callback: Generate new connection ID
 */
static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data) {
  nwep_conn *nconn = (nwep_conn *)user_data;
  (void)conn;

  if (RAND_bytes(cid->data, (int)cidlen) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  cid->datalen = cidlen;

  if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  /* Track this CID for server-side routing */
  if (nconn != NULL && nconn->scid_count < 8) {
    nconn->scids[nconn->scid_count++] = *cid;
#ifdef NWEP_DEBUG
    fprintf(stderr, "[get_new_cid] Added scid %zu: %02x%02x...\n",
            nconn->scid_count - 1, cid->data[0], cid->data[1]);
#endif
  }

  return 0;
}

/*
 * ngtcp2 callback: Handshake completed
 */
static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
  nwep_conn *nconn = (nwep_conn *)user_data;
  (void)conn;

  nconn->state = NWEP_CONN_STATE_CONNECTED;

  /* Call user's on_connect callback */
  if (nconn->callbacks.on_connect != NULL) {
    /* For now, pass NULL for peer identity - WEB/1 handshake not implemented yet */
    return nconn->callbacks.on_connect(nconn, NULL, nconn->user_data);
  }

  return 0;
}

/*
 * ngtcp2 callback: Receive stream data
 */
static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
                               int64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data, void *stream_user_data) {
  nwep_conn *nconn = (nwep_conn *)user_data;
  nwep_stream *stream = (nwep_stream *)stream_user_data;
  int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;

  (void)conn;
  (void)offset;

  if (stream == NULL) {
    stream = nwep_stream_find(nconn, stream_id);
#ifdef NWEP_DEBUG
    fprintf(stderr, "[recv_stream_data] stream_id=%ld, found=%p, is_server=%d\n",
            (long)stream_id, (void *)stream, nconn->is_server);
#endif
    if (stream == NULL) {
      stream = nwep_stream_new(nconn, stream_id);
      if (stream == NULL) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }
      stream->is_server_initiated = ((stream_id % 4) == 1);
      stream->state = NWEP_STREAM_STATE_OPEN;
      nwep_conn_add_stream(nconn, stream);
    }
  }

  if (datalen > 0) {
    int rv = 0;
    uint8_t msg_type;

    /*
     * Route first incoming message by type (offset 4 in wire format).
     * Check recv_len == 0 to determine if this is the first received data.
     * Note: stream->msg.type represents what WE sent, not what we're receiving.
     */
    if (datalen >= 5 && stream->recv_len == 0) {
      msg_type = data[4];

#ifdef NWEP_DEBUG
      fprintf(stderr,
              "[recv_stream_data] routing msg_type=%d, datalen=%zu, "
              "stream->msg.type=%d\n",
              msg_type, datalen, stream->msg.type);
#endif

      switch (msg_type) {
      case NWEP_MSG_NOTIFY:
        rv = nwep_stream_process_notify(stream, data, datalen);
        break;
      case NWEP_MSG_REQUEST:
        rv = nwep_stream_process_request(stream, data, datalen, 0);
        break;
      case NWEP_MSG_RESPONSE:
        rv = nwep_stream_process_response(stream, data, datalen);
        break;
      case NWEP_MSG_STREAM:
      default:
        rv = nwep_stream_process_data(stream, data, datalen);
        break;
      }
    } else {
#ifdef NWEP_DEBUG
      fprintf(stderr,
              "[recv_stream_data] fallback to process_data, datalen=%zu, "
              "recv_len=%zu\n",
              datalen, stream->recv_len);
#endif
      rv = nwep_stream_process_data(stream, data, datalen);
    }

#ifdef NWEP_DEBUG
    if (rv != 0) {
      fprintf(stderr, "[recv_stream_data] processing returned error %d\n", rv);
    }
#endif

    if (rv != 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
  }

  if (fin) {
    nwep_stream_process_end(stream);
  }

  return 0;
}

/*
 * ngtcp2 callback: Stream opened
 */
static int stream_open_cb(ngtcp2_conn *conn, int64_t stream_id,
                          void *user_data) {
  nwep_conn *nconn = (nwep_conn *)user_data;
  nwep_stream *stream;

  (void)conn;

  stream = nwep_stream_new(nconn, stream_id);
  if (stream == NULL) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  /* Server-initiated streams have ID % 4 == 1 */
  stream->is_server_initiated = ((stream_id % 4) == 1);
  stream->state = NWEP_STREAM_STATE_OPEN;

  nwep_conn_add_stream(nconn, stream);

  /* Set stream user data in ngtcp2 */
  ngtcp2_conn_set_stream_user_data(conn, stream_id, stream);

  return 0;
}

/*
 * ngtcp2 callback: Stream closed
 */
static int stream_close_cb(ngtcp2_conn *conn, uint32_t flags,
                           int64_t stream_id, uint64_t app_error_code,
                           void *user_data, void *stream_user_data) {
  nwep_conn *nconn = (nwep_conn *)user_data;
  nwep_stream *stream = (nwep_stream *)stream_user_data;

  (void)conn;
  (void)flags;
  (void)stream_id;
  (void)app_error_code;

  if (stream != NULL) {
    stream->state = NWEP_STREAM_STATE_CLOSED;
    /* Remove stream from connection */
    nwep_stream_remove(nconn, stream);
    nwep_stream_free(stream);
  }

  return 0;
}

/*
 * ngtcp2 callback: Acknowledge stream data offset
 */
static int acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
                                       uint64_t offset, uint64_t datalen,
                                       void *user_data,
                                       void *stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)offset;
  (void)datalen;
  (void)user_data;
  (void)stream_user_data;

  /* Could be used to free acknowledged data buffers */
  return 0;
}

/*
 * Initialize ngtcp2 callbacks for nwep
 */
static void init_callbacks(ngtcp2_callbacks *callbacks, int is_server) {
  memset(callbacks, 0, sizeof(*callbacks));

  /* Crypto callbacks (from nwep_tls.c) */
  nwep_tls_set_callbacks(callbacks);

  /* Required callbacks */
  callbacks->rand = rand_cb;
  callbacks->get_new_connection_id = get_new_connection_id_cb;

  /* Connection callbacks */
  callbacks->handshake_completed = handshake_completed_cb;

  /* Stream callbacks */
  callbacks->recv_stream_data = recv_stream_data_cb;
  callbacks->stream_open = stream_open_cb;
  callbacks->stream_close = stream_close_cb;
  callbacks->acked_stream_data_offset = acked_stream_data_offset_cb;

  (void)is_server;
}

/*
 * Initialize ngtcp2 settings for nwep
 */
static void init_settings(ngtcp2_settings *settings,
                          const nwep_settings *nwep_settings,
                          ngtcp2_tstamp initial_ts) {
  ngtcp2_settings_default(settings);

  settings->initial_ts = initial_ts;
  settings->max_tx_udp_payload_size = NWEP_MAX_UDP_PAYLOAD_SIZE;

  /* Use nwep settings for timeouts */
  if (nwep_settings->timeout_ms > 0) {
    settings->handshake_timeout =
        (ngtcp2_duration)nwep_settings->timeout_ms * NGTCP2_MILLISECONDS;
  }
}

/*
 * Initialize ngtcp2 transport parameters for nwep
 */
static void init_transport_params(ngtcp2_transport_params *params,
                                  const nwep_settings *nwep_settings) {
  ngtcp2_transport_params_default(params);

  /* Max streams */
  params->initial_max_streams_bidi = nwep_settings->max_streams;
  params->initial_max_streams_uni = nwep_settings->max_streams;

  /* Max data per stream and connection */
  params->initial_max_stream_data_bidi_local = 256 * 1024;
  params->initial_max_stream_data_bidi_remote = 256 * 1024;
  params->initial_max_stream_data_uni = 256 * 1024;
  params->initial_max_data = nwep_settings->max_message_size;

  /* Active connection ID limit */
  params->active_connection_id_limit = 4;
}

/*
 * Generate random connection ID
 */
static int generate_cid(ngtcp2_cid *cid, size_t len) {
  if (len > NGTCP2_MAX_CIDLEN) {
    len = NGTCP2_MAX_CIDLEN;
  }

  if (RAND_bytes(cid->data, (int)len) != 1) {
    return NWEP_ERR_CRYPTO_KEY_GEN_FAILED;
  }
  cid->datalen = len;
  return 0;
}

/*
 * Create ngtcp2 connection for client
 */
int nwep_quic_client_init(nwep_conn *conn, const struct sockaddr *remote_addr,
                          size_t remote_addrlen,
                          const struct sockaddr *local_addr,
                          size_t local_addrlen, ngtcp2_tstamp ts) {
  ngtcp2_callbacks callbacks;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_cid dcid, scid;
  ngtcp2_path path;
  SSL_CTX *ssl_ctx;
  int rv;

  if (conn == NULL || remote_addr == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Get SSL_CTX from client's TLS context */
  ssl_ctx = nwep_tls_ctx_get_ssl_ctx(conn->parent.client->tls_ctx);
  if (ssl_ctx == NULL) {
    return NWEP_ERR_NETWORK_TLS;
  }

  /* Generate connection IDs */
  rv = generate_cid(&dcid, NWEP_CID_LEN);
  if (rv != 0) {
    return rv;
  }

  rv = generate_cid(&scid, NWEP_CID_LEN);
  if (rv != 0) {
    return rv;
  }

  /* Set up path */
  path.local.addrlen = local_addrlen;
  path.local.addr = (struct sockaddr *)local_addr;
  path.remote.addrlen = remote_addrlen;
  path.remote.addr = (struct sockaddr *)remote_addr;

  /* Initialize callbacks, settings, params */
  init_callbacks(&callbacks, 0);
  init_settings(&settings, &conn->parent.client->settings, ts);
  init_transport_params(&params, &conn->parent.client->settings);

  /* Create SSL session */
  conn->ssl = SSL_new(ssl_ctx);
  if (conn->ssl == NULL) {
    return NWEP_ERR_NETWORK_TLS;
  }

  SSL_set_app_data(conn->ssl, &conn->conn_ref);
  SSL_set_connect_state(conn->ssl);

  /* Set up conn_ref for ngtcp2 crypto */
  nwep_tls_conn_ref_init(&conn->conn_ref, conn);

  /* Create ngtcp2 client connection */
  rv = ngtcp2_conn_client_new(&conn->qconn, &dcid, &scid, &path,
                              NWEP_QUIC_VERSION, &callbacks, &settings, &params,
                              NULL, conn);
  if (rv != 0) {
    SSL_free(conn->ssl);
    conn->ssl = NULL;
    return NWEP_ERR_NETWORK_CONN_FAILED;
  }

  /* Set TLS native handle */
  ngtcp2_conn_set_tls_native_handle(conn->qconn, conn->ssl);

  /* Store path info */
  memcpy(&conn->path.local_addr, local_addr, local_addrlen);
  conn->path.local_addrlen = local_addrlen;
  memcpy(&conn->path.remote_addr, remote_addr, remote_addrlen);
  conn->path.remote_addrlen = remote_addrlen;

  conn->state = NWEP_CONN_STATE_HANDSHAKING;

  return 0;
}

/*
 * Create ngtcp2 connection for server (from initial packet)
 */
int nwep_quic_server_init(nwep_conn *conn, const ngtcp2_pkt_hd *hd,
                          const struct sockaddr *remote_addr,
                          size_t remote_addrlen,
                          const struct sockaddr *local_addr,
                          size_t local_addrlen, ngtcp2_tstamp ts) {
  ngtcp2_callbacks callbacks;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_cid scid;
  ngtcp2_path path;
  SSL_CTX *ssl_ctx;
  int rv;

  if (conn == NULL || hd == NULL || remote_addr == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Get SSL_CTX from server's TLS context */
  ssl_ctx = nwep_tls_ctx_get_ssl_ctx(conn->parent.server->tls_ctx);
  if (ssl_ctx == NULL) {
    return NWEP_ERR_NETWORK_TLS;
  }

  /* Generate server connection ID */
  rv = generate_cid(&scid, NWEP_CID_LEN);
  if (rv != 0) {
    return rv;
  }

  /* Track the original SCID for connection routing */
  conn->scids[0] = scid;
  conn->scid_count = 1;
#ifdef NWEP_DEBUG
  fprintf(stderr, "[server_init] Original scid: %02x%02x...\n",
          scid.data[0], scid.data[1]);
#endif

  /* Set up path */
  path.local.addrlen = local_addrlen;
  path.local.addr = (struct sockaddr *)local_addr;
  path.remote.addrlen = remote_addrlen;
  path.remote.addr = (struct sockaddr *)remote_addr;

  /* Initialize callbacks, settings, params */
  init_callbacks(&callbacks, 1);
  init_settings(&settings, &conn->parent.server->settings, ts);
  init_transport_params(&params, &conn->parent.server->settings);

  /* Server must set original_dcid from Initial packet */
  params.original_dcid = hd->dcid;
  params.original_dcid_present = 1;

  /* Set token if present */
  settings.token = hd->token;
  settings.tokenlen = hd->tokenlen;

  /* Create SSL session */
  conn->ssl = SSL_new(ssl_ctx);
  if (conn->ssl == NULL) {
    return NWEP_ERR_NETWORK_TLS;
  }

  SSL_set_app_data(conn->ssl, &conn->conn_ref);
  SSL_set_accept_state(conn->ssl);

  /* Set up conn_ref for ngtcp2 crypto */
  nwep_tls_conn_ref_init(&conn->conn_ref, conn);

  /* Create ngtcp2 server connection */
  rv = ngtcp2_conn_server_new(&conn->qconn, &hd->scid, &scid, &path,
                              hd->version, &callbacks, &settings, &params, NULL,
                              conn);
  if (rv != 0) {
    SSL_free(conn->ssl);
    conn->ssl = NULL;
    return NWEP_ERR_NETWORK_CONN_FAILED;
  }

  /* Set TLS native handle */
  ngtcp2_conn_set_tls_native_handle(conn->qconn, conn->ssl);

  /* Store path info */
  memcpy(&conn->path.local_addr, local_addr, local_addrlen);
  conn->path.local_addrlen = local_addrlen;
  memcpy(&conn->path.remote_addr, remote_addr, remote_addrlen);
  conn->path.remote_addrlen = remote_addrlen;

  conn->state = NWEP_CONN_STATE_HANDSHAKING;

  return 0;
}

/*
 * Process incoming QUIC packet
 */
int nwep_quic_read(nwep_conn *conn, const uint8_t *data, size_t datalen,
                   const struct sockaddr *remote_addr, size_t remote_addrlen,
                   const struct sockaddr *local_addr, size_t local_addrlen,
                   ngtcp2_tstamp ts) {
  ngtcp2_path path;
  ngtcp2_pkt_info pi;
  int rv;

  if (conn == NULL || conn->qconn == NULL || data == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Set up path */
  path.local.addrlen = local_addrlen;
  path.local.addr = (struct sockaddr *)local_addr;
  path.remote.addrlen = remote_addrlen;
  path.remote.addr = (struct sockaddr *)remote_addr;

  memset(&pi, 0, sizeof(pi));

  rv = ngtcp2_conn_read_pkt(conn->qconn, &path, &pi, data, datalen, ts);

  if (rv != 0) {
#ifdef NWEP_DEBUG
    fprintf(stderr, "[nwep_quic_read] error: %s\n", ngtcp2_strerror(rv));
#endif
    /* Map ngtcp2 errors to nwep errors */
    if (rv == NGTCP2_ERR_DRAINING) {
      conn->state = NWEP_CONN_STATE_CLOSING;
      return 0;
    }
    if (rv == NGTCP2_ERR_DROP_CONN) {
      conn->state = NWEP_CONN_STATE_CLOSED;
      return NWEP_ERR_NETWORK_CONN_CLOSED;
    }
    return NWEP_ERR_NETWORK_CONN_FAILED;
  }

  return 0;
}

/*
 * Write outgoing QUIC packet
 */
nwep_ssize nwep_quic_write(nwep_conn *conn, uint8_t *data, size_t datalen,
                           ngtcp2_tstamp ts) {
  ngtcp2_path_storage ps;
  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite;
  ngtcp2_ssize ndatalen;
  nwep_stream *stream;

  if (conn == NULL || conn->qconn == NULL || data == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  ngtcp2_path_storage_zero(&ps);

  /* Check for streams with pending send data */
  for (stream = conn->streams; stream != NULL; stream = stream->next) {
    if (stream->send_len > stream->send_offset) {
      /* This stream has data to send */
      const uint8_t *stream_data = stream->send_buf + stream->send_offset;
      size_t stream_datalen = stream->send_len - stream->send_offset;
      int fin = (stream->state == NWEP_STREAM_STATE_HALF_CLOSED_LOCAL ||
                 stream->state == NWEP_STREAM_STATE_CLOSED);
      uint32_t flags = fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0;

      nwrite = ngtcp2_conn_write_stream(conn->qconn, &ps.path, &pi, data,
                                        datalen, &ndatalen, flags, stream->id,
                                        stream_data, stream_datalen, ts);

#ifdef NWEP_DEBUG
      fprintf(stderr,
              "[nwep_quic_write] ngtcp2_conn_write_stream(stream=%ld, "
              "datalen=%zu, fin=%d) returned nwrite=%ld, ndatalen=%ld\n",
              (long)stream->id, stream_datalen, fin, (long)nwrite,
              (long)ndatalen);
#endif

      if (nwrite < 0) {
        if (nwrite == NGTCP2_ERR_WRITE_MORE) {
          /* This shouldn't happen without MORE flag, but handle it */
          if (ndatalen > 0) {
            stream->send_offset += (size_t)ndatalen;
          }
          continue;
        }
        if (nwrite == NGTCP2_ERR_STREAM_NOT_FOUND ||
            nwrite == NGTCP2_ERR_STREAM_SHUT_WR) {
          /* Stream closed, skip it */
          continue;
        }
#ifdef NWEP_DEBUG
        fprintf(stderr, "[nwep_quic_write] error: %s\n",
                ngtcp2_strerror((int)nwrite));
#endif
        return NWEP_ERR_NETWORK_CONN_FAILED;
      }

      /* Update send offset based on how much stream data was accepted */
      if (ndatalen > 0) {
        stream->send_offset += (size_t)ndatalen;
      }

      /* Update path if changed */
      if (nwrite > 0 && ps.path.local.addrlen > 0) {
        memcpy(&conn->path.local_addr, ps.path.local.addr,
               ps.path.local.addrlen);
        conn->path.local_addrlen = ps.path.local.addrlen;
        memcpy(&conn->path.remote_addr, ps.path.remote.addr,
               ps.path.remote.addrlen);
        conn->path.remote_addrlen = ps.path.remote.addrlen;
      }

      /* Packet complete, return it */
      if (nwrite > 0) {
        return (nwep_ssize)nwrite;
      }
    }
  }

  /* No stream data to send, write connection-level data (handshake, acks, etc.) */
  nwrite = ngtcp2_conn_write_pkt(conn->qconn, &ps.path, &pi, data, datalen, ts);

#ifdef NWEP_DEBUG
  fprintf(stderr, "[nwep_quic_write] ngtcp2_conn_write_pkt returned %ld\n",
          (long)nwrite);
#endif

  if (nwrite < 0) {
    if (nwrite == NGTCP2_ERR_WRITE_MORE) {
      /* More data available, but buffer full */
      return 0;
    }
#ifdef NWEP_DEBUG
    fprintf(stderr, "[nwep_quic_write] error: %s\n",
            ngtcp2_strerror((int)nwrite));
#endif
    return NWEP_ERR_NETWORK_CONN_FAILED;
  }

  /* Update path if changed */
  if (nwrite > 0 && ps.path.local.addrlen > 0) {
    memcpy(&conn->path.local_addr, ps.path.local.addr, ps.path.local.addrlen);
    conn->path.local_addrlen = ps.path.local.addrlen;
    memcpy(&conn->path.remote_addr, ps.path.remote.addr,
           ps.path.remote.addrlen);
    conn->path.remote_addrlen = ps.path.remote.addrlen;
  }

  return (nwep_ssize)nwrite;
}

/*
 * Write stream data
 */
nwep_ssize nwep_quic_write_stream(nwep_conn *conn, int64_t stream_id,
                                  const uint8_t *data, size_t datalen, int fin,
                                  uint8_t *buf, size_t buflen,
                                  ngtcp2_tstamp ts) {
  ngtcp2_path_storage ps;
  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite;
  ngtcp2_ssize ndatalen;
  uint32_t flags = 0;

  if (conn == NULL || conn->qconn == NULL || buf == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (fin) {
    flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
  }

  ngtcp2_path_storage_zero(&ps);

  nwrite = ngtcp2_conn_write_stream(conn->qconn, &ps.path, &pi, buf, buflen,
                                    &ndatalen, flags, stream_id, data, datalen,
                                    ts);

  if (nwrite < 0) {
    if (nwrite == NGTCP2_ERR_WRITE_MORE) {
      return 0;
    }
    if (nwrite == NGTCP2_ERR_STREAM_NOT_FOUND) {
      return NWEP_ERR_PROTO_STREAM_ERROR;
    }
    return NWEP_ERR_NETWORK_CONN_FAILED;
  }

  return (nwep_ssize)nwrite;
}

/*
 * Open a new bidirectional stream
 */
int nwep_quic_open_stream(nwep_conn *conn, int64_t *pstream_id) {
  int rv;

  if (conn == NULL || conn->qconn == NULL || pstream_id == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  rv = ngtcp2_conn_open_bidi_stream(conn->qconn, pstream_id, NULL);
  if (rv != 0) {
    if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
      return NWEP_ERR_NETWORK_QUIC;
    }
    return NWEP_ERR_NETWORK_CONN_FAILED;
  }

  return 0;
}

/*
 * Shutdown stream
 */
int nwep_quic_shutdown_stream(nwep_conn *conn, int64_t stream_id,
                              uint64_t app_error_code) {
  int rv;

  if (conn == NULL || conn->qconn == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  rv = ngtcp2_conn_shutdown_stream(conn->qconn, 0, stream_id, app_error_code);
  if (rv != 0 && rv != NGTCP2_ERR_STREAM_NOT_FOUND) {
    return NWEP_ERR_NETWORK_CONN_FAILED;
  }

  return 0;
}

/*
 * Handle connection timeout
 */
int nwep_quic_handle_expiry(nwep_conn *conn, ngtcp2_tstamp ts) {
  int rv;

  if (conn == NULL || conn->qconn == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  rv = ngtcp2_conn_handle_expiry(conn->qconn, ts);
  if (rv != 0) {
    if (rv == NGTCP2_ERR_IDLE_CLOSE) {
      conn->state = NWEP_CONN_STATE_CLOSED;
      return NWEP_ERR_NETWORK_TIMEOUT;
    }
    return NWEP_ERR_NETWORK_CONN_FAILED;
  }

  return 0;
}

/*
 * Get connection expiry time
 */
ngtcp2_tstamp nwep_quic_get_expiry(const nwep_conn *conn) {
  if (conn == NULL || conn->qconn == NULL) {
    return UINT64_MAX;
  }

  return ngtcp2_conn_get_expiry(conn->qconn);
}

/*
 * Close connection
 */
nwep_ssize nwep_quic_close(nwep_conn *conn, uint8_t *buf, size_t buflen,
                           uint64_t app_error_code, ngtcp2_tstamp ts) {
  ngtcp2_path_storage ps;
  ngtcp2_pkt_info pi;
  ngtcp2_ccerr ccerr;
  ngtcp2_ssize nwrite;

  if (conn == NULL || conn->qconn == NULL || buf == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  ngtcp2_path_storage_zero(&ps);

  /* Set up connection close error */
  ngtcp2_ccerr_set_application_error(&ccerr, app_error_code, NULL, 0);

  nwrite = ngtcp2_conn_write_connection_close(conn->qconn, &ps.path, &pi, buf,
                                              buflen, &ccerr, ts);

  if (nwrite < 0) {
    return NWEP_ERR_NETWORK_CONN_FAILED;
  }

  conn->state = NWEP_CONN_STATE_CLOSING;

  return (nwep_ssize)nwrite;
}

/*
 * Check if connection is in draining state
 */
int nwep_quic_is_draining(const nwep_conn *conn) {
  if (conn == NULL || conn->qconn == NULL) {
    return 0;
  }

  return ngtcp2_conn_in_draining_period(conn->qconn);
}

/*
 * Check if connection handshake is complete
 */
int nwep_quic_handshake_completed(const nwep_conn *conn) {
  if (conn == NULL || conn->qconn == NULL) {
    return 0;
  }

  return ngtcp2_conn_get_handshake_completed(conn->qconn);
}

/*
 * Free QUIC connection resources
 */
void nwep_quic_free(nwep_conn *conn) {
  if (conn == NULL) {
    return;
  }

  if (conn->qconn != NULL) {
    ngtcp2_conn_del(conn->qconn);
    conn->qconn = NULL;
  }

  if (conn->ssl != NULL) {
    SSL_free(conn->ssl);
    conn->ssl = NULL;
  }
}
