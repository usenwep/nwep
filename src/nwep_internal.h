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
#ifndef NWEP_INTERNAL_H
#define NWEP_INTERNAL_H

#include <nwep/nwep.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>

#include <openssl/ssl.h>

/* Forward declaration for TLS context */
typedef struct nwep_tls_ctx nwep_tls_ctx;

/*
 * Connection states
 */
typedef enum nwep_conn_state {
  NWEP_CONN_STATE_INITIAL = 0,
  NWEP_CONN_STATE_HANDSHAKING = 1,
  NWEP_CONN_STATE_CONNECTED = 2,
  NWEP_CONN_STATE_CLOSING = 3,
  NWEP_CONN_STATE_CLOSED = 4
} nwep_conn_state;

/*
 * Stream states
 */
typedef enum nwep_stream_state {
  NWEP_STREAM_STATE_IDLE = 0,
  NWEP_STREAM_STATE_OPEN = 1,
  NWEP_STREAM_STATE_HALF_CLOSED_LOCAL = 2,
  NWEP_STREAM_STATE_HALF_CLOSED_REMOTE = 3,
  NWEP_STREAM_STATE_CLOSED = 4
} nwep_stream_state;

/*
 * Internal stream structure
 */
struct nwep_stream {
  int64_t id;
  nwep_stream_state state;
  nwep_conn *conn;
  void *user_data;

  int is_server_initiated;
  int is_handshake_stream;

  uint8_t trace_id[NWEP_TRACE_ID_LEN];

  const char *method;
  const char *path;
  const char *event;
  const char *status;

  /* Wire message parsing state */
  nwep_msg msg;
  nwep_header headers[NWEP_MAX_HEADERS];

  /* Receive buffer */
  uint8_t *recv_buf;
  size_t recv_len;    /* Amount of data in buffer */
  size_t recv_cap;
  size_t recv_offset; /* Stream offset of recv_buf[0] - tracks consumed data */

  /* Send buffer */
  uint8_t *send_buf;
  size_t send_len;
  size_t send_cap;
  size_t send_offset;

  /* Linked list for connection's stream list */
  nwep_stream *next;
};

/*
 * Internal connection structure
 */
struct nwep_conn {
  int is_server;
  nwep_conn_state state;
  nwep_callbacks callbacks;
  nwep_settings settings;
  void *user_data;

  /* Identity */
  nwep_identity local_identity;
  nwep_identity peer_identity;

  /* Handshake state */
  nwep_handshake handshake;
  nwep_stream *handshake_stream;
  int handshake_complete;

  /* Network path */
  nwep_path path;

  /* Streams */
  nwep_stream *streams;
  int64_t next_stream_id;

  /* Error state */
  int close_error;

  /* ngtcp2 connection */
  ngtcp2_conn *qconn;

  /* Connection IDs (for server-side routing) */
  ngtcp2_cid scids[8]; /* Source CIDs we've issued */
  size_t scid_count;

  /* TLS/SSL */
  SSL *ssl;
  ngtcp2_crypto_conn_ref conn_ref;

  /* Expiry timer */
  nwep_tstamp expiry;

  /* Parent server/client (for callbacks) */
  union {
    nwep_server *server;
    nwep_client *client;
  } parent;
};

/*
 * Internal server structure
 */
struct nwep_server {
  nwep_settings settings;
  nwep_callbacks callbacks;
  nwep_keypair *keypair;
  void *user_data;

  /* Active connections (linked list or hash table in future) */
  nwep_conn **connections;
  size_t conn_count;
  size_t conn_cap;

  /* TLS context (holds SSL_CTX, cert, and key) */
  nwep_tls_ctx *tls_ctx;

  /* Expiry tracking */
  nwep_tstamp next_expiry;
};

/*
 * Internal client structure
 */
struct nwep_client {
  nwep_settings settings;
  nwep_callbacks callbacks;
  nwep_keypair *keypair;
  void *user_data;

  /* Single connection for client */
  nwep_conn *conn;

  /* Target URL */
  nwep_url target_url;

  /* TLS context (holds SSL_CTX, cert, and key) */
  nwep_tls_ctx *tls_ctx;
};

/*
 * Internal functions
 */

/* Connection management */
nwep_conn *nwep_conn_new(nwep_keypair *keypair, int is_server,
                         const nwep_callbacks *callbacks,
                         const nwep_settings *settings, void *user_data);
void nwep_conn_free(nwep_conn *conn);

/* Stream management */
nwep_stream *nwep_stream_new(nwep_conn *conn, int64_t id);
void nwep_stream_free(nwep_stream *stream);
nwep_stream *nwep_conn_find_stream(nwep_conn *conn, int64_t id);
int nwep_conn_add_stream(nwep_conn *conn, nwep_stream *stream);
void nwep_conn_remove_stream(nwep_conn *conn, nwep_stream *stream);

/* Request/Response flow (Phase 7) */

/*
 * nwep_stream_process_request processes an incoming request on a stream.
 * This is called by the server when stream data is received.
 * |is_0rtt| indicates if this is early data (0-RTT).
 */
int nwep_stream_process_request(nwep_stream *stream, const uint8_t *data,
                                size_t data_len, int is_0rtt);

/*
 * nwep_stream_process_response processes an incoming response on a stream.
 * This is called by the client when stream data is received.
 */
int nwep_stream_process_response(nwep_stream *stream, const uint8_t *data,
                                 size_t data_len);

/*
 * nwep_stream_process_data processes incoming stream body data (chunks).
 * Calls the on_stream_data callback.
 */
int nwep_stream_process_data(nwep_stream *stream, const uint8_t *data,
                             size_t data_len);

/*
 * nwep_stream_process_end handles stream FIN (end of data).
 * Updates stream state and calls on_stream_end callback.
 */
int nwep_stream_process_end(nwep_stream *stream);

/*
 * nwep_stream_send_response sends a response on a stream (server-side).
 */
int nwep_stream_send_response(nwep_stream *stream, const char *status,
                              const char *status_details,
                              const nwep_header *extra_headers,
                              size_t extra_header_count, const uint8_t *body,
                              size_t body_len);

/*
 * nwep_stream_send_request sends a request on a stream (client-side).
 */
int nwep_stream_send_request(nwep_stream *stream, const char *method,
                             const char *path,
                             const nwep_header *extra_headers,
                             size_t extra_header_count, const uint8_t *body,
                             size_t body_len);

/*
 * nwep_stream_send_error sends an error response on a stream.
 */
int nwep_stream_send_error(nwep_stream *stream, const char *status,
                           const char *details);

/*
 * nwep_stream_process_notify processes an incoming NOTIFY on a stream.
 */
int nwep_stream_process_notify(nwep_stream *stream, const uint8_t *data,
                               size_t data_len);

/*
 * nwep_stream_send_notify sends a NOTIFY on a stream.
 */
int nwep_stream_send_notify(nwep_stream *stream, const char *event,
                            const char *path, const uint8_t *notify_id,
                            const nwep_header *extra_headers,
                            size_t extra_header_count, const uint8_t *body,
                            size_t body_len);

/* TLS/Crypto (Phase 8) */

/*
 * nwep_tls_init initializes the ngtcp2 crypto library.
 * Should be called once at startup.
 */
int nwep_tls_init(void);

/*
 * nwep_tls_ctx_server_new creates a TLS context for server.
 */
int nwep_tls_ctx_server_new(nwep_tls_ctx **pctx, nwep_keypair *keypair);

/*
 * nwep_tls_ctx_client_new creates a TLS context for client.
 */
int nwep_tls_ctx_client_new(nwep_tls_ctx **pctx, nwep_keypair *keypair);

/*
 * nwep_tls_ctx_free frees a TLS context.
 */
void nwep_tls_ctx_free(nwep_tls_ctx *ctx);

/*
 * nwep_tls_ctx_get_ssl_ctx gets the SSL_CTX from a TLS context.
 */
SSL_CTX *nwep_tls_ctx_get_ssl_ctx(nwep_tls_ctx *ctx);

/*
 * nwep_tls_new_ssl creates a new SSL session from a TLS context.
 */
SSL *nwep_tls_new_ssl(nwep_tls_ctx *ctx);

/*
 * nwep_tls_conn_ref_init initializes the ngtcp2_crypto_conn_ref for a connection.
 */
void nwep_tls_conn_ref_init(ngtcp2_crypto_conn_ref *ref, nwep_conn *conn);

/*
 * nwep_tls_set_callbacks sets the ngtcp2 callbacks for crypto operations.
 */
void nwep_tls_set_callbacks(ngtcp2_callbacks *callbacks);

/*
 * Certificate validation functions
 */

/*
 * nwep_cert_extract_pubkey extracts the Ed25519 public key from an X.509 certificate.
 */
int nwep_cert_extract_pubkey(uint8_t *pubkey, size_t pubkey_len, X509 *cert);

/*
 * nwep_cert_extract_pubkey_from_ssl extracts the peer's public key from an SSL connection.
 */
int nwep_cert_extract_pubkey_from_ssl(uint8_t *pubkey, size_t pubkey_len,
                                      SSL *ssl);

/*
 * nwep_cert_check_expiry checks if a certificate is expired.
 * Returns 0 if valid, error code if expired.
 * If days_until_expiry is not NULL, writes the number of days until expiry.
 */
int nwep_cert_check_expiry(X509 *cert, int *days_until_expiry);

/*
 * nwep_cert_needs_renewal returns 1 if the certificate should be renewed
 * (expired or within 30 days of expiry).
 */
int nwep_cert_needs_renewal(X509 *cert);

/* QUIC Integration (Phase 9) */

/*
 * nwep_quic_client_init initializes a client QUIC connection.
 */
int nwep_quic_client_init(nwep_conn *conn, const struct sockaddr *remote_addr,
                          size_t remote_addrlen,
                          const struct sockaddr *local_addr,
                          size_t local_addrlen, ngtcp2_tstamp ts);

/*
 * nwep_quic_server_init initializes a server QUIC connection from initial packet.
 */
int nwep_quic_server_init(nwep_conn *conn, const ngtcp2_pkt_hd *hd,
                          const struct sockaddr *remote_addr,
                          size_t remote_addrlen,
                          const struct sockaddr *local_addr,
                          size_t local_addrlen, ngtcp2_tstamp ts);

/*
 * nwep_quic_read processes an incoming QUIC packet.
 */
int nwep_quic_read(nwep_conn *conn, const uint8_t *data, size_t datalen,
                   const struct sockaddr *remote_addr, size_t remote_addrlen,
                   const struct sockaddr *local_addr, size_t local_addrlen,
                   ngtcp2_tstamp ts);

/*
 * nwep_quic_write generates an outgoing QUIC packet.
 * Returns the number of bytes written, or negative error code.
 */
nwep_ssize nwep_quic_write(nwep_conn *conn, uint8_t *data, size_t datalen,
                           ngtcp2_tstamp ts);

/*
 * nwep_quic_write_stream writes stream data in a QUIC packet.
 * Returns the number of bytes written, or negative error code.
 */
nwep_ssize nwep_quic_write_stream(nwep_conn *conn, int64_t stream_id,
                                  const uint8_t *data, size_t datalen, int fin,
                                  uint8_t *buf, size_t buflen,
                                  ngtcp2_tstamp ts);

/*
 * nwep_quic_open_stream opens a new bidirectional stream.
 */
int nwep_quic_open_stream(nwep_conn *conn, int64_t *pstream_id);

/*
 * nwep_quic_shutdown_stream shuts down a stream.
 */
int nwep_quic_shutdown_stream(nwep_conn *conn, int64_t stream_id,
                              uint64_t app_error_code);

/*
 * nwep_quic_handle_expiry handles connection timeout.
 */
int nwep_quic_handle_expiry(nwep_conn *conn, ngtcp2_tstamp ts);

/*
 * nwep_quic_get_expiry gets the connection expiry time.
 */
ngtcp2_tstamp nwep_quic_get_expiry(const nwep_conn *conn);

/*
 * nwep_quic_close closes the QUIC connection.
 * Returns the number of bytes written to buf, or negative error code.
 */
nwep_ssize nwep_quic_close(nwep_conn *conn, uint8_t *buf, size_t buflen,
                           uint64_t app_error_code, ngtcp2_tstamp ts);

/*
 * nwep_quic_is_draining returns 1 if connection is in draining state.
 */
int nwep_quic_is_draining(const nwep_conn *conn);

/*
 * nwep_quic_handshake_completed returns 1 if handshake is complete.
 */
int nwep_quic_handshake_completed(const nwep_conn *conn);

/*
 * nwep_quic_free frees QUIC connection resources.
 */
void nwep_quic_free(nwep_conn *conn);

/* Stream helpers */

/*
 * nwep_stream_find finds a stream by ID.
 */
nwep_stream *nwep_stream_find(nwep_conn *conn, int64_t stream_id);

/*
 * nwep_stream_remove removes a stream from the connection.
 */
void nwep_stream_remove(nwep_conn *conn, nwep_stream *stream);

#endif /* !defined(NWEP_INTERNAL_H) */
