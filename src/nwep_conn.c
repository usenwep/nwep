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
 * Connection implementation
 */

nwep_conn *nwep_conn_new(nwep_keypair *keypair, int is_server,
                         const nwep_callbacks *callbacks,
                         const nwep_settings *settings, void *user_data) {
  nwep_conn *conn;
  int rv;

  conn = (nwep_conn *)calloc(1, sizeof(*conn));
  if (conn == NULL) {
    return NULL;
  }

  conn->is_server = is_server;
  conn->callbacks = *callbacks;
  conn->settings = *settings;
  conn->user_data = user_data;
  conn->state = NWEP_CONN_STATE_INITIAL;

  /* Initialize handshake */
  if (is_server) {
    rv = nwep_handshake_server_init(&conn->handshake, keypair);
  } else {
    rv = nwep_handshake_client_init(&conn->handshake, keypair, NULL);
  }

  if (rv != 0) {
    free(conn);
    return NULL;
  }

  /* Copy identity */
  memcpy(conn->local_identity.pubkey, keypair->pubkey, NWEP_ED25519_PUBKEY_LEN);
  memcpy(&conn->local_identity.nodeid, &conn->handshake.local_nodeid,
         sizeof(nwep_nodeid));

  return conn;
}

void nwep_conn_free(nwep_conn *conn) {
  nwep_stream *stream, *next;

  if (conn == NULL) {
    return;
  }

  /* Free all streams */
  for (stream = conn->streams; stream != NULL; stream = next) {
    next = stream->next;
    nwep_stream_free(stream);
  }

  nwep_handshake_free(&conn->handshake);

  /* Free QUIC connection resources */
  nwep_quic_free(conn);

  free(conn);
}

const nwep_identity *nwep_conn_get_peer_identity(const nwep_conn *conn) {
  if (conn == NULL) {
    return NULL;
  }
  return &conn->peer_identity;
}

const nwep_identity *nwep_conn_get_local_identity(const nwep_conn *conn) {
  if (conn == NULL) {
    return NULL;
  }
  return &conn->local_identity;
}

const char *nwep_conn_get_role(const nwep_conn *conn) {
  if (conn == NULL) {
    return NULL;
  }
  return conn->handshake.negotiated_params.role;
}

void nwep_conn_close(nwep_conn *conn, int error) {
  if (conn == NULL) {
    return;
  }

  conn->state = NWEP_CONN_STATE_CLOSING;
  conn->close_error = error;

  /*
   * Note: Connection state is updated. The CONNECTION_CLOSE frame
   * is sent when nwep_*_write() detects the closing state and calls
   * ngtcp2_conn_write_connection_close().
   */
}

void *nwep_conn_get_user_data(const nwep_conn *conn) {
  if (conn == NULL) {
    return NULL;
  }
  return conn->user_data;
}

void nwep_conn_set_user_data(nwep_conn *conn, void *user_data) {
  if (conn == NULL) {
    return;
  }
  conn->user_data = user_data;
}

/*
 * Settings
 */

void nwep_settings_default(nwep_settings *settings) {
  if (settings == NULL) {
    return;
  }

  settings->max_streams = NWEP_DEFAULT_MAX_STREAMS;
  settings->max_message_size = NWEP_DEFAULT_MAX_MESSAGE_SIZE;
  settings->timeout_ms = NWEP_DEFAULT_TIMEOUT / 1000000; /* Convert ns to ms */
  settings->compression = "none";
  settings->role = NULL;
}
