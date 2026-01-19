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

#define INITIAL_CONN_CAP 16

int nwep_server_new(nwep_server **pserver, const nwep_settings *settings,
                    const nwep_callbacks *callbacks, nwep_keypair *keypair,
                    void *user_data) {
  nwep_server *server;

  if (pserver == NULL || settings == NULL || callbacks == NULL ||
      keypair == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  server = (nwep_server *)calloc(1, sizeof(*server));
  if (server == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  server->settings = *settings;
  server->callbacks = *callbacks;
  server->keypair = keypair;
  server->user_data = user_data;
  server->next_expiry = UINT64_MAX;
  server->connections =
      (nwep_conn **)calloc(INITIAL_CONN_CAP, sizeof(nwep_conn *));
  if (server->connections == NULL) {
    free(server);
    return NWEP_ERR_INTERNAL_NOMEM;
  }
  server->conn_cap = INITIAL_CONN_CAP;
  {
    int rv = nwep_tls_ctx_server_new(&server->tls_ctx, keypair);
    if (rv != 0) {
      free(server->connections);
      free(server);
      return rv;
    }
  }

  *pserver = server;
  return 0;
}

void nwep_server_free(nwep_server *server) {
  size_t i;

  if (server == NULL) {
    return;
  }
  for (i = 0; i < server->conn_count; i++) {
    if (server->connections[i] != NULL) {
      nwep_conn_free(server->connections[i]);
    }
  }
  free(server->connections);
  if (server->tls_ctx != NULL) {
    nwep_tls_ctx_free(server->tls_ctx);
  }

  free(server);
}

static nwep_conn *server_find_conn_by_dcid(nwep_server *server,
                                           const ngtcp2_cid *dcid) {
  size_t i, j;

  for (i = 0; i < server->conn_count; i++) {
    nwep_conn *conn = server->connections[i];
    if (conn == NULL || conn->qconn == NULL) {
      continue;
    }

    for (j = 0; j < conn->scid_count; j++) {
      if (ngtcp2_cid_eq(&conn->scids[j], dcid)) {
        return conn;
      }
    }
  }

  return NULL;
}

static int server_add_conn(nwep_server *server, nwep_conn *conn) {
  if (server->conn_count >= server->conn_cap) {
    size_t new_cap = server->conn_cap * 2;
    nwep_conn **new_conns =
        (nwep_conn **)realloc(server->connections, new_cap * sizeof(nwep_conn *));
    if (new_conns == NULL) {
      return NWEP_ERR_INTERNAL_NOMEM;
    }
    server->connections = new_conns;
    server->conn_cap = new_cap;
  }

  server->connections[server->conn_count++] = conn;
  return 0;
}

int nwep_server_read(nwep_server *server, const nwep_path *path,
                     const uint8_t *data, size_t datalen, nwep_tstamp ts) {
  ngtcp2_pkt_hd hd;
  nwep_conn *conn;
  ngtcp2_version_cid vc;
  ngtcp2_cid dcid;
  int rv;

  if (server == NULL || path == NULL || data == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (datalen == 0) {
    return 0;
  }

  rv = ngtcp2_pkt_decode_version_cid(&vc, data, datalen, 16);
  if (rv != 0) {
    return 0;
  }
  ngtcp2_cid_init(&dcid, vc.dcid, vc.dcidlen);
  conn = server_find_conn_by_dcid(server, &dcid);

#ifdef NWEP_DEBUG
  fprintf(stderr, "[server_read] dcid=%02x%02x..., conn=%p\n",
          dcid.data[0], dcid.data[1], (void *)conn);
#endif

  if (conn != NULL) {
    return nwep_quic_read(conn, data, datalen,
                          (const struct sockaddr *)&path->remote_addr,
                          path->remote_addrlen,
                          (const struct sockaddr *)&path->local_addr,
                          path->local_addrlen, ts);
  }
  if (vc.version == 0) {
    return 0;
  }
  rv = ngtcp2_accept(&hd, data, datalen);
#ifdef NWEP_DEBUG
  fprintf(stderr, "[server_read] ngtcp2_accept returned %d\n", rv);
#endif
  if (rv < 0) {
#ifdef NWEP_DEBUG
    fprintf(stderr, "[server_read] Packet not accepted, dropping\n");
#endif
    return 0;
  }
  conn = nwep_conn_new(server->keypair, 1, &server->callbacks, &server->settings,
                       server->user_data);
  if (conn == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }
  conn->parent.server = server;
  rv = nwep_quic_server_init(conn, &hd,
                             (const struct sockaddr *)&path->remote_addr,
                             path->remote_addrlen,
                             (const struct sockaddr *)&path->local_addr,
                             path->local_addrlen, ts);
  if (rv != 0) {
    nwep_conn_free(conn);
    return rv;
  }
  rv = server_add_conn(server, conn);
  if (rv != 0) {
    nwep_conn_free(conn);
    return rv;
  }
  return nwep_quic_read(conn, data, datalen,
                        (const struct sockaddr *)&path->remote_addr,
                        path->remote_addrlen,
                        (const struct sockaddr *)&path->local_addr,
                        path->local_addrlen, ts);
}

nwep_ssize nwep_server_write(nwep_server *server, nwep_path *path,
                             uint8_t *data, size_t datalen, nwep_tstamp ts) {
  size_t i;
  nwep_ssize nwrite;

  if (server == NULL || path == NULL || data == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  for (i = 0; i < server->conn_count; i++) {
    nwep_conn *conn = server->connections[i];
    if (conn == NULL || conn->qconn == NULL) {
      continue;
    }

    if (nwep_quic_is_draining(conn)) {
      continue;
    }

    nwrite = nwep_quic_write(conn, data, datalen, ts);
    if (nwrite > 0) {
      memcpy(&path->local_addr, &conn->path.local_addr, conn->path.local_addrlen);
      path->local_addrlen = conn->path.local_addrlen;
      memcpy(&path->remote_addr, &conn->path.remote_addr,
             conn->path.remote_addrlen);
      path->remote_addrlen = conn->path.remote_addrlen;
      return nwrite;
    }

    if (nwrite < 0) {
      continue;
    }
  }

  return 0;
}

int nwep_server_handle_expiry(nwep_server *server, nwep_tstamp ts) {
  size_t i;
  int rv;

  if (server == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  for (i = 0; i < server->conn_count; i++) {
    nwep_conn *conn = server->connections[i];
    if (conn == NULL || conn->qconn == NULL) {
      continue;
    }

    rv = nwep_quic_handle_expiry(conn, ts);
    if (rv != 0) {
      conn->state = NWEP_CONN_STATE_CLOSED;
    }
  }
  server->next_expiry = UINT64_MAX;
  for (i = 0; i < server->conn_count; i++) {
    nwep_conn *conn = server->connections[i];
    if (conn == NULL || conn->qconn == NULL) {
      continue;
    }

    nwep_tstamp expiry = nwep_quic_get_expiry(conn);
    if (expiry < server->next_expiry) {
      server->next_expiry = expiry;
    }
  }

  return 0;
}

nwep_tstamp nwep_server_get_expiry(const nwep_server *server) {
  size_t i;
  nwep_tstamp min_expiry = UINT64_MAX;

  if (server == NULL) {
    return UINT64_MAX;
  }

  for (i = 0; i < server->conn_count; i++) {
    nwep_conn *conn = server->connections[i];
    if (conn == NULL || conn->qconn == NULL) {
      continue;
    }

    nwep_tstamp expiry = nwep_quic_get_expiry(conn);
    if (expiry < min_expiry) {
      min_expiry = expiry;
    }
  }

  return min_expiry;
}

void nwep_server_close(nwep_server *server) {
  size_t i;

  if (server == NULL) {
    return;
  }

  for (i = 0; i < server->conn_count; i++) {
    if (server->connections[i] != NULL) {
      nwep_conn_close(server->connections[i], 0);
    }
  }
}
