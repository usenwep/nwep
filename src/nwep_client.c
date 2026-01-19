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

int nwep_client_new(nwep_client **pclient, const nwep_settings *settings,
                    const nwep_callbacks *callbacks, nwep_keypair *keypair,
                    void *user_data) {
  nwep_client *client;

  if (pclient == NULL || settings == NULL || callbacks == NULL ||
      keypair == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  client = (nwep_client *)calloc(1, sizeof(*client));
  if (client == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  client->settings = *settings;
  client->callbacks = *callbacks;
  client->keypair = keypair;
  client->user_data = user_data;

  /* Initialize TLS context for client */
  {
    int rv = nwep_tls_ctx_client_new(&client->tls_ctx, keypair);
    if (rv != 0) {
      free(client);
      return rv;
    }
  }

  *pclient = client;
  return 0;
}

void nwep_client_free(nwep_client *client) {
  if (client == NULL) {
    return;
  }

  if (client->conn != NULL) {
    nwep_conn_free(client->conn);
  }

  /* Free TLS context */
  if (client->tls_ctx != NULL) {
    nwep_tls_ctx_free(client->tls_ctx);
  }

  free(client);
}

int nwep_client_connect(nwep_client *client, const nwep_url *url,
                        const struct sockaddr *local_addr,
                        size_t local_addrlen, nwep_tstamp ts) {
  nwep_conn *conn;
  struct sockaddr_in6 remote_addr;
  struct sockaddr_in6 default_local;
  const struct sockaddr *local;
  size_t local_len;
  int rv;

  if (client == NULL || url == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Store target URL */
  client->target_url = *url;

  /* Create connection */
  conn = nwep_conn_new(client->keypair, 0, &client->callbacks,
                       &client->settings, client->user_data);
  if (conn == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  conn->parent.client = client;

  /* Set expected peer NodeID from URL for verification */
  memcpy(&conn->handshake.expected_peer_nodeid, &url->addr.nodeid,
         sizeof(nwep_nodeid));

  /* Use provided local address or default to INADDR6_ANY */
  if (local_addr != NULL && local_addrlen > 0) {
    local = local_addr;
    local_len = local_addrlen;
  } else {
    memset(&default_local, 0, sizeof(default_local));
    default_local.sin6_family = AF_INET6;
    local = (struct sockaddr *)&default_local;
    local_len = sizeof(default_local);
  }

  /* Store local address */
  memcpy(&conn->path.local_addr, local, local_len);
  conn->path.local_addrlen = local_len;

  client->conn = conn;

  /* Build remote address from URL */
  memset(&remote_addr, 0, sizeof(remote_addr));
  remote_addr.sin6_family = AF_INET6;
  memcpy(&remote_addr.sin6_addr, url->addr.ip, 16);
  remote_addr.sin6_port = htons(url->addr.port);

  /* Initialize QUIC connection */
  rv = nwep_quic_client_init(conn, (struct sockaddr *)&remote_addr,
                             sizeof(remote_addr), local, local_len, ts);
  if (rv != 0) {
    nwep_conn_free(conn);
    client->conn = NULL;
    return rv;
  }

  conn->handshake.state.client = NWEP_CLIENT_STATE_TLS_HANDSHAKE;

  return 0;
}

int nwep_client_read(nwep_client *client, const nwep_path *path,
                     const uint8_t *data, size_t datalen, nwep_tstamp ts) {
  if (client == NULL || path == NULL || data == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (client->conn == NULL) {
    return NWEP_ERR_INTERNAL_INVALID_STATE;
  }

  /* Process incoming QUIC packet */
  return nwep_quic_read(client->conn, data, datalen,
                        (const struct sockaddr *)&path->remote_addr,
                        path->remote_addrlen,
                        (const struct sockaddr *)&path->local_addr,
                        path->local_addrlen, ts);
}

nwep_ssize nwep_client_write(nwep_client *client, nwep_path *path,
                             uint8_t *data, size_t datalen, nwep_tstamp ts) {
  nwep_ssize nwrite;

  if (client == NULL || path == NULL || data == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (client->conn == NULL) {
    return NWEP_ERR_INTERNAL_INVALID_STATE;
  }

  /* Generate outgoing QUIC packet */
  nwrite = nwep_quic_write(client->conn, data, datalen, ts);

  if (nwrite > 0) {
    /* Update path with connection's current path */
    memcpy(&path->local_addr, &client->conn->path.local_addr,
           client->conn->path.local_addrlen);
    path->local_addrlen = client->conn->path.local_addrlen;
    memcpy(&path->remote_addr, &client->conn->path.remote_addr,
           client->conn->path.remote_addrlen);
    path->remote_addrlen = client->conn->path.remote_addrlen;
  }

  return nwrite;
}

int nwep_client_handle_expiry(nwep_client *client, nwep_tstamp ts) {
  if (client == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (client->conn == NULL) {
    return 0;
  }

  return nwep_quic_handle_expiry(client->conn, ts);
}

nwep_tstamp nwep_client_get_expiry(const nwep_client *client) {
  if (client == NULL || client->conn == NULL) {
    return UINT64_MAX;
  }

  return nwep_quic_get_expiry(client->conn);
}

void nwep_client_close(nwep_client *client) {
  if (client == NULL || client->conn == NULL) {
    return;
  }

  nwep_conn_close(client->conn, 0);
}

nwep_conn *nwep_client_get_conn(nwep_client *client) {
  if (client == NULL) {
    return NULL;
  }
  return client->conn;
}
