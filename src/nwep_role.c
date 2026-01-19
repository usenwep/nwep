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
#include <nwep/nwep.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

nwep_server_role nwep_role_from_str(const char *role_str) {
  if (role_str == NULL) {
    return NWEP_ROLE_REGULAR;
  }
  if (strcmp(role_str, NWEP_ROLE_STR_LOG_SERVER) == 0) {
    return NWEP_ROLE_LOG_SERVER;
  }
  if (strcmp(role_str, NWEP_ROLE_STR_ANCHOR) == 0) {
    return NWEP_ROLE_ANCHOR;
  }
  return NWEP_ROLE_REGULAR;
}

const char *nwep_role_to_str(nwep_server_role role) {
  switch (role) {
  case NWEP_ROLE_LOG_SERVER:
    return NWEP_ROLE_STR_LOG_SERVER;
  case NWEP_ROLE_ANCHOR:
    return NWEP_ROLE_STR_ANCHOR;
  case NWEP_ROLE_REGULAR:
  default:
    return NWEP_ROLE_STR_REGULAR;
  }
}

struct nwep_log_server {
  nwep_merkle_log *log;
  nwep_log_server_settings settings;
};

int nwep_log_server_new(nwep_log_server **pserver, nwep_merkle_log *log,
                        const nwep_log_server_settings *settings) {
  nwep_log_server *server;

  if (pserver == NULL || log == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  server = calloc(1, sizeof(*server));
  if (server == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  server->log = log;
  if (settings != NULL) {
    server->settings = *settings;
  }

  *pserver = server;
  return 0;
}

/*
 * nwep_log_server_free frees |server|.  It does not free the underlying
 * merkle log which is owned by the caller.
 */
void nwep_log_server_free(nwep_log_server *server) {
  if (server == NULL) {
    return;
  }
  free(server);
}

nwep_merkle_log *nwep_log_server_get_log(nwep_log_server *server) {
  if (server == NULL) {
    return NULL;
  }
  return server->log;
}

static int parse_path_index(const char *path, const char *prefix,
                            uint64_t *index) {
  size_t prefix_len;
  const char *p;
  char *endptr;

  if (path == NULL || prefix == NULL || index == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  prefix_len = strlen(prefix);
  if (strncmp(path, prefix, prefix_len) != 0) {
    return NWEP_ERR_PROTO_PATH_NOT_FOUND;
  }

  p = path + prefix_len;
  *index = strtoull(p, &endptr, 10);
  if (endptr == p || *endptr != '\0') {
    return NWEP_ERR_PROTO_PATH_NOT_FOUND;
  }

  return 0;
}

static int send_json_response(nwep_stream *stream, const char *status,
                              const char *json_body) {
  nwep_response resp;
  nwep_header headers[2];

  memset(&resp, 0, sizeof(resp));
  resp.status = status;
  resp.headers = headers;
  resp.header_count = 1;

  nwep_header_set(&headers[0], "content-type", "application/json");

  if (json_body != NULL) {
    resp.body = (const uint8_t *)json_body;
    resp.body_len = strlen(json_body);
  }

  return nwep_stream_respond(stream, &resp);
}

static int send_error_response(nwep_stream *stream, const char *status,
                               const char *error_msg) {
  char json[256];
  snprintf(json, sizeof(json), "{\"error\":\"%s\"}", error_msg);
  return send_json_response(stream, status, json);
}

int nwep_log_server_handle_request(nwep_log_server *server, nwep_stream *stream,
                                   const nwep_request *request) {
  const char *method;
  const char *path;
  uint64_t index;
  int rv;

  if (server == NULL || stream == NULL || request == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  method = request->method;
  path = request->path;

  if (method == NULL || path == NULL) {
    return send_error_response(stream, NWEP_STATUS_BAD_REQUEST,
                               "missing method or path");
  }

  /* READ /log/size */
  if (strcmp(method, NWEP_METHOD_READ) == 0 &&
      strcmp(path, "/log/size") == 0) {
    char json[64];
    uint64_t size = nwep_merkle_log_size(server->log);
    snprintf(json, sizeof(json), "{\"size\":%" PRIu64 "}", size);
    return send_json_response(stream, NWEP_STATUS_OK, json);
  }

  /* READ /log/entry/{index} */
  if (strcmp(method, NWEP_METHOD_READ) == 0 &&
      strncmp(path, "/log/entry/", 11) == 0) {
    nwep_merkle_entry entry;

    rv = parse_path_index(path, "/log/entry/", &index);
    if (rv != 0) {
      return send_error_response(stream, NWEP_STATUS_BAD_REQUEST,
                                 "invalid index");
    }

    rv = nwep_merkle_log_get(server->log, index, &entry);
    if (rv != 0) {
      return send_error_response(stream, NWEP_STATUS_NOT_FOUND,
                                 "entry not found");
    }

    /* Encode entry to response body */
    uint8_t entry_buf[NWEP_LOG_ENTRY_MAX_SIZE];
    nwep_ssize entry_len = nwep_merkle_entry_encode(entry_buf, sizeof(entry_buf),
                                                     &entry);
    if (entry_len < 0) {
      return send_error_response(stream, NWEP_STATUS_INTERNAL_ERROR,
                                 "encode failed");
    }

    nwep_response resp;
    nwep_header headers[1];
    memset(&resp, 0, sizeof(resp));
    resp.status = NWEP_STATUS_OK;
    resp.headers = headers;
    resp.header_count = 1;
    nwep_header_set(&headers[0], "content-type", "application/octet-stream");
    resp.body = entry_buf;
    resp.body_len = (size_t)entry_len;

    return nwep_stream_respond(stream, &resp);
  }

  /* READ /log/proof/{index} */
  if (strcmp(method, NWEP_METHOD_READ) == 0 &&
      strncmp(path, "/log/proof/", 11) == 0) {
    nwep_merkle_proof proof;

    rv = parse_path_index(path, "/log/proof/", &index);
    if (rv != 0) {
      return send_error_response(stream, NWEP_STATUS_BAD_REQUEST,
                                 "invalid index");
    }

    rv = nwep_merkle_log_prove(server->log, index, &proof);
    if (rv != 0) {
      return send_error_response(stream, NWEP_STATUS_NOT_FOUND,
                                 "proof generation failed");
    }

    /* Encode proof to response body */
    uint8_t proof_buf[NWEP_MERKLE_PROOF_MAX_SIZE];
    nwep_ssize proof_len = nwep_merkle_proof_encode(proof_buf, sizeof(proof_buf),
                                                     &proof);
    if (proof_len < 0) {
      return send_error_response(stream, NWEP_STATUS_INTERNAL_ERROR,
                                 "proof encode failed");
    }

    nwep_response resp;
    nwep_header headers[1];
    memset(&resp, 0, sizeof(resp));
    resp.status = NWEP_STATUS_OK;
    resp.headers = headers;
    resp.header_count = 1;
    nwep_header_set(&headers[0], "content-type", "application/octet-stream");
    resp.body = proof_buf;
    resp.body_len = (size_t)proof_len;

    return nwep_stream_respond(stream, &resp);
  }

  /* WRITE /log/entry */
  if (strcmp(method, NWEP_METHOD_WRITE) == 0 &&
      strcmp(path, "/log/entry") == 0) {
    nwep_merkle_entry entry;
    uint64_t new_index;

    /* Check authorization */
    if (server->settings.authorize == NULL) {
      return send_error_response(stream, NWEP_STATUS_FORBIDDEN,
                                 "writes not allowed");
    }

    /* Decode entry from body */
    if (request->body == NULL || request->body_len == 0) {
      return send_error_response(stream, NWEP_STATUS_BAD_REQUEST,
                                 "missing body");
    }

    rv = nwep_merkle_entry_decode(&entry, request->body, request->body_len);
    if (rv != 0) {
      return send_error_response(stream, NWEP_STATUS_BAD_REQUEST,
                                 "invalid entry");
    }

    /* Check authorization */
    nwep_conn *conn = nwep_stream_get_conn(stream);
    const nwep_identity *peer = nwep_conn_get_peer_identity(conn);
    rv = server->settings.authorize(server->settings.user_data, &peer->nodeid,
                                    &entry);
    if (rv != 0) {
      return send_error_response(stream, NWEP_STATUS_FORBIDDEN,
                                 "not authorized");
    }

    /* Append to log */
    rv = nwep_merkle_log_append(server->log, &entry, &new_index);
    if (rv != 0) {
      return send_error_response(stream, NWEP_STATUS_INTERNAL_ERROR,
                                 "append failed");
    }

    char json[64];
    snprintf(json, sizeof(json), "{\"index\":%" PRIu64 "}", new_index);
    return send_json_response(stream, NWEP_STATUS_CREATED, json);
  }

  return send_error_response(stream, NWEP_STATUS_NOT_FOUND, "path not found");
}

struct nwep_anchor_server {
  nwep_bls_keypair keypair;
  nwep_anchor_set *anchors;
  nwep_checkpoint checkpoints[NWEP_MAX_CHECKPOINTS];
  size_t checkpoint_count;
  uint64_t latest_epoch;
  nwep_anchor_server_settings settings;
};

int nwep_anchor_server_new(nwep_anchor_server **pserver,
                           const nwep_bls_keypair *keypair,
                           nwep_anchor_set *anchors,
                           const nwep_anchor_server_settings *settings) {
  nwep_anchor_server *server;

  if (pserver == NULL || keypair == NULL || anchors == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  server = calloc(1, sizeof(*server));
  if (server == NULL) {
    return NWEP_ERR_INTERNAL_NOMEM;
  }

  memcpy(&server->keypair, keypair, sizeof(nwep_bls_keypair));
  server->anchors = anchors;
  if (settings != NULL) {
    server->settings = *settings;
  }

  *pserver = server;
  return 0;
}

/*
 * nwep_anchor_server_free frees |server|.  It does not free the anchor set
 * which is owned by the caller.
 */
void nwep_anchor_server_free(nwep_anchor_server *server) {
  if (server == NULL) {
    return;
  }
  free(server);
}

int nwep_anchor_server_add_checkpoint(nwep_anchor_server *server,
                                      const nwep_checkpoint *cp) {
  size_t idx;
  int rv;

  if (server == NULL || cp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Verify checkpoint */
  rv = nwep_checkpoint_verify(cp, server->anchors);
  if (rv != 0) {
    return rv;
  }

  /* Find slot */
  idx = server->checkpoint_count;
  for (size_t i = 0; i < server->checkpoint_count; i++) {
    if (server->checkpoints[i].epoch == cp->epoch) {
      idx = i;
      break;
    }
  }

  if (idx == server->checkpoint_count) {
    if (server->checkpoint_count >= NWEP_MAX_CHECKPOINTS) {
      /* Evict oldest */
      uint64_t oldest_epoch = UINT64_MAX;
      size_t oldest_idx = 0;
      for (size_t i = 0; i < server->checkpoint_count; i++) {
        if (server->checkpoints[i].epoch < oldest_epoch) {
          oldest_epoch = server->checkpoints[i].epoch;
          oldest_idx = i;
        }
      }
      idx = oldest_idx;
    } else {
      server->checkpoint_count++;
    }
  }

  memcpy(&server->checkpoints[idx], cp, sizeof(nwep_checkpoint));

  if (cp->epoch > server->latest_epoch) {
    server->latest_epoch = cp->epoch;
  }

  return 0;
}

int nwep_anchor_server_get_latest(const nwep_anchor_server *server,
                                  nwep_checkpoint *cp) {
  if (server == NULL || cp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (server->checkpoint_count == 0) {
    return NWEP_ERR_TRUST_ENTRY_NOT_FOUND;
  }

  for (size_t i = 0; i < server->checkpoint_count; i++) {
    if (server->checkpoints[i].epoch == server->latest_epoch) {
      memcpy(cp, &server->checkpoints[i], sizeof(nwep_checkpoint));
      return 0;
    }
  }

  return NWEP_ERR_TRUST_ENTRY_NOT_FOUND;
}

int nwep_anchor_server_get_checkpoint(const nwep_anchor_server *server,
                                      uint64_t epoch, nwep_checkpoint *cp) {
  if (server == NULL || cp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  for (size_t i = 0; i < server->checkpoint_count; i++) {
    if (server->checkpoints[i].epoch == epoch) {
      memcpy(cp, &server->checkpoints[i], sizeof(nwep_checkpoint));
      return 0;
    }
  }

  return NWEP_ERR_TRUST_ENTRY_NOT_FOUND;
}

int nwep_anchor_server_create_proposal(nwep_anchor_server *server,
                                       nwep_merkle_log *log, uint64_t epoch,
                                       nwep_tstamp timestamp,
                                       nwep_checkpoint *cp) {
  nwep_merkle_hash root;
  uint64_t log_size;
  int rv;

  if (server == NULL || log == NULL || cp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  /* Get current log state */
  rv = nwep_merkle_log_root(log, &root);
  if (rv != 0) {
    return rv;
  }
  log_size = nwep_merkle_log_size(log);

  /* Create checkpoint */
  rv = nwep_checkpoint_new(cp, epoch, timestamp, &root, log_size);
  return rv;
}

int nwep_anchor_server_sign_proposal(nwep_anchor_server *server,
                                     nwep_checkpoint *cp) {
  if (server == NULL || cp == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  return nwep_checkpoint_sign(cp, &server->keypair);
}

int nwep_anchor_server_handle_request(nwep_anchor_server *server,
                                      nwep_stream *stream,
                                      const nwep_request *request) {
  const char *method;
  const char *path;
  uint64_t epoch;
  int rv;

  if (server == NULL || stream == NULL || request == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  method = request->method;
  path = request->path;

  if (method == NULL || path == NULL) {
    return send_error_response(stream, NWEP_STATUS_BAD_REQUEST,
                               "missing method or path");
  }

  /* READ /checkpoint/latest */
  if (strcmp(method, NWEP_METHOD_READ) == 0 &&
      strcmp(path, "/checkpoint/latest") == 0) {
    nwep_checkpoint cp;

    rv = nwep_anchor_server_get_latest(server, &cp);
    if (rv != 0) {
      return send_error_response(stream, NWEP_STATUS_NOT_FOUND,
                                 "no checkpoints");
    }

    /* Encode checkpoint */
    uint8_t buf[1024];
    nwep_ssize len = nwep_checkpoint_encode(buf, sizeof(buf), &cp);
    if (len < 0) {
      return send_error_response(stream, NWEP_STATUS_INTERNAL_ERROR,
                                 "encode failed");
    }

    nwep_response resp;
    nwep_header headers[1];
    memset(&resp, 0, sizeof(resp));
    resp.status = NWEP_STATUS_OK;
    resp.headers = headers;
    resp.header_count = 1;
    nwep_header_set(&headers[0], "content-type", "application/octet-stream");
    resp.body = buf;
    resp.body_len = (size_t)len;

    return nwep_stream_respond(stream, &resp);
  }

  /* READ /checkpoint/{epoch} */
  if (strcmp(method, NWEP_METHOD_READ) == 0 &&
      strncmp(path, "/checkpoint/", 12) == 0 &&
      strcmp(path, "/checkpoint/latest") != 0) {
    nwep_checkpoint cp;

    rv = parse_path_index(path, "/checkpoint/", &epoch);
    if (rv != 0) {
      return send_error_response(stream, NWEP_STATUS_BAD_REQUEST,
                                 "invalid epoch");
    }

    rv = nwep_anchor_server_get_checkpoint(server, epoch, &cp);
    if (rv != 0) {
      return send_error_response(stream, NWEP_STATUS_NOT_FOUND,
                                 "checkpoint not found");
    }

    /* Encode checkpoint */
    uint8_t buf[1024];
    nwep_ssize len = nwep_checkpoint_encode(buf, sizeof(buf), &cp);
    if (len < 0) {
      return send_error_response(stream, NWEP_STATUS_INTERNAL_ERROR,
                                 "encode failed");
    }

    nwep_response resp;
    nwep_header headers[1];
    memset(&resp, 0, sizeof(resp));
    resp.status = NWEP_STATUS_OK;
    resp.headers = headers;
    resp.header_count = 1;
    nwep_header_set(&headers[0], "content-type", "application/octet-stream");
    resp.body = buf;
    resp.body_len = (size_t)len;

    return nwep_stream_respond(stream, &resp);
  }

  /* WRITE /checkpoint/propose */
  if (strcmp(method, NWEP_METHOD_WRITE) == 0 &&
      strcmp(path, "/checkpoint/propose") == 0) {
    nwep_checkpoint cp;

    if (request->body == NULL || request->body_len == 0) {
      return send_error_response(stream, NWEP_STATUS_BAD_REQUEST,
                                 "missing body");
    }

    /* Decode proposal */
    rv = nwep_checkpoint_decode(&cp, request->body, request->body_len);
    if (rv != 0) {
      return send_error_response(stream, NWEP_STATUS_BAD_REQUEST,
                                 "invalid proposal");
    }

    /* Check with callback if provided */
    if (server->settings.on_proposal != NULL) {
      rv = server->settings.on_proposal(server->settings.user_data, &cp);
      if (rv != 0) {
        return send_error_response(stream, NWEP_STATUS_FORBIDDEN,
                                   "proposal rejected");
      }
    }

    /* Sign the proposal */
    rv = nwep_anchor_server_sign_proposal(server, &cp);
    if (rv != 0) {
      return send_error_response(stream, NWEP_STATUS_INTERNAL_ERROR,
                                 "signing failed");
    }

    /* Return signed checkpoint */
    uint8_t buf[1024];
    nwep_ssize len = nwep_checkpoint_encode(buf, sizeof(buf), &cp);
    if (len < 0) {
      return send_error_response(stream, NWEP_STATUS_INTERNAL_ERROR,
                                 "encode failed");
    }

    nwep_response resp;
    nwep_header headers[1];
    memset(&resp, 0, sizeof(resp));
    resp.status = NWEP_STATUS_OK;
    resp.headers = headers;
    resp.header_count = 1;
    nwep_header_set(&headers[0], "content-type", "application/octet-stream");
    resp.body = buf;
    resp.body_len = (size_t)len;

    return nwep_stream_respond(stream, &resp);
  }

  /* Unknown path */
  return send_error_response(stream, NWEP_STATUS_NOT_FOUND, "path not found");
}
