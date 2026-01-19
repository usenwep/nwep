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
#include <nwep/nwep.h>

#include <stdio.h>
#include <string.h>

const char *nwep_strerror(int liberr) {
  if (liberr == 0) {
    return "NO_ERROR";
  }

  switch (liberr) {
  /* Config errors (-1xx) */
  case NWEP_ERR_CONFIG_FILE_NOT_FOUND:
    return "CONFIG_FILE_NOT_FOUND";
  case NWEP_ERR_CONFIG_PARSE_ERROR:
    return "CONFIG_PARSE_ERROR";
  case NWEP_ERR_CONFIG_INVALID_VALUE:
    return "CONFIG_INVALID_VALUE";
  case NWEP_ERR_CONFIG_MISSING_REQUIRED:
    return "CONFIG_MISSING_REQUIRED";
  case NWEP_ERR_CONFIG_VALIDATION_FAILED:
    return "CONFIG_VALIDATION_FAILED";

  /* Network errors (-2xx) */
  case NWEP_ERR_NETWORK_CONN_FAILED:
    return "NETWORK_CONN_FAILED";
  case NWEP_ERR_NETWORK_CONN_CLOSED:
    return "NETWORK_CONN_CLOSED";
  case NWEP_ERR_NETWORK_TIMEOUT:
    return "NETWORK_TIMEOUT";
  case NWEP_ERR_NETWORK_ADDR_IN_USE:
    return "NETWORK_ADDR_IN_USE";
  case NWEP_ERR_NETWORK_ADDR_INVALID:
    return "NETWORK_ADDR_INVALID";
  case NWEP_ERR_NETWORK_SOCKET:
    return "NETWORK_SOCKET";
  case NWEP_ERR_NETWORK_TLS:
    return "NETWORK_TLS";
  case NWEP_ERR_NETWORK_QUIC:
    return "NETWORK_QUIC";
  case NWEP_ERR_NETWORK_NO_SERVERS:
    return "NETWORK_NO_SERVERS";

  /* Crypto errors (-3xx) */
  case NWEP_ERR_CRYPTO_KEY_GEN_FAILED:
    return "CRYPTO_KEY_GEN_FAILED";
  case NWEP_ERR_CRYPTO_SIGN_FAILED:
    return "CRYPTO_SIGN_FAILED";
  case NWEP_ERR_CRYPTO_VERIFY_FAILED:
    return "CRYPTO_VERIFY_FAILED";
  case NWEP_ERR_CRYPTO_HASH_FAILED:
    return "CRYPTO_HASH_FAILED";
  case NWEP_ERR_CRYPTO_INVALID_KEY:
    return "CRYPTO_INVALID_KEY";
  case NWEP_ERR_CRYPTO_INVALID_SIG:
    return "CRYPTO_INVALID_SIG";
  case NWEP_ERR_CRYPTO_ENCRYPT_FAILED:
    return "CRYPTO_ENCRYPT_FAILED";
  case NWEP_ERR_CRYPTO_DECRYPT_FAILED:
    return "CRYPTO_DECRYPT_FAILED";
  case NWEP_ERR_CRYPTO_KEY_LOAD_FAILED:
    return "CRYPTO_KEY_LOAD_FAILED";
  case NWEP_ERR_CRYPTO_KEY_SAVE_FAILED:
    return "CRYPTO_KEY_SAVE_FAILED";
  case NWEP_ERR_CRYPTO_CERT_ERROR:
    return "CRYPTO_CERT_ERROR";
  case NWEP_ERR_CRYPTO_AUTH_TIMEOUT:
    return "CRYPTO_AUTH_TIMEOUT";
  /* Fatal crypto errors */
  case NWEP_ERR_CRYPTO_PUBKEY_MISMATCH:
    return "CRYPTO_PUBKEY_MISMATCH";
  case NWEP_ERR_CRYPTO_NODEID_MISMATCH:
    return "CRYPTO_NODEID_MISMATCH";
  case NWEP_ERR_CRYPTO_CHALLENGE_FAILED:
    return "CRYPTO_CHALLENGE_FAILED";
  case NWEP_ERR_CRYPTO_SERVER_SIG_INVALID:
    return "CRYPTO_SERVER_SIG_INVALID";
  case NWEP_ERR_CRYPTO_CLIENT_SIG_INVALID:
    return "CRYPTO_CLIENT_SIG_INVALID";

  /* Protocol errors (-4xx) */
  case NWEP_ERR_PROTO_INVALID_MESSAGE:
    return "PROTO_INVALID_MESSAGE";
  case NWEP_ERR_PROTO_INVALID_METHOD:
    return "PROTO_INVALID_METHOD";
  case NWEP_ERR_PROTO_INVALID_HEADER:
    return "PROTO_INVALID_HEADER";
  case NWEP_ERR_PROTO_MSG_TOO_LARGE:
    return "PROTO_MSG_TOO_LARGE";
  case NWEP_ERR_PROTO_STREAM_ERROR:
    return "PROTO_STREAM_ERROR";
  case NWEP_ERR_PROTO_CONNECT_REQUIRED:
    return "PROTO_CONNECT_REQUIRED";
  case NWEP_ERR_PROTO_TOO_MANY_HEADERS:
    return "PROTO_TOO_MANY_HEADERS";
  case NWEP_ERR_PROTO_HEADER_TOO_LARGE:
    return "PROTO_HEADER_TOO_LARGE";
  case NWEP_ERR_PROTO_INVALID_STATUS:
    return "PROTO_INVALID_STATUS";
  case NWEP_ERR_PROTO_0RTT_REJECTED:
    return "PROTO_0RTT_REJECTED";
  case NWEP_ERR_PROTO_MISSING_HEADER:
    return "PROTO_MISSING_HEADER";
  case NWEP_ERR_PROTO_ROLE_MISMATCH:
    return "PROTO_ROLE_MISMATCH";
  case NWEP_ERR_PROTO_UNAUTHORIZED:
    return "PROTO_UNAUTHORIZED";
  case NWEP_ERR_PROTO_PATH_NOT_FOUND:
    return "PROTO_PATH_NOT_FOUND";
  /* Fatal protocol errors */
  case NWEP_ERR_PROTO_VERSION_MISMATCH:
    return "PROTO_VERSION_MISMATCH";

  /* Identity errors (-5xx) */
  case NWEP_ERR_IDENTITY_INVALID_NODEID:
    return "IDENTITY_INVALID_NODEID";
  case NWEP_ERR_IDENTITY_INVALID_ADDR:
    return "IDENTITY_INVALID_ADDR";
  case NWEP_ERR_IDENTITY_AUTH_FAILED:
    return "IDENTITY_AUTH_FAILED";
  case NWEP_ERR_IDENTITY_CHALLENGE_EXPIRED:
    return "IDENTITY_CHALLENGE_EXPIRED";
  case NWEP_ERR_IDENTITY_INVALID_SHARE:
    return "IDENTITY_INVALID_SHARE";
  case NWEP_ERR_IDENTITY_SHARE_COMBINE:
    return "IDENTITY_SHARE_COMBINE";
  case NWEP_ERR_IDENTITY_INVALID_THRESHOLD:
    return "IDENTITY_INVALID_THRESHOLD";
  /* Fatal identity errors */
  case NWEP_ERR_IDENTITY_KEY_MISMATCH:
    return "IDENTITY_KEY_MISMATCH";
  case NWEP_ERR_IDENTITY_REVOKED:
    return "IDENTITY_REVOKED";

  /* Storage errors (-6xx) */
  case NWEP_ERR_STORAGE_FILE_NOT_FOUND:
    return "STORAGE_FILE_NOT_FOUND";
  case NWEP_ERR_STORAGE_READ_ERROR:
    return "STORAGE_READ_ERROR";
  case NWEP_ERR_STORAGE_WRITE_ERROR:
    return "STORAGE_WRITE_ERROR";
  case NWEP_ERR_STORAGE_PERMISSION:
    return "STORAGE_PERMISSION";
  case NWEP_ERR_STORAGE_DISK_FULL:
    return "STORAGE_DISK_FULL";
  /* Fatal storage errors */
  case NWEP_ERR_STORAGE_CORRUPTED:
    return "STORAGE_CORRUPTED";

  /* Trust errors (-7xx) */
  case NWEP_ERR_TRUST_PARSE_ERROR:
    return "TRUST_PARSE_ERROR";
  case NWEP_ERR_TRUST_INVALID_ENTRY:
    return "TRUST_INVALID_ENTRY";
  case NWEP_ERR_TRUST_INVALID_SIG:
    return "TRUST_INVALID_SIG";
  case NWEP_ERR_TRUST_QUORUM_NOT_REACHED:
    return "TRUST_QUORUM_NOT_REACHED";
  case NWEP_ERR_TRUST_INVALID_PROOF:
    return "TRUST_INVALID_PROOF";
  case NWEP_ERR_TRUST_ENTRY_NOT_FOUND:
    return "TRUST_ENTRY_NOT_FOUND";
  case NWEP_ERR_TRUST_CHECKPOINT_STALE:
    return "TRUST_CHECKPOINT_STALE";
  case NWEP_ERR_TRUST_ANCHOR_UNKNOWN:
    return "TRUST_ANCHOR_UNKNOWN";
  case NWEP_ERR_TRUST_DUPLICATE_BINDING:
    return "TRUST_DUPLICATE_BINDING";
  case NWEP_ERR_TRUST_NODE_NOT_FOUND:
    return "TRUST_NODE_NOT_FOUND";
  case NWEP_ERR_TRUST_ALREADY_REVOKED:
    return "TRUST_ALREADY_REVOKED";
  case NWEP_ERR_TRUST_INVALID_AUTH:
    return "TRUST_INVALID_AUTH";
  case NWEP_ERR_TRUST_UNAUTHORIZED:
    return "TRUST_UNAUTHORIZED";
  case NWEP_ERR_TRUST_TYPE_NOT_ALLOWED:
    return "TRUST_TYPE_NOT_ALLOWED";
  case NWEP_ERR_TRUST_KEY_MISMATCH:
    return "TRUST_KEY_MISMATCH";
  case NWEP_ERR_TRUST_STORAGE:
    return "TRUST_STORAGE";
  /* Fatal trust errors */
  case NWEP_ERR_TRUST_LOG_CORRUPTED:
    return "TRUST_LOG_CORRUPTED";
  case NWEP_ERR_TRUST_EQUIVOCATION:
    return "TRUST_EQUIVOCATION";

  /* Internal errors (-8xx) */
  case NWEP_ERR_INTERNAL_UNKNOWN:
    return "INTERNAL_UNKNOWN";
  case NWEP_ERR_INTERNAL_NOT_IMPLEMENTED:
    return "INTERNAL_NOT_IMPLEMENTED";
  case NWEP_ERR_INTERNAL_INVALID_STATE:
    return "INTERNAL_INVALID_STATE";
  case NWEP_ERR_INTERNAL_NULL_PTR:
    return "INTERNAL_NULL_PTR";
  case NWEP_ERR_INTERNAL_NOMEM:
    return "INTERNAL_NOMEM";
  case NWEP_ERR_INTERNAL_INVALID_ARG:
    return "INTERNAL_INVALID_ARG";
  case NWEP_ERR_INTERNAL_CALLBACK_FAILURE:
    return "INTERNAL_CALLBACK_FAILURE";
  case NWEP_ERR_INTERNAL_NOBUF:
    return "INTERNAL_NOBUF";

  default:
    return "(unknown)";
  }
}

int nwep_err_is_fatal(int liberr) {
  int code_in_category;

  if (liberr >= 0) {
    return 0;
  }

  /* Extract the code within the category (last two digits) */
  code_in_category = (-liberr) % 100;

  /* Fatal errors are those ending in 81-99 */
  return code_in_category >= NWEP_ERR_FATAL_THRESHOLD;
}

nwep_error_category nwep_err_category(int liberr) {
  int category;

  if (liberr >= 0) {
    return NWEP_ERR_CAT_NONE;
  }

  /* Extract category from error code: -1xx = 1, -2xx = 2, etc. */
  category = (-liberr) / 100;

  if (category < NWEP_ERR_CAT_CONFIG || category > NWEP_ERR_CAT_INTERNAL) {
    return NWEP_ERR_CAT_NONE;
  }

  return (nwep_error_category)category;
}

const char *nwep_err_category_str(nwep_error_category cat) {
  switch (cat) {
  case NWEP_ERR_CAT_NONE:
    return "none";
  case NWEP_ERR_CAT_CONFIG:
    return "config";
  case NWEP_ERR_CAT_NETWORK:
    return "network";
  case NWEP_ERR_CAT_CRYPTO:
    return "crypto";
  case NWEP_ERR_CAT_PROTOCOL:
    return "protocol";
  case NWEP_ERR_CAT_IDENTITY:
    return "identity";
  case NWEP_ERR_CAT_STORAGE:
    return "storage";
  case NWEP_ERR_CAT_TRUST:
    return "trust";
  case NWEP_ERR_CAT_INTERNAL:
    return "internal";
  default:
    return "unknown";
  }
}

const char *nwep_err_to_status(int liberr) {
  nwep_error_category cat;

  if (liberr == 0) {
    return NWEP_STATUS_OK;
  }

  cat = nwep_err_category(liberr);

  switch (cat) {
  case NWEP_ERR_CAT_NONE:
    return NWEP_STATUS_INTERNAL_ERROR;

  case NWEP_ERR_CAT_CONFIG:
    return NWEP_STATUS_BAD_REQUEST;

  case NWEP_ERR_CAT_NETWORK:
    if (liberr == NWEP_ERR_NETWORK_TIMEOUT) {
      return NWEP_STATUS_UNAVAILABLE;
    }
    return NWEP_STATUS_INTERNAL_ERROR;

  case NWEP_ERR_CAT_CRYPTO:
    /* Fatal crypto errors indicate authentication failure */
    if (nwep_err_is_fatal(liberr)) {
      return NWEP_STATUS_UNAUTHORIZED;
    }
    return NWEP_STATUS_INTERNAL_ERROR;

  case NWEP_ERR_CAT_PROTOCOL:
    if (liberr == NWEP_ERR_PROTO_CONNECT_REQUIRED) {
      return NWEP_STATUS_UNAUTHORIZED;
    }
    return NWEP_STATUS_BAD_REQUEST;

  case NWEP_ERR_CAT_IDENTITY:
    if (liberr == NWEP_ERR_IDENTITY_AUTH_FAILED ||
        liberr == NWEP_ERR_IDENTITY_KEY_MISMATCH) {
      return NWEP_STATUS_UNAUTHORIZED;
    }
    if (liberr == NWEP_ERR_IDENTITY_REVOKED) {
      return NWEP_STATUS_FORBIDDEN;
    }
    return NWEP_STATUS_BAD_REQUEST;

  case NWEP_ERR_CAT_STORAGE:
    if (liberr == NWEP_ERR_STORAGE_FILE_NOT_FOUND) {
      return NWEP_STATUS_NOT_FOUND;
    }
    if (liberr == NWEP_ERR_STORAGE_PERMISSION) {
      return NWEP_STATUS_FORBIDDEN;
    }
    return NWEP_STATUS_INTERNAL_ERROR;

  case NWEP_ERR_CAT_TRUST:
    if (liberr == NWEP_ERR_TRUST_ENTRY_NOT_FOUND ||
        liberr == NWEP_ERR_TRUST_NODE_NOT_FOUND) {
      return NWEP_STATUS_NOT_FOUND;
    }
    if (liberr == NWEP_ERR_TRUST_UNAUTHORIZED) {
      return NWEP_STATUS_UNAUTHORIZED;
    }
    if (liberr == NWEP_ERR_TRUST_TYPE_NOT_ALLOWED) {
      return NWEP_STATUS_FORBIDDEN;
    }
    if (liberr == NWEP_ERR_TRUST_DUPLICATE_BINDING) {
      return NWEP_STATUS_CONFLICT;
    }
    /* Fatal trust errors are severe */
    if (nwep_err_is_fatal(liberr)) {
      return NWEP_STATUS_INTERNAL_ERROR;
    }
    return NWEP_STATUS_BAD_REQUEST;

  case NWEP_ERR_CAT_INTERNAL:
    return NWEP_STATUS_INTERNAL_ERROR;

  default:
    return NWEP_STATUS_INTERNAL_ERROR;
  }
}

void nwep_error_init(nwep_error *err, int code) {
  if (err == NULL) {
    return;
  }
  err->code = code;
  err->context_count = 0;
  memset(err->context, 0, sizeof(err->context));
}

nwep_error *nwep_error_set_context(nwep_error *err, const char *context) {
  size_t i;

  if (err == NULL || context == NULL) {
    return err;
  }

  if (err->context_count >= NWEP_ERR_CONTEXT_MAX) {
    /* Shift contexts down, dropping the oldest */
    for (i = NWEP_ERR_CONTEXT_MAX - 1; i > 0; --i) {
      err->context[i] = err->context[i - 1];
    }
    err->context[0] = context;
  } else {
    /* Shift existing contexts and insert at front */
    for (i = err->context_count; i > 0; --i) {
      err->context[i] = err->context[i - 1];
    }
    err->context[0] = context;
    err->context_count++;
  }

  return err;
}

size_t nwep_error_format(const nwep_error *err, char *buf, size_t buflen) {
  size_t written = 0;
  size_t i;
  int rv;
  nwep_error_category cat;
  const char *cat_str;
  const char *err_str;

  if (err == NULL) {
    if (buf != NULL && buflen > 0) {
      buf[0] = '\0';
    }
    return 0;
  }

  cat = nwep_err_category(err->code);
  cat_str = nwep_err_category_str(cat);
  err_str = nwep_strerror(err->code);

  /* Format: [category:code] error_string */
  if (buf != NULL && buflen > 0) {
    rv = snprintf(buf + written, buflen - written, "[%s:%d] %s", cat_str,
                  err->code, err_str);
  } else {
    rv = snprintf(NULL, 0, "[%s:%d] %s", cat_str, err->code, err_str);
  }

  if (rv < 0) {
    return written;
  }

  written += (size_t)rv;

  /* Add context chain */
  for (i = 0; i < err->context_count; ++i) {
    if (buf != NULL && written < buflen) {
      rv = snprintf(buf + written, buflen - written, "\n  caused by: %s",
                    err->context[i]);
    } else {
      rv = snprintf(NULL, 0, "\n  caused by: %s", err->context[i]);
    }

    if (rv < 0) {
      break;
    }

    written += (size_t)rv;
  }

  /* Null terminate if we have space */
  if (buf != NULL && written < buflen) {
    buf[written] = '\0';
  } else if (buf != NULL && buflen > 0) {
    buf[buflen - 1] = '\0';
  }

  return written;
}
