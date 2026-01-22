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
#ifndef NWEP_H
#define NWEP_H

/* Define WIN32 when build target is Win32 API (borrowed from libcurl) */
#if (defined(_WIN32) || defined(__WIN32__)) && !defined(WIN32)
#  define WIN32
#endif /* (defined(_WIN32) || defined(__WIN32__)) && !defined(WIN32) */

#include <stdlib.h>
#if defined(_MSC_VER) && (_MSC_VER < 1800)
#  include <stdint.h>
#else
#  include <inttypes.h>
#endif
#include <sys/types.h>
#include <stddef.h>

#ifndef NWEP_USE_GENERIC_SOCKADDR
#  ifdef WIN32
#    ifndef WIN32_LEAN_AND_MEAN
#      define WIN32_LEAN_AND_MEAN
#    endif
#    include <ws2tcpip.h>
#  else
#    include <sys/socket.h>
#    include <netinet/in.h>
#  endif
#endif

#include <nwep/version.h>

#ifdef NWEP_STATICLIB
#  define NWEP_EXTERN
#elif defined(WIN32)
#  ifdef BUILDING_NWEP
#    define NWEP_EXTERN __declspec(dllexport)
#  else
#    define NWEP_EXTERN __declspec(dllimport)
#  endif
#else
#  ifdef BUILDING_NWEP
#    define NWEP_EXTERN __attribute__((visibility("default")))
#  else
#    define NWEP_EXTERN
#  endif
#endif

#ifdef _MSC_VER
#  define NWEP_ALIGN(N) __declspec(align(N))
#else
#  define NWEP_ALIGN(N) __attribute__((aligned(N)))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @typedef
 *
 * :type:`nwep_ssize` is signed counterpart of size_t.
 */
typedef ptrdiff_t nwep_ssize;

/**
 * @typedef
 *
 * :type:`nwep_tstamp` is a timestamp in nanoseconds.
 */
typedef uint64_t nwep_tstamp;

/**
 * @typedef
 *
 * :type:`nwep_duration` is a duration in nanoseconds.
 */
typedef uint64_t nwep_duration;

/**
 * @macrosection
 *
 * Time conversion macros
 *
 * These macros convert human-readable time units to nanoseconds
 * for use with :type:`nwep_tstamp` and :type:`nwep_duration`.
 */

/**
 * @macro
 *
 * :macro:`NWEP_NANOSECONDS` is a count of ticks which corresponds to
 * 1 nanosecond.
 */
#define NWEP_NANOSECONDS ((nwep_duration)1ULL)

/**
 * @macro
 *
 * :macro:`NWEP_MICROSECONDS` is a count of ticks which corresponds to
 * 1 microsecond.
 */
#define NWEP_MICROSECONDS ((nwep_duration)(1000ULL * NWEP_NANOSECONDS))

/**
 * @macro
 *
 * :macro:`NWEP_MILLISECONDS` is a count of ticks which corresponds to
 * 1 millisecond.
 */
#define NWEP_MILLISECONDS ((nwep_duration)(1000ULL * NWEP_MICROSECONDS))

/**
 * @macro
 *
 * :macro:`NWEP_SECONDS` is a count of ticks which corresponds to 1 second.
 */
#define NWEP_SECONDS ((nwep_duration)(1000ULL * NWEP_MILLISECONDS))

/**
 * @macrosection
 *
 * Protocol version and identification
 *
 * These macros define WEB/1 protocol identification strings used
 * during TLS negotiation and protocol version checks.
 */

/**
 * @macro
 *
 * :macro:`NWEP_PROTO_VER` is the WEB/1 protocol version string.
 */
#define NWEP_PROTO_VER "WEB/1"

/**
 * @macro
 *
 * :macro:`NWEP_ALPN` is the ALPN identifier for WEB/1.
 */
#define NWEP_ALPN "WEB/1"

/**
 * @macro
 *
 * :macro:`NWEP_ALPN_LEN` is the length of :macro:`NWEP_ALPN`.
 */
#define NWEP_ALPN_LEN 5

/**
 * @macro
 *
 * :macro:`NWEP_DEFAULT_PORT` is the default port for WEB/1.
 */
#define NWEP_DEFAULT_PORT 4433

/**
 * @macrosection
 *
 * Protocol limits
 *
 * Default limits for message size, headers, and streams.
 * These can be overridden via :type:`nwep_settings`.
 */

/**
 * @macro
 *
 * :macro:`NWEP_DEFAULT_MAX_MESSAGE_SIZE` is the default maximum message
 * size (24MB).
 */
#define NWEP_DEFAULT_MAX_MESSAGE_SIZE ((size_t)25165824)

/**
 * @macro
 *
 * :macro:`NWEP_MAX_HEADERS` is the maximum number of headers per message.
 */
#define NWEP_MAX_HEADERS 128

/**
 * @macro
 *
 * :macro:`NWEP_MAX_HEADER_SIZE` is the maximum size of a single header (8KB).
 */
#define NWEP_MAX_HEADER_SIZE ((size_t)8192)

/**
 * @macro
 *
 * :macro:`NWEP_DEFAULT_MAX_STREAMS` is the default maximum concurrent streams.
 */
#define NWEP_DEFAULT_MAX_STREAMS 100

/**
 * @macro
 *
 * :macro:`NWEP_DEFAULT_TIMEOUT` is the default timeout in nanoseconds
 * (30 seconds).
 */
#define NWEP_DEFAULT_TIMEOUT (30ULL * NWEP_SECONDS)

/**
 * @macrosection
 *
 * Cryptographic constant sizes
 *
 * Buffer sizes for Ed25519 keys, signatures, NodeIDs, and protocol nonces.
 */

/**
 * @macro
 *
 * :macro:`NWEP_ED25519_PUBKEY_LEN` is the length of an Ed25519 public key.
 */
#define NWEP_ED25519_PUBKEY_LEN 32

/**
 * @macro
 *
 * :macro:`NWEP_ED25519_PRIVKEY_LEN` is the length of an Ed25519 private key.
 */
#define NWEP_ED25519_PRIVKEY_LEN 32

/**
 * @macro
 *
 * :macro:`NWEP_ED25519_SIG_LEN` is the length of an Ed25519 signature.
 */
#define NWEP_ED25519_SIG_LEN 64

/**
 * @macro
 *
 * :macro:`NWEP_NODEID_LEN` is the length of a NodeID (SHA-256 hash).
 */
#define NWEP_NODEID_LEN 32

/**
 * @macro
 *
 * :macro:`NWEP_CHALLENGE_LEN` is the length of a challenge nonce.
 */
#define NWEP_CHALLENGE_LEN 32

/**
 * @macro
 *
 * :macro:`NWEP_REQUEST_ID_LEN` is the length of a request ID.
 */
#define NWEP_REQUEST_ID_LEN 16

/**
 * @macro
 *
 * :macro:`NWEP_TRACE_ID_LEN` is the length of a trace ID.
 */
#define NWEP_TRACE_ID_LEN 16

/**
 * @macrosection
 *
 * Message types
 *
 * Wire format message type field values. Used in :member:`nwep_msg.type`.
 */

/**
 * @macro
 *
 * :macro:`NWEP_MSG_REQUEST` is the message type for requests.
 */
#define NWEP_MSG_REQUEST 0

/**
 * @macro
 *
 * :macro:`NWEP_MSG_RESPONSE` is the message type for responses.
 */
#define NWEP_MSG_RESPONSE 1

/**
 * @macro
 *
 * :macro:`NWEP_MSG_STREAM` is the message type for streaming data.
 */
#define NWEP_MSG_STREAM 2

/**
 * @macro
 *
 * :macro:`NWEP_MSG_NOTIFY` is the message type for server-initiated notifications.
 */
#define NWEP_MSG_NOTIFY 3

/**
 * @macrosection
 *
 * Request methods
 *
 * WEB/1 method strings for the :header:`:method` pseudo-header.
 */

/**
 * @macro
 *
 * :macro:`NWEP_METHOD_READ` is the READ method (idempotent, 0-RTT allowed).
 */
#define NWEP_METHOD_READ "read"

/**
 * @macro
 *
 * :macro:`NWEP_METHOD_WRITE` is the WRITE method (create resource).
 */
#define NWEP_METHOD_WRITE "write"

/**
 * @macro
 *
 * :macro:`NWEP_METHOD_UPDATE` is the UPDATE method (modify resource).
 */
#define NWEP_METHOD_UPDATE "update"

/**
 * @macro
 *
 * :macro:`NWEP_METHOD_DELETE` is the DELETE method (idempotent).
 */
#define NWEP_METHOD_DELETE "delete"

/**
 * @macro
 *
 * :macro:`NWEP_METHOD_CONNECT` is the CONNECT method (handshake).
 */
#define NWEP_METHOD_CONNECT "connect"

/**
 * @macro
 *
 * :macro:`NWEP_METHOD_AUTHENTICATE` is the AUTHENTICATE method (handshake).
 */
#define NWEP_METHOD_AUTHENTICATE "authenticate"

/**
 * @macro
 *
 * :macro:`NWEP_METHOD_HEARTBEAT` is the HEARTBEAT method (keepalive).
 */
#define NWEP_METHOD_HEARTBEAT "heartbeat"

/**
 * @macrosection
 *
 * Status tokens
 *
 * WEB/1 response status strings for the :header:`:status` pseudo-header.
 * Use :func:`nwep_status_is_success` and :func:`nwep_status_is_error` to
 * classify status values.
 */

#define NWEP_STATUS_OK "ok"
#define NWEP_STATUS_CREATED "created"
#define NWEP_STATUS_ACCEPTED "accepted"
#define NWEP_STATUS_NO_CONTENT "no_content"
#define NWEP_STATUS_BAD_REQUEST "bad_request"
#define NWEP_STATUS_UNAUTHORIZED "unauthorized"
#define NWEP_STATUS_FORBIDDEN "forbidden"
#define NWEP_STATUS_NOT_FOUND "not_found"
#define NWEP_STATUS_CONFLICT "conflict"
#define NWEP_STATUS_RATE_LIMITED "rate_limited"
#define NWEP_STATUS_INTERNAL_ERROR "internal_error"
#define NWEP_STATUS_UNAVAILABLE "unavailable"

/**
 * @macrosection
 *
 * Error codes and categories
 *
 * nwep functions return 0 on success or a negative error code on failure.
 * Error codes are organized by category:
 * - Config errors (-1xx): Configuration and settings
 * - Network errors (-2xx): Connection and socket
 * - Crypto errors (-3xx): Cryptographic operations
 * - Protocol errors (-4xx): Message format and protocol
 * - Identity errors (-5xx): NodeID and authentication
 * - Storage errors (-6xx): File and data persistence
 * - Trust errors (-7xx): Merkle log and checkpoints
 * - Internal errors (-8xx): Library state and memory
 *
 * Errors ending in 81-99 are fatal and require connection termination.
 * Use :func:`nwep_err_is_fatal` to check and :func:`nwep_strerror` for messages.
 */

/**
 * @enum
 *
 * :type:`nwep_error_category` defines the error category values.
 */
typedef enum nwep_error_category {
  NWEP_ERR_CAT_NONE = 0,
  NWEP_ERR_CAT_CONFIG = 1,
  NWEP_ERR_CAT_NETWORK = 2,
  NWEP_ERR_CAT_CRYPTO = 3,
  NWEP_ERR_CAT_PROTOCOL = 4,
  NWEP_ERR_CAT_IDENTITY = 5,
  NWEP_ERR_CAT_STORAGE = 6,
  NWEP_ERR_CAT_TRUST = 7,
  NWEP_ERR_CAT_INTERNAL = 8
} nwep_error_category;

/* Config errors (-1xx) */
#define NWEP_ERR_CONFIG_FILE_NOT_FOUND     -101
#define NWEP_ERR_CONFIG_PARSE_ERROR        -102
#define NWEP_ERR_CONFIG_INVALID_VALUE      -103
#define NWEP_ERR_CONFIG_MISSING_REQUIRED   -104
#define NWEP_ERR_CONFIG_VALIDATION_FAILED  -105

/* Network errors (-2xx) */
#define NWEP_ERR_NETWORK_CONN_FAILED       -201
#define NWEP_ERR_NETWORK_CONN_CLOSED       -202
#define NWEP_ERR_NETWORK_TIMEOUT           -203
#define NWEP_ERR_NETWORK_ADDR_IN_USE       -204
#define NWEP_ERR_NETWORK_ADDR_INVALID      -205
#define NWEP_ERR_NETWORK_SOCKET            -206
#define NWEP_ERR_NETWORK_TLS               -207
#define NWEP_ERR_NETWORK_QUIC              -208
#define NWEP_ERR_NETWORK_NO_SERVERS        -209

/* Crypto errors (-3xx) */
#define NWEP_ERR_CRYPTO_KEY_GEN_FAILED     -301
#define NWEP_ERR_CRYPTO_SIGN_FAILED        -302
#define NWEP_ERR_CRYPTO_VERIFY_FAILED      -303
#define NWEP_ERR_CRYPTO_HASH_FAILED        -304
#define NWEP_ERR_CRYPTO_INVALID_KEY        -305
#define NWEP_ERR_CRYPTO_INVALID_SIG        -306
#define NWEP_ERR_CRYPTO_ENCRYPT_FAILED     -307
#define NWEP_ERR_CRYPTO_DECRYPT_FAILED     -308
#define NWEP_ERR_CRYPTO_KEY_LOAD_FAILED    -309
#define NWEP_ERR_CRYPTO_KEY_SAVE_FAILED    -310
#define NWEP_ERR_CRYPTO_CERT_ERROR         -311
/* Fatal crypto errors */
#define NWEP_ERR_CRYPTO_PUBKEY_MISMATCH    -381  /* Layer 1 failed */
#define NWEP_ERR_CRYPTO_NODEID_MISMATCH    -382  /* Layer 2 failed - MITM? */
#define NWEP_ERR_CRYPTO_CHALLENGE_FAILED   -383  /* Layer 3 failed */
#define NWEP_ERR_CRYPTO_SERVER_SIG_INVALID -384
#define NWEP_ERR_CRYPTO_CLIENT_SIG_INVALID -385
#define NWEP_ERR_CRYPTO_AUTH_TIMEOUT       -320

/* Protocol errors (-4xx) */
#define NWEP_ERR_PROTO_INVALID_MESSAGE     -401
#define NWEP_ERR_PROTO_INVALID_METHOD      -402
#define NWEP_ERR_PROTO_INVALID_HEADER      -403
#define NWEP_ERR_PROTO_MSG_TOO_LARGE       -404
#define NWEP_ERR_PROTO_STREAM_ERROR        -405
#define NWEP_ERR_PROTO_INVALID_STATUS      -406
#define NWEP_ERR_PROTO_CONNECT_REQUIRED    -407
#define NWEP_ERR_PROTO_TOO_MANY_HEADERS    -408
#define NWEP_ERR_PROTO_HEADER_TOO_LARGE    -409
#define NWEP_ERR_PROTO_0RTT_REJECTED       -410
#define NWEP_ERR_PROTO_MISSING_HEADER      -411
#define NWEP_ERR_PROTO_ROLE_MISMATCH       -412
#define NWEP_ERR_PROTO_UNAUTHORIZED        -413
#define NWEP_ERR_PROTO_PATH_NOT_FOUND      -414
/* Fatal protocol errors */
#define NWEP_ERR_PROTO_VERSION_MISMATCH    -481

/* Identity errors (-5xx) */
#define NWEP_ERR_IDENTITY_INVALID_NODEID   -501
#define NWEP_ERR_IDENTITY_INVALID_ADDR     -502
#define NWEP_ERR_IDENTITY_AUTH_FAILED      -503
#define NWEP_ERR_IDENTITY_CHALLENGE_EXPIRED -504
#define NWEP_ERR_IDENTITY_NO_RECOVERY      -505
#define NWEP_ERR_IDENTITY_RECOVERY_MISMATCH -506
#define NWEP_ERR_IDENTITY_INVALID_SHARE    -507
#define NWEP_ERR_IDENTITY_SHARE_COMBINE    -508
#define NWEP_ERR_IDENTITY_INVALID_THRESHOLD -509
#define NWEP_ERR_IDENTITY_ROTATION_IN_PROGRESS -510
/* Fatal identity errors */
#define NWEP_ERR_IDENTITY_KEY_MISMATCH     -581
#define NWEP_ERR_IDENTITY_REVOKED          -582

/* Storage errors (-6xx) */
#define NWEP_ERR_STORAGE_FILE_NOT_FOUND    -601
#define NWEP_ERR_STORAGE_READ_ERROR        -602
#define NWEP_ERR_STORAGE_WRITE_ERROR       -603
#define NWEP_ERR_STORAGE_PERMISSION        -604
#define NWEP_ERR_STORAGE_DISK_FULL         -605
#define NWEP_ERR_STORAGE_KEY_NOT_FOUND     -606
#define NWEP_ERR_STORAGE_INDEX_OUT_OF_RANGE -607
/* Fatal storage errors */
#define NWEP_ERR_STORAGE_CORRUPTED         -681

/* Trust errors (-7xx) */
#define NWEP_ERR_TRUST_PARSE_ERROR         -701
#define NWEP_ERR_TRUST_INVALID_ENTRY       -702
#define NWEP_ERR_TRUST_INVALID_SIG         -703
#define NWEP_ERR_TRUST_QUORUM_NOT_REACHED  -704
#define NWEP_ERR_TRUST_INVALID_PROOF       -705
#define NWEP_ERR_TRUST_ENTRY_NOT_FOUND     -706
#define NWEP_ERR_TRUST_CHECKPOINT_STALE    -708
#define NWEP_ERR_TRUST_ANCHOR_UNKNOWN      -709
#define NWEP_ERR_TRUST_DUPLICATE_BINDING   -711
#define NWEP_ERR_TRUST_NODE_NOT_FOUND      -712
#define NWEP_ERR_TRUST_ALREADY_REVOKED     -713
#define NWEP_ERR_TRUST_INVALID_AUTH        -714
#define NWEP_ERR_TRUST_UNAUTHORIZED        -715
#define NWEP_ERR_TRUST_TYPE_NOT_ALLOWED    -716
#define NWEP_ERR_TRUST_KEY_MISMATCH        -717
#define NWEP_ERR_TRUST_STORAGE             -718
/* Fatal trust errors */
#define NWEP_ERR_TRUST_LOG_CORRUPTED       -781
#define NWEP_ERR_TRUST_EQUIVOCATION        -782

/* Internal errors (-8xx) */
#define NWEP_ERR_INTERNAL_UNKNOWN          -801
#define NWEP_ERR_INTERNAL_NOT_IMPLEMENTED  -802
#define NWEP_ERR_INTERNAL_INVALID_STATE    -803
#define NWEP_ERR_INTERNAL_NULL_PTR         -804
#define NWEP_ERR_INTERNAL_NOMEM            -805
#define NWEP_ERR_INTERNAL_INVALID_ARG      -806
#define NWEP_ERR_INTERNAL_CALLBACK_FAILURE -807
#define NWEP_ERR_INTERNAL_NOBUF            -808

/**
 * @macro
 *
 * :macro:`NWEP_ERR_FATAL_THRESHOLD` marks the boundary for fatal errors
 * within each category. Errors ending in 81-99 are fatal.
 */
#define NWEP_ERR_FATAL_THRESHOLD 80

/**
 * @macro
 *
 * :macro:`NWEP_ERR_CONTEXT_MAX` is the maximum depth of error context chain.
 */
#define NWEP_ERR_CONTEXT_MAX 8

/**
 * @struct
 *
 * :type:`nwep_error` represents an error with context chain for debugging.
 */
typedef struct nwep_error {
  /**
   * :member:`code` is the error code.
   */
  int code;
  /**
   * :member:`context` is an array of context strings (most recent first).
   */
  const char *context[NWEP_ERR_CONTEXT_MAX];
  /**
   * :member:`context_count` is the number of context entries.
   */
  size_t context_count;
} nwep_error;

/**
 * @functypedef
 *
 * :type:`nwep_malloc` is a custom memory allocator to replace malloc(3).
 */
typedef void *(*nwep_malloc)(size_t size, void *user_data);

/**
 * @functypedef
 *
 * :type:`nwep_free` is a custom memory allocator to replace free(3).
 */
typedef void (*nwep_free)(void *ptr, void *user_data);

/**
 * @functypedef
 *
 * :type:`nwep_calloc` is a custom memory allocator to replace calloc(3).
 */
typedef void *(*nwep_calloc)(size_t nmemb, size_t size, void *user_data);

/**
 * @functypedef
 *
 * :type:`nwep_realloc` is a custom memory allocator to replace realloc(3).
 */
typedef void *(*nwep_realloc)(void *ptr, size_t size, void *user_data);

/**
 * @struct
 *
 * :type:`nwep_mem` is a custom memory allocator.
 */
typedef struct nwep_mem {
  /**
   * :member:`user_data` is an arbitrary user supplied data passed to each
   * allocator function.
   */
  void *user_data;
  /**
   * :member:`malloc` is a custom allocator function to replace malloc(3).
   */
  nwep_malloc malloc;
  /**
   * :member:`free` is a custom allocator function to replace free(3).
   */
  nwep_free free;
  /**
   * :member:`calloc` is a custom allocator function to replace calloc(3).
   */
  nwep_calloc calloc;
  /**
   * :member:`realloc` is a custom allocator function to replace realloc(3).
   */
  nwep_realloc realloc;
} nwep_mem;

/**
 * @struct
 *
 * :type:`nwep_vec` is a buffer with a pointer and length.
 */
typedef struct nwep_vec {
  /**
   * :member:`base` points to the buffer.
   */
  uint8_t *base;
  /**
   * :member:`len` is the length of the buffer.
   */
  size_t len;
} nwep_vec;

/**
 * @struct
 *
 * :type:`nwep_nodeid` is a 32-byte NodeID.
 */
typedef struct nwep_nodeid {
  /**
   * :member:`data` contains the NodeID bytes.
   */
  uint8_t data[NWEP_NODEID_LEN];
} nwep_nodeid;

/**
 * @function
 *
 * `nwep_version` returns the version string of the nwep library.
 */
NWEP_EXTERN const char *nwep_version(void);

/**
 * @function
 *
 * `nwep_strerror` returns the error string for the given error code |liberr|.
 */
NWEP_EXTERN const char *nwep_strerror(int liberr);

/**
 * @function
 *
 * `nwep_err_is_fatal` returns nonzero if |liberr| is a fatal error that
 * requires immediate connection termination. Fatal errors are those with
 * codes ending in 81-99 within their category.
 */
NWEP_EXTERN int nwep_err_is_fatal(int liberr);

/**
 * @function
 *
 * `nwep_err_category` returns the error category for the given error code.
 * Returns :enum:`NWEP_ERR_CAT_NONE` for success (0) or unknown errors.
 */
NWEP_EXTERN nwep_error_category nwep_err_category(int liberr);

/**
 * @function
 *
 * `nwep_err_category_str` returns the category name string for the given
 * category.
 */
NWEP_EXTERN const char *nwep_err_category_str(nwep_error_category cat);

/**
 * @function
 *
 * `nwep_err_to_status` returns the WEB/1 status token string appropriate
 * for the given error code. This is used when generating error responses.
 */
NWEP_EXTERN const char *nwep_err_to_status(int liberr);

/**
 * @function
 *
 * `nwep_error_init` initializes an error struct with the given code.
 */
NWEP_EXTERN void nwep_error_init(nwep_error *err, int code);

/**
 * @function
 *
 * `nwep_error_set_context` adds a context string to the error. Context
 * strings are stored most-recent-first, up to :macro:`NWEP_ERR_CONTEXT_MAX`.
 * Returns the error struct for chaining.
 */
NWEP_EXTERN nwep_error *nwep_error_set_context(nwep_error *err,
                                                const char *context);

/**
 * @function
 *
 * `nwep_error_format` formats the error with its context chain into a
 * human-readable string. The format is:
 *   [category:code] context1
 *     caused by: context2
 *     caused by: context3
 *
 * |buf| is the buffer to write to, |buflen| is the buffer size.
 * Returns the number of bytes written (excluding null terminator), or
 * the number of bytes that would have been written if the buffer was
 * large enough.
 */
NWEP_EXTERN size_t nwep_error_format(const nwep_error *err, char *buf,
                                      size_t buflen);

/**
 * @macrosection
 *
 * Base58 encoding
 *
 * Functions for encoding and decoding binary data to/from Base58.
 * Used for WEB/1 addresses in URLs.
 */

/**
 * @macro
 *
 * :macro:`NWEP_BASE58_ADDR_LEN` is the maximum length of a Base58-encoded
 * address (48 raw bytes = IPv6 + NodeID).
 */
#define NWEP_BASE58_ADDR_LEN 66

/**
 * @function
 *
 * `nwep_base58_encode` encodes |srclen| bytes from |src| into Base58.
 * |dest| must have space for at least |destlen| bytes. The output is
 * null-terminated.
 *
 * Returns the number of characters written (excluding null terminator),
 * or 0 on error.
 */
NWEP_EXTERN size_t nwep_base58_encode(char *dest, size_t destlen,
                                       const uint8_t *src, size_t srclen);

/**
 * @function
 *
 * `nwep_base58_decode` decodes Base58 string |src| into |dest|.
 * |dest| must have space for at least |destlen| bytes.
 *
 * Returns the number of bytes written, or 0 on error.
 */
NWEP_EXTERN size_t nwep_base58_decode(uint8_t *dest, size_t destlen,
                                       const char *src);

/**
 * @function
 *
 * `nwep_base58_encode_len` returns the buffer size needed to encode
 * |srclen| bytes as Base58 (including null terminator).
 */
NWEP_EXTERN size_t nwep_base58_encode_len(size_t srclen);

/**
 * @function
 *
 * `nwep_base58_decode_len` returns the maximum buffer size needed to
 * decode a Base58 string of |srclen| characters.
 */
NWEP_EXTERN size_t nwep_base58_decode_len(size_t srclen);

/**
 * @macrosection
 *
 * Ed25519 key management
 *
 * Types and functions for managing Ed25519 keypairs used for identity
 * authentication and message signing.
 */

/**
 * @struct
 *
 * :type:`nwep_keypair` holds an Ed25519 keypair. The private key is stored
 * in a form suitable for signing operations.
 */
typedef struct nwep_keypair {
  /**
   * :member:`pubkey` is the 32-byte public key.
   */
  uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN];
  /**
   * :member:`privkey` is the 64-byte expanded private key (seed + pubkey).
   */
  uint8_t privkey[64];
} nwep_keypair;

/**
 * @function
 *
 * `nwep_keypair_generate` generates a new Ed25519 keypair using the
 * system's secure random number generator.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_keypair_generate(nwep_keypair *kp);

/**
 * @function
 *
 * `nwep_keypair_from_seed` derives an Ed25519 keypair from a 32-byte seed.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_keypair_from_seed(nwep_keypair *kp,
                                        const uint8_t seed[32]);

/**
 * @function
 *
 * `nwep_keypair_from_privkey` loads a keypair from a 64-byte private key
 * (as returned by OpenSSL's Ed25519 routines or stored previously).
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_keypair_from_privkey(nwep_keypair *kp,
                                           const uint8_t privkey[64]);

/**
 * @function
 *
 * `nwep_keypair_clear` securely zeros the keypair memory.
 */
NWEP_EXTERN void nwep_keypair_clear(nwep_keypair *kp);

/**
 * @macrosection
 *
 * Shamir secret sharing
 *
 * Split a secret into n shares where any t shares can reconstruct it.
 * Used for secure key backup and recovery.
 */

/**
 * @macro
 *
 * :macro:`NWEP_SHAMIR_MAX_SHARES` is the maximum number of shares.
 */
#define NWEP_SHAMIR_MAX_SHARES 255

/**
 * @macro
 *
 * :macro:`NWEP_SHAMIR_MIN_THRESHOLD` is the minimum threshold.
 */
#define NWEP_SHAMIR_MIN_THRESHOLD 2

/**
 * @struct
 *
 * :type:`nwep_shamir_share` holds a single share of a split secret.
 */
typedef struct nwep_shamir_share {
  uint8_t index;
  uint8_t data[32];
} nwep_shamir_share;

/**
 * @function
 *
 * `nwep_shamir_split` splits a 32-byte secret into n shares with threshold t.
 * Any t shares can reconstruct the original secret.
 *
 * |secret| is the 32-byte secret to split.
 * |shares| is an array of at least n nwep_shamir_share structs.
 * |n| is the total number of shares to create (2-255).
 * |t| is the threshold (2-n).
 *
 * Returns 0 on success, or one of the following negative error codes:
 *
 * :macro:`NWEP_ERR_CRYPTO_INVALID_KEY`
 *     Invalid parameters (n < t, t < 2, n > 255).
 */
NWEP_EXTERN int nwep_shamir_split(const uint8_t secret[32],
                                   nwep_shamir_share *shares, size_t n,
                                   size_t t);

/**
 * @function
 *
 * `nwep_shamir_combine` reconstructs a secret from t or more shares.
 *
 * |secret| receives the reconstructed 32-byte secret.
 * |shares| is an array of at least t shares.
 * |num_shares| is the number of shares provided (must be >= threshold used in split).
 *
 * Returns 0 on success, or one of the following negative error codes:
 *
 * :macro:`NWEP_ERR_CRYPTO_INVALID_KEY`
 *     Invalid parameters or duplicate share indices.
 */
NWEP_EXTERN int nwep_shamir_combine(uint8_t secret[32],
                                     const nwep_shamir_share *shares,
                                     size_t num_shares);

/**
 * @macrosection
 *
 * Recovery authority
 *
 * A separate keypair that can revoke the primary identity key if compromised.
 */

/**
 * @struct
 *
 * :type:`nwep_recovery_authority` holds the recovery authority keypair
 * which can revoke the primary identity key.
 */
typedef struct nwep_recovery_authority {
  nwep_keypair keypair;
  int initialized;
} nwep_recovery_authority;

/**
 * @function
 *
 * `nwep_recovery_authority_new` generates a new recovery authority keypair.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_recovery_authority_new(nwep_recovery_authority *ra);

/**
 * @function
 *
 * `nwep_recovery_authority_from_keypair` initializes a recovery authority
 * from an existing keypair.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_recovery_authority_from_keypair(nwep_recovery_authority *ra,
                                                      const nwep_keypair *kp);

/**
 * @function
 *
 * `nwep_recovery_authority_clear` securely zeros the recovery authority.
 */
NWEP_EXTERN void nwep_recovery_authority_clear(nwep_recovery_authority *ra);

/**
 * @function
 *
 * `nwep_recovery_authority_get_pubkey` returns the public key of the
 * recovery authority.
 *
 * Returns pointer to the 32-byte public key, or NULL if not initialized.
 */
NWEP_EXTERN const uint8_t *nwep_recovery_authority_get_pubkey(
    const nwep_recovery_authority *ra);

/**
 * @macrosection
 *
 * Key rotation and revocation
 *
 * Support for rotating identity keys while maintaining NodeID continuity,
 * and for revoking compromised keys.
 */

/**
 * @macro
 *
 * :macro:`NWEP_KEY_OVERLAP_SECONDS` is the overlap period during key rotation.
 */
#define NWEP_KEY_OVERLAP_SECONDS 300

/**
 * @macro
 *
 * :macro:`NWEP_MAX_ACTIVE_KEYS` is the maximum concurrent active keys.
 */
#define NWEP_MAX_ACTIVE_KEYS 2

/**
 * @struct
 *
 * :type:`nwep_timed_keypair` holds a keypair with rotation timestamps.
 */
typedef struct nwep_timed_keypair {
  nwep_keypair keypair;
  nwep_tstamp activated_at;
  nwep_tstamp expires_at;
  int active;
} nwep_timed_keypair;

/**
 * @struct
 *
 * :type:`nwep_revocation` holds a signed revocation record.
 */
typedef struct nwep_revocation {
  nwep_nodeid nodeid;
  nwep_tstamp timestamp;
  uint8_t recovery_pubkey[NWEP_ED25519_PUBKEY_LEN];
  uint8_t signature[NWEP_ED25519_SIG_LEN];
} nwep_revocation;

/**
 * @struct
 *
 * :type:`nwep_managed_identity` holds an identity with key rotation
 * and recovery support.
 */
typedef struct nwep_managed_identity {
  nwep_nodeid nodeid;
  nwep_timed_keypair keys[NWEP_MAX_ACTIVE_KEYS];
  size_t key_count;
  uint8_t recovery_pubkey[NWEP_ED25519_PUBKEY_LEN];
  int has_recovery;
  int revoked;
  nwep_revocation revocation;
} nwep_managed_identity;

/**
 * @function
 *
 * `nwep_managed_identity_new` creates a new managed identity with
 * the given keypair and optional recovery authority.
 *
 * |identity| receives the initialized managed identity.
 * |kp| is the initial keypair.
 * |ra| is the recovery authority (may be NULL for no recovery support).
 * |now| is the current timestamp.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_managed_identity_new(nwep_managed_identity *identity,
                                           const nwep_keypair *kp,
                                           const nwep_recovery_authority *ra,
                                           nwep_tstamp now);

/**
 * @function
 *
 * `nwep_managed_identity_rotate` generates a new keypair and begins
 * the rotation process. The old key remains active for the overlap period.
 *
 * |identity| is the managed identity.
 * |now| is the current timestamp.
 *
 * Returns 0 on success, or one of the following negative error codes:
 *
 * :macro:`NWEP_ERR_IDENTITY_REVOKED`
 *     Identity has been revoked.
 * :macro:`NWEP_ERR_IDENTITY_ROTATION_IN_PROGRESS`
 *     Maximum active keys reached (rotation in progress).
 */
NWEP_EXTERN int nwep_managed_identity_rotate(nwep_managed_identity *identity,
                                              nwep_tstamp now);

/**
 * @function
 *
 * `nwep_managed_identity_update` expires old keys based on current time.
 * Should be called periodically.
 *
 * |identity| is the managed identity.
 * |now| is the current timestamp.
 */
NWEP_EXTERN void nwep_managed_identity_update(nwep_managed_identity *identity,
                                               nwep_tstamp now);

/**
 * @function
 *
 * `nwep_managed_identity_get_active` returns the currently active keypair
 * for signing. Returns the newest active key.
 *
 * Returns pointer to the active keypair, or NULL if revoked or no active key.
 */
NWEP_EXTERN const nwep_keypair *nwep_managed_identity_get_active(
    const nwep_managed_identity *identity);

/**
 * @function
 *
 * `nwep_managed_identity_get_active_keys` returns all currently active
 * keypairs. Used for verification (accept signatures from any active key).
 *
 * |keys| receives pointers to active keypairs.
 * |max_keys| is the size of the keys array.
 *
 * Returns the number of active keys written to the array.
 */
NWEP_EXTERN size_t nwep_managed_identity_get_active_keys(
    const nwep_managed_identity *identity, const nwep_keypair **keys,
    size_t max_keys);

/**
 * @function
 *
 * `nwep_managed_identity_is_revoked` returns nonzero if the identity
 * has been revoked.
 */
NWEP_EXTERN int nwep_managed_identity_is_revoked(
    const nwep_managed_identity *identity);

/**
 * @function
 *
 * `nwep_managed_identity_revoke` revokes the identity using the
 * recovery authority. After revocation, no keys are active.
 *
 * |identity| is the managed identity to revoke.
 * |ra| is the recovery authority (must match identity's recovery pubkey).
 * |now| is the current timestamp.
 *
 * Returns 0 on success, or one of the following negative error codes:
 *
 * :macro:`NWEP_ERR_IDENTITY_NO_RECOVERY`
 *     Identity has no recovery authority configured.
 * :macro:`NWEP_ERR_IDENTITY_RECOVERY_MISMATCH`
 *     Recovery authority does not match.
 * :macro:`NWEP_ERR_IDENTITY_REVOKED`
 *     Identity is already revoked.
 */
NWEP_EXTERN int nwep_managed_identity_revoke(nwep_managed_identity *identity,
                                              const nwep_recovery_authority *ra,
                                              nwep_tstamp now);

/**
 * @function
 *
 * `nwep_managed_identity_verify_revocation` verifies a revocation record.
 *
 * |revocation| is the revocation record to verify.
 *
 * Returns 0 if valid, or a negative error code.
 */
NWEP_EXTERN int nwep_managed_identity_verify_revocation(
    const nwep_revocation *revocation);

/**
 * @function
 *
 * `nwep_managed_identity_clear` securely zeros the managed identity.
 */
NWEP_EXTERN void nwep_managed_identity_clear(nwep_managed_identity *identity);

/**
 * @macrosection
 *
 * Merkle log
 *
 * Append-only log with cryptographic inclusion proofs. Used for
 * identity verification and transparency.
 */

/**
 * @macro
 *
 * :macro:`NWEP_LOG_ENTRY_MAX_SIZE` is the maximum serialized entry size.
 */
#define NWEP_LOG_ENTRY_MAX_SIZE 256

/**
 * @macro
 *
 * :macro:`NWEP_MERKLE_PROOF_MAX_DEPTH` is the maximum proof depth (log2 of max entries).
 */
#define NWEP_MERKLE_PROOF_MAX_DEPTH 64

/**
 * @enum
 *
 * :type:`nwep_merkle_entry_type` defines the types of log entries.
 */
typedef enum nwep_merkle_entry_type {
  NWEP_LOG_ENTRY_KEY_BINDING = 1,
  NWEP_LOG_ENTRY_KEY_ROTATION = 2,
  NWEP_LOG_ENTRY_REVOCATION = 3,
  NWEP_LOG_ENTRY_ANCHOR_CHANGE = 4
} nwep_merkle_entry_type;

/**
 * @struct
 *
 * :type:`nwep_merkle_entry` represents an entry in the Merkle log.
 */
typedef struct nwep_merkle_entry {
  nwep_merkle_entry_type type;
  nwep_tstamp timestamp;
  nwep_nodeid nodeid;
  uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN];
  uint8_t prev_pubkey[NWEP_ED25519_PUBKEY_LEN];
  uint8_t recovery_pubkey[NWEP_ED25519_PUBKEY_LEN];
  uint8_t signature[NWEP_ED25519_SIG_LEN];
} nwep_merkle_entry;

/**
 * @struct
 *
 * :type:`nwep_merkle_hash` holds a 32-byte Merkle tree hash.
 */
typedef struct nwep_merkle_hash {
  uint8_t data[32];
} nwep_merkle_hash;

/**
 * @struct
 *
 * :type:`nwep_merkle_proof` holds an inclusion proof for a log entry.
 */
typedef struct nwep_merkle_proof {
  uint64_t index;
  uint64_t log_size;
  nwep_merkle_hash leaf_hash;
  nwep_merkle_hash siblings[NWEP_MERKLE_PROOF_MAX_DEPTH];
  size_t depth;
} nwep_merkle_proof;

/**
 * @function
 *
 * `nwep_merkle_entry_encode` serializes a Merkle log entry.
 *
 * |buf| receives the serialized data.
 * |buflen| is the buffer size.
 * |entry| is the entry to serialize.
 *
 * Returns the number of bytes written, or a negative error code.
 */
NWEP_EXTERN nwep_ssize nwep_merkle_entry_encode(uint8_t *buf, size_t buflen,
                                                 const nwep_merkle_entry *entry);

/**
 * @function
 *
 * `nwep_merkle_entry_decode` deserializes a Merkle log entry.
 *
 * |entry| receives the deserialized entry.
 * |data| is the serialized data.
 * |datalen| is the data length.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_merkle_entry_decode(nwep_merkle_entry *entry,
                                          const uint8_t *data, size_t datalen);

/**
 * @function
 *
 * `nwep_merkle_leaf_hash` computes the leaf hash for a Merkle log entry.
 * Hash = SHA-256(0x00 || entry_bytes)
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_merkle_leaf_hash(nwep_merkle_hash *hash,
                                       const nwep_merkle_entry *entry);

/**
 * @function
 *
 * `nwep_merkle_node_hash` computes an internal node hash.
 * Hash = SHA-256(0x01 || left || right)
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_merkle_node_hash(nwep_merkle_hash *hash,
                                       const nwep_merkle_hash *left,
                                       const nwep_merkle_hash *right);

/**
 * @function
 *
 * `nwep_merkle_proof_verify` verifies an inclusion proof against a root hash.
 *
 * |proof| is the inclusion proof.
 * |root| is the expected root hash.
 *
 * Returns 0 if valid, or a negative error code.
 */
NWEP_EXTERN int nwep_merkle_proof_verify(const nwep_merkle_proof *proof,
                                          const nwep_merkle_hash *root);

/**
 * @macro
 *
 * :macro:`NWEP_MERKLE_PROOF_MAX_SIZE` is the maximum serialized proof size.
 * 8 (index) + 8 (log_size) + 32 (leaf_hash) + 4 (depth) + 64*32 (siblings)
 */
#define NWEP_MERKLE_PROOF_MAX_SIZE (8 + 8 + 32 + 4 + NWEP_MERKLE_PROOF_MAX_DEPTH * 32)

/**
 * @function
 *
 * `nwep_merkle_proof_encode` serializes an inclusion proof.
 *
 * |buf| receives the serialized data.
 * |buflen| is the buffer size.
 * |proof| is the proof to serialize.
 *
 * Returns the number of bytes written, or a negative error code.
 */
NWEP_EXTERN nwep_ssize nwep_merkle_proof_encode(uint8_t *buf, size_t buflen,
                                                 const nwep_merkle_proof *proof);

/**
 * @function
 *
 * `nwep_merkle_proof_decode` deserializes an inclusion proof.
 *
 * |proof| receives the deserialized proof.
 * |data| is the serialized data.
 * |datalen| is the data length.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_merkle_proof_decode(nwep_merkle_proof *proof,
                                          const uint8_t *data, size_t datalen);

/**
 * @macrosection
 *
 * Merkle log storage interface
 *
 * Callbacks for persistent log storage. Users implement these to
 * connect the Merkle log to their storage backend.
 */

/**
 * @callback
 *
 * `nwep_log_append_cb` appends an entry to storage.
 * Returns 0 on success, or negative error code.
 */
typedef int (*nwep_log_append_cb)(void *user_data, uint64_t index,
                                  const uint8_t *entry, size_t entry_len);

/**
 * @callback
 *
 * `nwep_log_get_cb` retrieves an entry from storage.
 * Returns entry length on success, or negative error code.
 */
typedef nwep_ssize (*nwep_log_get_cb)(void *user_data, uint64_t index,
                                      uint8_t *buf, size_t buflen);

/**
 * @callback
 *
 * `nwep_log_size_cb` returns the current log size (number of entries).
 */
typedef uint64_t (*nwep_log_size_cb)(void *user_data);

/**
 * @struct
 *
 * :type:`nwep_log_storage` holds storage callbacks for the Merkle log.
 */
typedef struct nwep_log_storage {
  nwep_log_append_cb append;
  nwep_log_get_cb get;
  nwep_log_size_cb size;
  void *user_data;
} nwep_log_storage;

/**
 * @struct
 *
 * :type:`nwep_merkle_log` is the opaque Merkle log structure.
 */
typedef struct nwep_merkle_log nwep_merkle_log;

/**
 * @function
 *
 * `nwep_merkle_log_new` creates a new Merkle log.
 *
 * |plog| receives the created log.
 * |storage| provides the storage callbacks.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_merkle_log_new(nwep_merkle_log **plog,
                                     const nwep_log_storage *storage);

/**
 * @function
 *
 * `nwep_merkle_log_free` frees a Merkle log.
 */
NWEP_EXTERN void nwep_merkle_log_free(nwep_merkle_log *log);

/**
 * @function
 *
 * `nwep_merkle_log_append` appends an entry to the log.
 *
 * |log| is the Merkle log.
 * |entry| is the entry to append.
 * |pindex| receives the index of the appended entry (may be NULL).
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_merkle_log_append(nwep_merkle_log *log,
                                        const nwep_merkle_entry *entry,
                                        uint64_t *pindex);

/**
 * @function
 *
 * `nwep_merkle_log_get` retrieves an entry from the log.
 *
 * |log| is the Merkle log.
 * |index| is the entry index.
 * |entry| receives the entry.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_merkle_log_get(nwep_merkle_log *log, uint64_t index,
                                     nwep_merkle_entry *entry);

/**
 * @function
 *
 * `nwep_merkle_log_size` returns the number of entries in the log.
 */
NWEP_EXTERN uint64_t nwep_merkle_log_size(const nwep_merkle_log *log);

/**
 * @function
 *
 * `nwep_merkle_log_root` computes the current root hash.
 *
 * |log| is the Merkle log.
 * |root| receives the root hash.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_merkle_log_root(nwep_merkle_log *log,
                                      nwep_merkle_hash *root);

/**
 * @function
 *
 * `nwep_merkle_log_prove` generates an inclusion proof for an entry.
 *
 * |log| is the Merkle log.
 * |index| is the entry index.
 * |proof| receives the inclusion proof.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_merkle_log_prove(nwep_merkle_log *log, uint64_t index,
                                       nwep_merkle_proof *proof);

/**
 * @macrosection
 *
 * Log index
 *
 * In-memory index mapping NodeID to current log state for fast lookups.
 */

/**
 * @struct
 *
 * :type:`nwep_log_index_entry` holds the current state for a NodeID.
 */
typedef struct nwep_log_index_entry {
  nwep_nodeid nodeid;
  uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN];
  uint64_t log_index;
  int revoked;
} nwep_log_index_entry;

/**
 * @callback
 *
 * `nwep_index_get_cb` retrieves an index entry by NodeID.
 * Returns 0 on success, NWEP_ERR_STORAGE_KEY_NOT_FOUND if not found.
 */
typedef int (*nwep_index_get_cb)(void *user_data, const nwep_nodeid *nodeid,
                                 nwep_log_index_entry *entry);

/**
 * @callback
 *
 * `nwep_index_put_cb` stores an index entry.
 * Returns 0 on success, or negative error code.
 */
typedef int (*nwep_index_put_cb)(void *user_data,
                                 const nwep_log_index_entry *entry);

/**
 * @struct
 *
 * :type:`nwep_log_index_storage` holds storage callbacks for the log index.
 */
typedef struct nwep_log_index_storage {
  nwep_index_get_cb get;
  nwep_index_put_cb put;
  void *user_data;
} nwep_log_index_storage;

/**
 * @struct
 *
 * :type:`nwep_log_index` is the opaque log index structure.
 */
typedef struct nwep_log_index nwep_log_index;

/**
 * @function
 *
 * `nwep_log_index_new` creates a new log index.
 *
 * |pindex| receives the created index.
 * |storage| provides the storage callbacks.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_log_index_new(nwep_log_index **pindex,
                                    const nwep_log_index_storage *storage);

/**
 * @function
 *
 * `nwep_log_index_free` frees a log index.
 */
NWEP_EXTERN void nwep_log_index_free(nwep_log_index *index);

/**
 * @function
 *
 * `nwep_log_index_lookup` looks up the current state for a NodeID.
 *
 * |index| is the log index.
 * |nodeid| is the NodeID to look up.
 * |entry| receives the index entry.
 *
 * Returns 0 on success, or one of the following negative error codes:
 *
 * :macro:`NWEP_ERR_STORAGE_KEY_NOT_FOUND`
 *     NodeID not found in index.
 */
NWEP_EXTERN int nwep_log_index_lookup(nwep_log_index *index,
                                       const nwep_nodeid *nodeid,
                                       nwep_log_index_entry *entry);

/**
 * @function
 *
 * `nwep_log_index_update` updates the index from a Merkle log entry.
 *
 * |index| is the log index.
 * |entry| is the Merkle log entry.
 * |log_idx| is the entry's index in the log.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_log_index_update(nwep_log_index *index,
                                       const nwep_merkle_entry *entry,
                                       uint64_t log_idx);

/**
 * @macrosection
 *
 * NodeID computation
 *
 * NodeID is a 32-byte identifier derived from a public key:
 * NodeID = SHA-256(pubkey || "WEB/1")
 */

/**
 * @function
 *
 * `nwep_nodeid_from_pubkey` computes a NodeID from a public key.
 * NodeID = SHA-256(pubkey || "WEB/1")
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_nodeid_from_pubkey(nwep_nodeid *nodeid,
                                         const uint8_t pubkey[32]);

/**
 * @function
 *
 * `nwep_nodeid_from_keypair` computes a NodeID from a keypair.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_nodeid_from_keypair(nwep_nodeid *nodeid,
                                          const nwep_keypair *kp);

/**
 * @function
 *
 * `nwep_nodeid_eq` returns nonzero if two NodeIDs are equal.
 */
NWEP_EXTERN int nwep_nodeid_eq(const nwep_nodeid *a, const nwep_nodeid *b);

/**
 * @function
 *
 * `nwep_nodeid_is_zero` returns nonzero if the NodeID is all zeros.
 */
NWEP_EXTERN int nwep_nodeid_is_zero(const nwep_nodeid *nodeid);

/**
 * @macrosection
 *
 * Address and URL parsing
 *
 * WEB/1 addresses contain IP and NodeID: web://[Base58(IP||NodeID)]:port/path
 */

/**
 * @struct
 *
 * :type:`nwep_addr` holds an IP address (IPv6 or IPv4-mapped) and NodeID.
 */
typedef struct nwep_addr {
  /**
   * :member:`ip` is the IPv6 address (IPv4 mapped as ::ffff:x.x.x.x).
   */
  uint8_t ip[16];
  /**
   * :member:`nodeid` is the NodeID.
   */
  nwep_nodeid nodeid;
  /**
   * :member:`port` is the port number (default 4433).
   */
  uint16_t port;
} nwep_addr;

/**
 * @function
 *
 * `nwep_addr_encode` encodes an address to Base58.
 * |dest| must have space for at least NWEP_BASE58_ADDR_LEN + 1 bytes.
 *
 * Returns the number of characters written (excluding null), or 0 on error.
 */
NWEP_EXTERN size_t nwep_addr_encode(char *dest, size_t destlen,
                                     const nwep_addr *addr);

/**
 * @function
 *
 * `nwep_addr_decode` decodes a Base58 address string into an nwep_addr.
 * This only decodes the address portion, not the full URL.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_addr_decode(nwep_addr *addr, const char *encoded);

/**
 * @macro
 *
 * :macro:`NWEP_URL_MAX_LEN` is the maximum length of a web:// URL.
 */
#define NWEP_URL_MAX_LEN 512

/**
 * @struct
 *
 * :type:`nwep_url` represents a parsed web:// URL.
 */
typedef struct nwep_url {
  /**
   * :member:`addr` is the decoded address.
   */
  nwep_addr addr;
  /**
   * :member:`path` is the path portion (null-terminated, max 256 chars).
   */
  char path[256];
} nwep_url;

/**
 * @function
 *
 * `nwep_url_parse` parses a web:// URL string.
 * Format: web://[address]:port/path
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_url_parse(nwep_url *url, const char *str);

/**
 * @function
 *
 * `nwep_url_format` formats a URL into a string buffer.
 * |dest| must have space for at least NWEP_URL_MAX_LEN bytes.
 *
 * Returns the number of characters written (excluding null), or 0 on error.
 */
NWEP_EXTERN size_t nwep_url_format(char *dest, size_t destlen,
                                    const nwep_url *url);

/**
 * @function
 *
 * `nwep_addr_set_ipv4` sets an address to an IPv4-mapped IPv6 address.
 */
NWEP_EXTERN void nwep_addr_set_ipv4(nwep_addr *addr, uint32_t ipv4);

/**
 * @function
 *
 * `nwep_addr_set_ipv6` sets an address to an IPv6 address.
 */
NWEP_EXTERN void nwep_addr_set_ipv6(nwep_addr *addr, const uint8_t ipv6[16]);

/**
 * @macrosection
 *
 * Ed25519 signing operations
 *
 * Sign and verify messages using Ed25519 keys.
 */

/**
 * @function
 *
 * `nwep_sign` signs |msg| of |msglen| bytes using |kp|.
 * |sig| must have space for 64 bytes.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_sign(uint8_t sig[64], const uint8_t *msg, size_t msglen,
                           const nwep_keypair *kp);

/**
 * @function
 *
 * `nwep_verify` verifies a signature |sig| on |msglen| bytes of |msg|
 * using the public key |pubkey|.
 *
 * Returns 0 if the signature is valid, or a negative error code.
 */
NWEP_EXTERN int nwep_verify(const uint8_t sig[64], const uint8_t *msg,
                             size_t msglen, const uint8_t pubkey[32]);

/**
 * @macrosection
 *
 * Challenge/response authentication
 *
 * Functions for the handshake challenge/response protocol that proves
 * possession of the private key.
 */

/**
 * @function
 *
 * `nwep_challenge_generate` generates a 32-byte random challenge nonce.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_challenge_generate(uint8_t challenge[32]);

/**
 * @function
 *
 * `nwep_challenge_sign` signs a challenge using the keypair.
 * |response| must have space for 64 bytes.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_challenge_sign(uint8_t response[64],
                                     const uint8_t challenge[32],
                                     const nwep_keypair *kp);

/**
 * @function
 *
 * `nwep_challenge_verify` verifies a challenge response signature.
 *
 * Returns 0 if valid, or a negative error code.
 */
NWEP_EXTERN int nwep_challenge_verify(const uint8_t response[64],
                                       const uint8_t challenge[32],
                                       const uint8_t pubkey[32]);

/**
 * @function
 *
 * `nwep_random_bytes` fills |dest| with |len| cryptographically secure
 * random bytes.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_random_bytes(uint8_t *dest, size_t len);

/**
 * @macrosection
 *
 * Message framing
 *
 * WEB/1 wire format: [4-byte BE length][1-byte type][headers][body]
 *
 * Header block format:
 * - [4-byte count][header1][header2]...
 * - Each header: [4-byte name_len][name][4-byte value_len][value]
 */

/**
 * @struct
 *
 * :type:`nwep_header` represents a single header name-value pair.
 */
typedef struct nwep_header {
  /**
   * :member:`name` is the header name (not null-terminated in wire format).
   */
  const uint8_t *name;
  /**
   * :member:`name_len` is the length of the header name.
   */
  size_t name_len;
  /**
   * :member:`value` is the header value (not null-terminated in wire format).
   */
  const uint8_t *value;
  /**
   * :member:`value_len` is the length of the header value.
   */
  size_t value_len;
} nwep_header;

/**
 * @macro
 *
 * :macro:`NWEP_FRAME_HEADER_SIZE` is the size of the frame header (length field).
 */
#define NWEP_FRAME_HEADER_SIZE 4

/**
 * @macro
 *
 * :macro:`NWEP_MSG_TYPE_SIZE` is the size of the message type field.
 */
#define NWEP_MSG_TYPE_SIZE 1

/**
 * @struct
 *
 * :type:`nwep_msg` represents a parsed WEB/1 message.
 */
typedef struct nwep_msg {
  /**
   * :member:`type` is the message type (NWEP_MSG_REQUEST, etc.).
   */
  uint8_t type;
  /**
   * :member:`headers` points to an array of headers.
   */
  nwep_header *headers;
  /**
   * :member:`header_count` is the number of headers.
   */
  size_t header_count;
  /**
   * :member:`body` points to the message body.
   */
  const uint8_t *body;
  /**
   * :member:`body_len` is the length of the body.
   */
  size_t body_len;
} nwep_msg;

/**
 * @function
 *
 * `nwep_msg_init` initializes a message structure.
 */
NWEP_EXTERN void nwep_msg_init(nwep_msg *msg, uint8_t type);

/**
 * @function
 *
 * `nwep_msg_encode_len` calculates the encoded size of a message.
 * This includes the 4-byte length prefix.
 */
NWEP_EXTERN size_t nwep_msg_encode_len(const nwep_msg *msg);

/**
 * @function
 *
 * `nwep_msg_encode` encodes a message into a buffer.
 * |dest| must have space for at least nwep_msg_encode_len() bytes.
 *
 * Returns the number of bytes written, or 0 on error.
 */
NWEP_EXTERN size_t nwep_msg_encode(uint8_t *dest, size_t destlen,
                                    const nwep_msg *msg);

/**
 * @function
 *
 * `nwep_msg_decode_header` decodes just the frame header to get payload size.
 * |src| must have at least NWEP_FRAME_HEADER_SIZE (4) bytes.
 * |payload_len| receives the payload length (excludes the 4-byte header).
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_msg_decode_header(uint32_t *payload_len,
                                        const uint8_t *src, size_t srclen);

/**
 * @function
 *
 * `nwep_msg_decode` decodes a complete message from a buffer.
 * |src| must contain the complete message including the 4-byte length prefix.
 * |msg| receives the decoded message. Headers point into |src| buffer.
 * |headers| is a caller-provided array to store decoded headers.
 * |max_headers| is the maximum number of headers to decode.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_msg_decode(nwep_msg *msg, const uint8_t *src,
                                 size_t srclen, nwep_header *headers,
                                 size_t max_headers);

/**
 * @function
 *
 * `nwep_header_set` sets a header from C strings (null-terminated).
 */
NWEP_EXTERN void nwep_header_set(nwep_header *hdr, const char *name,
                                  const char *value);

/**
 * @function
 *
 * `nwep_header_set_n` sets a header from byte arrays with lengths.
 */
NWEP_EXTERN void nwep_header_set_n(nwep_header *hdr, const uint8_t *name,
                                    size_t name_len, const uint8_t *value,
                                    size_t value_len);

/**
 * @function
 *
 * `nwep_msg_find_header` finds a header by name in a message.
 * Returns a pointer to the header, or NULL if not found.
 */
NWEP_EXTERN const nwep_header *nwep_msg_find_header(const nwep_msg *msg,
                                                     const char *name);

/**
 * @function
 *
 * `nwep_header_value_eq` returns nonzero if a header's value equals
 * the given null-terminated string.
 */
NWEP_EXTERN int nwep_header_value_eq(const nwep_header *hdr, const char *value);

/**
 * @macrosection
 *
 * Header name constants
 *
 * Pseudo-headers (start with ':') and standard header names.
 */

/* Pseudo-headers (required, start with ':') */
#define NWEP_HDR_METHOD ":method"
#define NWEP_HDR_PATH ":path"
#define NWEP_HDR_VERSION ":version"
#define NWEP_HDR_STATUS ":status"

/* Standard headers */
#define NWEP_HDR_REQUEST_ID "request-id"
#define NWEP_HDR_CLIENT_ID "client-id"
#define NWEP_HDR_SERVER_ID "server-id"
#define NWEP_HDR_CHALLENGE "challenge"
#define NWEP_HDR_CHALLENGE_RESPONSE "challenge-response"
#define NWEP_HDR_SERVER_CHALLENGE "server-challenge"
#define NWEP_HDR_AUTH_RESPONSE "auth-response"
#define NWEP_HDR_MAX_STREAMS "max-streams"
#define NWEP_HDR_MAX_MESSAGE_SIZE "max-message-size"
#define NWEP_HDR_COMPRESSION "compression"
#define NWEP_HDR_ROLES "roles"
#define NWEP_HDR_TRANSCRIPT_SIG "transcript-signature"
#define NWEP_HDR_STATUS_DETAILS "status-details"
#define NWEP_HDR_RETRY_AFTER "retry-after"
#define NWEP_HDR_TRACE_ID "trace-id"
#define NWEP_HDR_EVENT ":event"
#define NWEP_HDR_NOTIFY_ID "notify-id"

/**
 * @macrosection
 *
 * Trace and request ID generation
 *
 * Generate unique identifiers for request tracing and correlation.
 */

/**
 * @function
 *
 * `nwep_trace_id_generate` generates a 16-byte trace ID.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_trace_id_generate(uint8_t trace_id[16]);

/**
 * @function
 *
 * `nwep_request_id_generate` generates a 16-byte request ID.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_request_id_generate(uint8_t request_id[16]);

/**
 * @macrosection
 *
 * Method and status validation
 *
 * Helper functions to validate and classify methods and status tokens.
 */

/**
 * @function
 *
 * `nwep_method_is_valid` checks if |method| is a valid WEB/1 method.
 *
 * Returns 1 if valid, 0 otherwise.
 */
NWEP_EXTERN int nwep_method_is_valid(const char *method);

/**
 * @function
 *
 * `nwep_method_is_idempotent` checks if |method| is idempotent.
 * Idempotent methods: READ, DELETE, HEARTBEAT.
 *
 * Returns 1 if idempotent, 0 otherwise.
 */
NWEP_EXTERN int nwep_method_is_idempotent(const char *method);

/**
 * @function
 *
 * `nwep_method_allowed_0rtt` checks if |method| is allowed in 0-RTT.
 * Only READ is allowed in 0-RTT for replay safety.
 *
 * Returns 1 if allowed, 0 otherwise.
 */
NWEP_EXTERN int nwep_method_allowed_0rtt(const char *method);

/**
 * @function
 *
 * `nwep_status_is_valid` checks if |status| is a valid WEB/1 status token.
 *
 * Returns 1 if valid, 0 otherwise.
 */
NWEP_EXTERN int nwep_status_is_valid(const char *status);

/**
 * @function
 *
 * `nwep_status_is_success` checks if |status| indicates success.
 * Success statuses: ok, created, accepted, no_content.
 *
 * Returns 1 if success, 0 otherwise.
 */
NWEP_EXTERN int nwep_status_is_success(const char *status);

/**
 * @function
 *
 * `nwep_status_is_error` checks if |status| indicates an error.
 *
 * Returns 1 if error, 0 otherwise.
 */
NWEP_EXTERN int nwep_status_is_error(const char *status);

/**
 * @macrosection
 *
 * Request/response building
 *
 * Helper functions to construct WEB/1 request and response messages.
 */

/**
 * @function
 *
 * `nwep_request_build` builds a request message.
 * |headers| must have space for at least 4 headers.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_request_build(nwep_msg *msg, nwep_header *headers,
                                    size_t max_headers, const char *method,
                                    const char *path, const uint8_t *body,
                                    size_t body_len);

/**
 * @function
 *
 * `nwep_response_build` builds a response message.
 * |headers| must have space for at least 2 headers.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_response_build(nwep_msg *msg, nwep_header *headers,
                                     size_t max_headers, const char *status,
                                     const char *status_details,
                                     const uint8_t *body, size_t body_len);

/**
 * @function
 *
 * `nwep_stream_msg_build` builds a stream message for chunked body data.
 * Stream messages have no headers, only body data.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_stream_msg_build(nwep_msg *msg, const uint8_t *data,
                                       size_t data_len, int is_final);

/**
 * @function
 *
 * `nwep_heartbeat_build` builds a HEARTBEAT request message.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_heartbeat_build(nwep_msg *msg, nwep_header *headers,
                                      size_t max_headers);

/**
 * @function
 *
 * `nwep_heartbeat_response_build` builds a HEARTBEAT response message.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_heartbeat_response_build(nwep_msg *msg,
                                               nwep_header *headers,
                                               size_t max_headers);

/**
 * @macrosection
 *
 * Base64 encoding
 *
 * Encode and decode binary data (keys, signatures) for header values.
 */

/**
 * @function
 *
 * `nwep_base64_encode_len` returns the buffer size needed to encode
 * |srclen| bytes as Base64 (including null terminator).
 */
NWEP_EXTERN size_t nwep_base64_encode_len(size_t srclen);

/**
 * @function
 *
 * `nwep_base64_encode` encodes |srclen| bytes from |src| into Base64.
 * |dest| must have space for nwep_base64_encode_len(srclen) bytes.
 *
 * Returns the number of characters written (excluding null), or 0 on error.
 */
NWEP_EXTERN size_t nwep_base64_encode(char *dest, size_t destlen,
                                       const uint8_t *src, size_t srclen);

/**
 * @function
 *
 * `nwep_base64_decode_len` returns the maximum buffer size needed to decode
 * a Base64 string of |srclen| characters.
 */
NWEP_EXTERN size_t nwep_base64_decode_len(size_t srclen);

/**
 * @function
 *
 * `nwep_base64_decode` decodes Base64 string |src| into |dest|.
 * |src| must be null-terminated.
 *
 * Returns the number of bytes written, or 0 on error.
 */
NWEP_EXTERN size_t nwep_base64_decode(uint8_t *dest, size_t destlen,
                                       const char *src);

/**
 * @function
 *
 * `nwep_base64_decode_n` decodes |srclen| bytes of Base64 from |src| into
 * |dest|. Unlike `nwep_base64_decode`, this function does not require |src|
 * to be null-terminated.
 *
 * Returns the number of bytes written, or 0 on error.
 */
NWEP_EXTERN size_t nwep_base64_decode_n(uint8_t *dest, size_t destlen,
                                         const char *src, size_t srclen);

/**
 * @macrosection
 *
 * Byte order helpers
 *
 * Read and write big-endian integers for wire format encoding.
 */

/**
 * @function
 *
 * `nwep_put_uint32be` writes a 32-bit big-endian value to |p|.
 * Returns pointer past written bytes.
 */
NWEP_EXTERN uint8_t *nwep_put_uint32be(uint8_t *p, uint32_t n);

/**
 * @function
 *
 * `nwep_get_uint32be` reads a 32-bit big-endian value from |p|.
 * Returns pointer past read bytes.
 */
NWEP_EXTERN const uint8_t *nwep_get_uint32be(uint32_t *dest, const uint8_t *p);

/**
 * @function
 *
 * `nwep_put_uint16be` writes a 16-bit big-endian value to |p|.
 * Returns pointer past written bytes.
 */
NWEP_EXTERN uint8_t *nwep_put_uint16be(uint8_t *p, uint16_t n);

/**
 * @function
 *
 * `nwep_get_uint16be` reads a 16-bit big-endian value from |p|.
 * Returns pointer past read bytes.
 */
NWEP_EXTERN const uint8_t *nwep_get_uint16be(uint16_t *dest, const uint8_t *p);

/**
 * @macrosection
 *
 * CONNECT/AUTHENTICATE handshake
 *
 * State machine and message building for the WEB/1 connection handshake.
 * The handshake establishes mutual authentication via triple-layer verification:
 * 1. TLS certificate pubkey matches declared pubkey
 * 2. NodeID correctly derived from pubkey
 * 3. Challenge/response proves private key possession
 */

/**
 * @enum
 *
 * :type:`nwep_client_state` represents the client connection state machine.
 */
typedef enum nwep_client_state {
  NWEP_CLIENT_STATE_INITIAL = 0,
  NWEP_CLIENT_STATE_TLS_HANDSHAKE = 1,
  NWEP_CLIENT_STATE_SEND_CONNECT = 2,
  NWEP_CLIENT_STATE_WAIT_CONNECT_RESP = 3,
  NWEP_CLIENT_STATE_SEND_AUTHENTICATE = 4,
  NWEP_CLIENT_STATE_WAIT_AUTH_RESP = 5,
  NWEP_CLIENT_STATE_CONNECTED = 6,
  NWEP_CLIENT_STATE_ERROR = 7
} nwep_client_state;

/**
 * @enum
 *
 * :type:`nwep_server_state` represents the server connection state machine.
 */
typedef enum nwep_server_state {
  NWEP_SERVER_STATE_INITIAL = 0,
  NWEP_SERVER_STATE_TLS_HANDSHAKE = 1,
  NWEP_SERVER_STATE_AWAITING_CONNECT = 2,
  NWEP_SERVER_STATE_AWAITING_CLIENT_AUTH = 3,
  NWEP_SERVER_STATE_CONNECTED = 4,
  NWEP_SERVER_STATE_ERROR = 5
} nwep_server_state;

/**
 * @struct
 *
 * :type:`nwep_handshake_params` holds negotiable parameters for the handshake.
 */
typedef struct nwep_handshake_params {
  uint32_t max_streams;
  uint32_t max_message_size;
  const char *compression;
  const char *role;
} nwep_handshake_params;

/**
 * @struct
 *
 * :type:`nwep_handshake` holds the state for a CONNECT/AUTHENTICATE handshake.
 */
typedef struct nwep_handshake {
  /* Our identity */
  nwep_keypair *local_keypair;
  nwep_nodeid local_nodeid;

  /* Peer identity (filled during handshake) */
  uint8_t peer_pubkey[NWEP_ED25519_PUBKEY_LEN];
  nwep_nodeid peer_nodeid;
  nwep_nodeid expected_peer_nodeid; /* From address, for verification */
  int peer_nodeid_verified;

  /* Challenge/response */
  uint8_t local_challenge[NWEP_CHALLENGE_LEN];
  uint8_t peer_challenge[NWEP_CHALLENGE_LEN];

  /* Negotiated parameters */
  nwep_handshake_params local_params;
  nwep_handshake_params peer_params;      /* Peer's original params (for transcript) */
  nwep_handshake_params negotiated_params;

  /* Transcript for signing */
  uint8_t *transcript;
  size_t transcript_len;
  size_t transcript_cap;

  /* State */
  int is_server;
  union {
    nwep_client_state client;
    nwep_server_state server;
  } state;
  int error_code;
} nwep_handshake;

/**
 * @function
 *
 * `nwep_handshake_client_init` initializes a client handshake context.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_handshake_client_init(nwep_handshake *hs,
                                            nwep_keypair *keypair,
                                            const nwep_nodeid *expected_server);

/**
 * @function
 *
 * `nwep_handshake_server_init` initializes a server handshake context.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_handshake_server_init(nwep_handshake *hs,
                                            nwep_keypair *keypair);

/**
 * @function
 *
 * `nwep_handshake_free` frees resources allocated for a handshake.
 */
NWEP_EXTERN void nwep_handshake_free(nwep_handshake *hs);

/**
 * @function
 *
 * `nwep_handshake_set_params` sets the local handshake parameters.
 */
NWEP_EXTERN void nwep_handshake_set_params(nwep_handshake *hs,
                                            const nwep_handshake_params *params);

/**
 * @function
 *
 * `nwep_connect_request_build` builds a CONNECT request message.
 * |headers| must have space for at least 6 headers.
 * |header_buf| is scratch space for Base64-encoded values.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_connect_request_build(nwep_msg *msg, nwep_header *headers,
                                            size_t max_headers,
                                            uint8_t *header_buf,
                                            size_t header_buf_len,
                                            nwep_handshake *hs);

/**
 * @function
 *
 * `nwep_connect_request_parse` parses a CONNECT request and updates handshake state.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_connect_request_parse(nwep_handshake *hs,
                                            const nwep_msg *msg);

/**
 * @function
 *
 * `nwep_connect_response_build` builds a CONNECT response message.
 * |headers| must have space for at least 10 headers.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_connect_response_build(nwep_msg *msg, nwep_header *headers,
                                             size_t max_headers,
                                             uint8_t *header_buf,
                                             size_t header_buf_len,
                                             nwep_handshake *hs);

/**
 * @function
 *
 * `nwep_connect_response_parse` parses a CONNECT response and verifies server.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_connect_response_parse(nwep_handshake *hs,
                                             const nwep_msg *msg);

/**
 * @function
 *
 * `nwep_auth_request_build` builds an AUTHENTICATE request message.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_auth_request_build(nwep_msg *msg, nwep_header *headers,
                                         size_t max_headers,
                                         uint8_t *header_buf,
                                         size_t header_buf_len,
                                         nwep_handshake *hs);

/**
 * @function
 *
 * `nwep_auth_request_parse` parses an AUTHENTICATE request and verifies client.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_auth_request_parse(nwep_handshake *hs,
                                         const nwep_msg *msg);

/**
 * @function
 *
 * `nwep_auth_response_build` builds an AUTHENTICATE response message.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_auth_response_build(nwep_msg *msg, nwep_header *headers,
                                          size_t max_headers,
                                          nwep_handshake *hs);

/**
 * @function
 *
 * `nwep_auth_response_parse` parses an AUTHENTICATE response.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_auth_response_parse(nwep_handshake *hs,
                                          const nwep_msg *msg);

/**
 * @function
 *
 * `nwep_verify_layer1` verifies Layer 1: TLS cert pubkey matches peer_pubkey.
 * |tls_pubkey| is extracted from the peer's TLS certificate.
 *
 * Returns 0 if valid, or NWEP_ERR_CRYPTO_PUBKEY_MISMATCH.
 */
NWEP_EXTERN int nwep_verify_layer1(const nwep_handshake *hs,
                                    const uint8_t tls_pubkey[32]);

/**
 * @function
 *
 * `nwep_verify_layer2` verifies Layer 2: NodeID derivation is correct.
 * Checks that SHA-256(peer_pubkey || "WEB/1") == expected_peer_nodeid.
 *
 * Returns 0 if valid, or NWEP_ERR_CRYPTO_NODEID_MISMATCH.
 */
NWEP_EXTERN int nwep_verify_layer2(const nwep_handshake *hs);

/**
 * @function
 *
 * `nwep_verify_layer3` verifies Layer 3: challenge signature is valid.
 * |signature| is the peer's response to our challenge.
 *
 * Returns 0 if valid, or NWEP_ERR_CRYPTO_CHALLENGE_FAILED.
 */
NWEP_EXTERN int nwep_verify_layer3(const nwep_handshake *hs,
                                    const uint8_t signature[64]);

/**
 * @function
 *
 * `nwep_verify_all_layers` performs all three verification layers.
 *
 * Returns 0 if all valid, or the first fatal error encountered.
 */
NWEP_EXTERN int nwep_verify_all_layers(const nwep_handshake *hs,
                                        const uint8_t tls_pubkey[32],
                                        const uint8_t signature[64]);

/**
 * @function
 *
 * `nwep_transcript_init` initializes the transcript buffer.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_transcript_init(nwep_handshake *hs);

/**
 * @function
 *
 * `nwep_transcript_add_connect_request` adds CONNECT request to transcript.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_transcript_add_connect_request(nwep_handshake *hs);

/**
 * @function
 *
 * `nwep_transcript_add_connect_response` adds CONNECT response to transcript.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_transcript_add_connect_response(nwep_handshake *hs);

/**
 * @function
 *
 * `nwep_transcript_sign` signs the transcript and returns the signature.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_transcript_sign(uint8_t signature[64],
                                      const nwep_handshake *hs);

/**
 * @function
 *
 * `nwep_transcript_verify` verifies a transcript signature from the peer.
 *
 * Returns 0 if valid, or a negative error code.
 */
NWEP_EXTERN int nwep_transcript_verify(const nwep_handshake *hs,
                                        const uint8_t signature[64]);

/**
 * @function
 *
 * `nwep_client_state_str` returns a string representation of the client state.
 */
NWEP_EXTERN const char *nwep_client_state_str(nwep_client_state state);

/**
 * @function
 *
 * `nwep_server_state_str` returns a string representation of the server state.
 */
NWEP_EXTERN const char *nwep_server_state_str(nwep_server_state state);

/**
 * @macrosection
 *
 * Public connection API
 *
 * The main user-facing API for nwep. Users create servers or clients,
 * feed packets via read/write, and handle events via callbacks.
 *
 * Typical server flow:
 * 1. nwep_init()
 * 2. nwep_server_new() with settings and callbacks
 * 3. Loop: recv -> nwep_server_read() -> nwep_server_write() -> send
 * 4. Handle timer via nwep_server_handle_expiry()
 * 5. nwep_server_free()
 *
 * Typical client flow:
 * 1. nwep_init()
 * 2. nwep_client_new() then nwep_client_connect()
 * 3. Loop: recv -> nwep_client_read() -> nwep_client_write() -> send
 * 4. Handle timer via nwep_client_handle_expiry()
 * 5. nwep_client_free()
 */

/* Opaque types */
typedef struct nwep_server nwep_server;
typedef struct nwep_client nwep_client;
typedef struct nwep_conn nwep_conn;
typedef struct nwep_stream nwep_stream;

/**
 * @enum
 *
 * :type:`nwep_log_level` defines logging severity levels.
 */
typedef enum nwep_log_level {
  NWEP_LOG_TRACE = 0,
  NWEP_LOG_DEBUG = 1,
  NWEP_LOG_INFO = 2,
  NWEP_LOG_WARN = 3,
  NWEP_LOG_ERROR = 4
} nwep_log_level;

/**
 * @struct
 *
 * :type:`nwep_log_entry` represents a structured log entry.
 */
typedef struct nwep_log_entry {
  /**
   * :member:`level` is the log severity level.
   */
  nwep_log_level level;
  /**
   * :member:`timestamp_ns` is the timestamp in nanoseconds (optional, 0 if not set).
   */
  uint64_t timestamp_ns;
  /**
   * :member:`trace_id` is the 16-byte trace ID (all zeros if not set).
   */
  uint8_t trace_id[NWEP_TRACE_ID_LEN];
  /**
   * :member:`component` is the component name (e.g., "handshake", "stream").
   */
  const char *component;
  /**
   * :member:`message` is the log message.
   */
  const char *message;
} nwep_log_entry;

/**
 * @callback
 *
 * `nwep_log_callback` is called for each log entry when using custom logging.
 */
typedef void (*nwep_log_callback)(const nwep_log_entry *entry, void *user_data);

/**
 * @function
 *
 * `nwep_log_level_str` returns the string representation of a log level.
 */
NWEP_EXTERN const char *nwep_log_level_str(nwep_log_level level);

/**
 * @function
 *
 * `nwep_log_set_level` sets the minimum log level for output.
 * Messages below this level are discarded.
 */
NWEP_EXTERN void nwep_log_set_level(nwep_log_level level);

/**
 * @function
 *
 * `nwep_log_get_level` returns the current minimum log level.
 */
NWEP_EXTERN nwep_log_level nwep_log_get_level(void);

/**
 * @function
 *
 * `nwep_log_set_callback` sets a custom log callback function.
 * If set, all log output goes to the callback instead of default output.
 */
NWEP_EXTERN void nwep_log_set_callback(nwep_log_callback callback,
                                        void *user_data);

/**
 * @function
 *
 * `nwep_log_set_json` enables or disables JSON format output.
 * Default is plain text format.
 */
NWEP_EXTERN void nwep_log_set_json(int enabled);

/**
 * @function
 *
 * `nwep_log_set_stderr` enables or disables stderr output.
 * Default is enabled. Disable when using a custom callback.
 */
NWEP_EXTERN void nwep_log_set_stderr(int enabled);

/**
 * @function
 *
 * `nwep_log_write` writes a log entry with the specified level, trace ID,
 * component, and printf-style message.
 */
NWEP_EXTERN void nwep_log_write(nwep_log_level level, const uint8_t *trace_id,
                                 const char *component, const char *fmt, ...);

/**
 * @function
 *
 * `nwep_log_trace` writes a TRACE level log entry.
 */
NWEP_EXTERN void nwep_log_trace(const uint8_t *trace_id, const char *component,
                                 const char *fmt, ...);

/**
 * @function
 *
 * `nwep_log_debug` writes a DEBUG level log entry.
 */
NWEP_EXTERN void nwep_log_debug(const uint8_t *trace_id, const char *component,
                                 const char *fmt, ...);

/**
 * @function
 *
 * `nwep_log_info` writes an INFO level log entry.
 */
NWEP_EXTERN void nwep_log_info(const uint8_t *trace_id, const char *component,
                                const char *fmt, ...);

/**
 * @function
 *
 * `nwep_log_warn` writes a WARN level log entry.
 */
NWEP_EXTERN void nwep_log_warn(const uint8_t *trace_id, const char *component,
                                const char *fmt, ...);

/**
 * @function
 *
 * `nwep_log_error` writes an ERROR level log entry.
 */
NWEP_EXTERN void nwep_log_error(const uint8_t *trace_id, const char *component,
                                 const char *fmt, ...);

/**
 * @function
 *
 * `nwep_log_format_json` formats a log entry as a JSON string.
 * Returns the number of bytes written (excluding null terminator).
 */
NWEP_EXTERN size_t nwep_log_format_json(char *dest, size_t destlen,
                                         const nwep_log_entry *entry);

/**
 * @struct
 *
 * :type:`nwep_identity` holds identity information (pubkey and NodeID).
 */
typedef struct nwep_identity {
  uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN];
  nwep_nodeid nodeid;
} nwep_identity;

/**
 * @struct
 *
 * :type:`nwep_request` represents an incoming request.
 */
typedef struct nwep_request {
  const char *method;
  size_t method_len;
  const char *path;
  size_t path_len;
  const nwep_header *headers;
  size_t header_count;
  const uint8_t *body;
  size_t body_len;
  uint8_t request_id[NWEP_REQUEST_ID_LEN];
  uint8_t trace_id[NWEP_TRACE_ID_LEN];
} nwep_request;

/**
 * @struct
 *
 * :type:`nwep_response` represents an incoming or outgoing response.
 */
typedef struct nwep_response {
  const char *status;
  size_t status_len;
  const char *status_details;
  size_t status_details_len;
  const nwep_header *headers;
  size_t header_count;
  const uint8_t *body;
  size_t body_len;
} nwep_response;

/**
 * @macro
 *
 * :macro:`NWEP_NOTIFY_ID_LEN` is the length of a notify ID.
 */
#define NWEP_NOTIFY_ID_LEN 16

/**
 * @struct
 *
 * :type:`nwep_notify` represents a server-initiated notification.
 */
typedef struct nwep_notify {
  const char *event;
  const char *path;
  uint8_t notify_id[NWEP_NOTIFY_ID_LEN];
  int has_notify_id;
  const nwep_header *headers;
  size_t header_count;
  const uint8_t *body;
  size_t body_len;
} nwep_notify;

/**
 * @function
 *
 * `nwep_request_parse` parses a decoded message into a request structure.
 * |msg| must be a NWEP_MSG_REQUEST type message.
 *
 * Returns 0 on success, or one of the following negative error codes:
 *
 * :macro:`NWEP_ERR_PROTO_INVALID_MESSAGE`
 *     Message is not a request.
 * :macro:`NWEP_ERR_PROTO_MISSING_HEADER`
 *     Required header is missing.
 * :macro:`NWEP_ERR_PROTO_INVALID_METHOD`
 *     Method is not valid.
 */
NWEP_EXTERN int nwep_request_parse(nwep_request *req, const nwep_msg *msg);

/**
 * @function
 *
 * `nwep_response_parse` parses a decoded message into a response structure.
 * |msg| must be a NWEP_MSG_RESPONSE type message.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_response_parse(nwep_response *resp, const nwep_msg *msg);

/**
 * @callback
 *
 * `nwep_on_connect` is called when a connection is established.
 * |peer| contains the peer's identity.
 *
 * Return 0 to accept the connection, or a negative error code to reject.
 */
typedef int (*nwep_on_connect)(nwep_conn *conn, const nwep_identity *peer,
                                void *user_data);

/**
 * @callback
 *
 * `nwep_on_disconnect` is called when a connection is closed.
 * |error| is the error that caused the disconnect (0 for graceful close).
 */
typedef void (*nwep_on_disconnect)(nwep_conn *conn, int error, void *user_data);

/**
 * @callback
 *
 * `nwep_on_request` is called when a request is received (server-side).
 * The callback should call nwep_stream_respond() to send a response.
 *
 * Return 0 on success, or a negative error code.
 */
typedef int (*nwep_on_request)(nwep_conn *conn, nwep_stream *stream,
                                const nwep_request *req, void *user_data);

/**
 * @callback
 *
 * `nwep_on_response` is called when a response is received (client-side).
 *
 * Return 0 on success, or a negative error code.
 */
typedef int (*nwep_on_response)(nwep_conn *conn, nwep_stream *stream,
                                 const nwep_response *resp, void *user_data);

/**
 * @callback
 *
 * `nwep_on_stream_data` is called when stream body data is received.
 *
 * Return 0 on success, or a negative error code.
 */
typedef int (*nwep_on_stream_data)(nwep_conn *conn, nwep_stream *stream,
                                    const uint8_t *data, size_t len,
                                    void *user_data);

/**
 * @callback
 *
 * `nwep_on_stream_end` is called when the stream ends (FIN received).
 *
 * Return 0 on success, or a negative error code.
 */
typedef int (*nwep_on_stream_end)(nwep_conn *conn, nwep_stream *stream,
                                   void *user_data);

/**
 * @callback
 *
 * `nwep_on_notify` is called when a NOTIFY is received (client-side).
 *
 * Return 0 on success, or a negative error code.
 */
typedef int (*nwep_on_notify)(nwep_conn *conn, nwep_stream *stream,
                               const nwep_notify *notify, void *user_data);

/**
 * @callback
 *
 * `nwep_rand` generates random bytes. If not provided, OpenSSL's
 * RAND_bytes will be used.
 *
 * Return 0 on success, or a negative error code.
 */
typedef int (*nwep_rand)(uint8_t *dest, size_t len, void *user_data);

/**
 * @struct
 *
 * :type:`nwep_callbacks` holds all callback function pointers.
 */
typedef struct nwep_callbacks {
  nwep_on_connect on_connect;
  nwep_on_disconnect on_disconnect;
  nwep_on_request on_request;
  nwep_on_response on_response;
  nwep_on_notify on_notify;
  nwep_on_stream_data on_stream_data;
  nwep_on_stream_end on_stream_end;
  nwep_rand rand;
  nwep_log_callback log;
} nwep_callbacks;

/**
 * @struct
 *
 * :type:`nwep_settings` holds configuration settings.
 */
typedef struct nwep_settings {
  /**
   * :member:`max_streams` is the maximum concurrent streams (default 100).
   */
  uint32_t max_streams;
  /**
   * :member:`max_message_size` is the maximum message size (default 24MB).
   */
  uint32_t max_message_size;
  /**
   * :member:`timeout_ms` is the connection timeout in milliseconds (default 30000).
   */
  uint32_t timeout_ms;
  /**
   * :member:`compression` is the compression algorithm ("none" or "zstd").
   */
  const char *compression;
  /**
   * :member:`role` is the advertised role (server only, e.g., "regular_node").
   */
  const char *role;
} nwep_settings;

/**
 * @function
 *
 * `nwep_settings_default` initializes settings with default values.
 */
NWEP_EXTERN void nwep_settings_default(nwep_settings *settings);

/**
 * @struct
 *
 * :type:`nwep_path` represents a network path (local and remote addresses).
 */
typedef struct nwep_path {
  struct sockaddr_storage local_addr;
  size_t local_addrlen;
  struct sockaddr_storage remote_addr;
  size_t remote_addrlen;
} nwep_path;

/**
 * @function
 *
 * `nwep_init` initializes the nwep library.
 * Call this function before using any other nwep functions.
 * This initializes the underlying TLS/crypto library.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_init(void);

/**
 * @function
 *
 * `nwep_server_new` creates a new server instance.
 * |keypair| is the server's Ed25519 keypair (caller retains ownership).
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_server_new(nwep_server **pserver,
                                 const nwep_settings *settings,
                                 const nwep_callbacks *callbacks,
                                 nwep_keypair *keypair, void *user_data);

/**
 * @function
 *
 * `nwep_server_free` frees a server instance.
 */
NWEP_EXTERN void nwep_server_free(nwep_server *server);

/**
 * @function
 *
 * `nwep_server_read` processes a received packet.
 * |path| identifies the network path the packet arrived on.
 * |data| is the packet data, |datalen| is its length.
 * |ts| is the current timestamp in nanoseconds.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_server_read(nwep_server *server, const nwep_path *path,
                                  const uint8_t *data, size_t datalen,
                                  nwep_tstamp ts);

/**
 * @function
 *
 * `nwep_server_write` gets the next packet to send.
 * |path| receives the network path to send on.
 * |data| is the buffer to write to, |datalen| is its capacity.
 * |ts| is the current timestamp in nanoseconds.
 *
 * Returns the number of bytes written, 0 if no packet to send,
 * or a negative error code.
 */
NWEP_EXTERN nwep_ssize nwep_server_write(nwep_server *server, nwep_path *path,
                                          uint8_t *data, size_t datalen,
                                          nwep_tstamp ts);

/**
 * @function
 *
 * `nwep_server_handle_expiry` handles timer expiration.
 * Call this when the timer returned by nwep_server_get_expiry() fires.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_server_handle_expiry(nwep_server *server, nwep_tstamp ts);

/**
 * @function
 *
 * `nwep_server_get_expiry` gets the next timer deadline.
 *
 * Returns the deadline in nanoseconds, or UINT64_MAX if no timer is set.
 */
NWEP_EXTERN nwep_tstamp nwep_server_get_expiry(const nwep_server *server);

/**
 * @function
 *
 * `nwep_server_close` initiates graceful shutdown.
 */
NWEP_EXTERN void nwep_server_close(nwep_server *server);

/**
 * @function
 *
 * `nwep_client_new` creates a new client instance.
 * |keypair| is the client's Ed25519 keypair (caller retains ownership).
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_client_new(nwep_client **pclient,
                                 const nwep_settings *settings,
                                 const nwep_callbacks *callbacks,
                                 nwep_keypair *keypair, void *user_data);

/**
 * @function
 *
 * `nwep_client_free` frees a client instance.
 */
NWEP_EXTERN void nwep_client_free(nwep_client *client);

/**
 * @function
 *
 * `nwep_client_connect` initiates a connection to a web:// address.
 * |url| is the parsed URL containing address and path.
 * |local_addr| is the local address to bind to (can be NULL).
 * |ts| is the current timestamp in nanoseconds.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_client_connect(nwep_client *client, const nwep_url *url,
                                     const struct sockaddr *local_addr,
                                     size_t local_addrlen, nwep_tstamp ts);

/**
 * @function
 *
 * `nwep_client_read` processes a received packet.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_client_read(nwep_client *client, const nwep_path *path,
                                  const uint8_t *data, size_t datalen,
                                  nwep_tstamp ts);

/**
 * @function
 *
 * `nwep_client_write` gets the next packet to send.
 *
 * Returns the number of bytes written, 0 if no packet to send,
 * or a negative error code.
 */
NWEP_EXTERN nwep_ssize nwep_client_write(nwep_client *client, nwep_path *path,
                                          uint8_t *data, size_t datalen,
                                          nwep_tstamp ts);

/**
 * @function
 *
 * `nwep_client_handle_expiry` handles timer expiration.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_client_handle_expiry(nwep_client *client, nwep_tstamp ts);

/**
 * @function
 *
 * `nwep_client_get_expiry` gets the next timer deadline.
 *
 * Returns the deadline in nanoseconds, or UINT64_MAX if no timer is set.
 */
NWEP_EXTERN nwep_tstamp nwep_client_get_expiry(const nwep_client *client);

/**
 * @function
 *
 * `nwep_client_close` initiates graceful shutdown.
 */
NWEP_EXTERN void nwep_client_close(nwep_client *client);

/**
 * @function
 *
 * `nwep_client_get_conn` gets the connection for the client.
 * Returns NULL if not connected.
 */
NWEP_EXTERN nwep_conn *nwep_client_get_conn(nwep_client *client);

/**
 * @function
 *
 * `nwep_conn_get_peer_identity` gets the peer's identity.
 */
NWEP_EXTERN const nwep_identity *nwep_conn_get_peer_identity(
    const nwep_conn *conn);

/**
 * @function
 *
 * `nwep_conn_get_local_identity` gets our identity.
 */
NWEP_EXTERN const nwep_identity *nwep_conn_get_local_identity(
    const nwep_conn *conn);

/**
 * @function
 *
 * `nwep_conn_get_role` gets the negotiated role.
 */
NWEP_EXTERN const char *nwep_conn_get_role(const nwep_conn *conn);

/**
 * @function
 *
 * `nwep_conn_close` closes the connection with an error.
 * |error| is the error code (0 for graceful close).
 */
NWEP_EXTERN void nwep_conn_close(nwep_conn *conn, int error);

/**
 * @function
 *
 * `nwep_conn_get_user_data` gets the user data associated with the connection.
 */
NWEP_EXTERN void *nwep_conn_get_user_data(const nwep_conn *conn);

/**
 * @function
 *
 * `nwep_conn_set_user_data` sets user data for the connection.
 */
NWEP_EXTERN void nwep_conn_set_user_data(nwep_conn *conn, void *user_data);

/**
 * @function
 *
 * `nwep_stream_request` sends a request and returns the stream.
 * |req| contains the request to send.
 * |pstream| receives the stream pointer for response handling.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_stream_request(nwep_conn *conn, const nwep_request *req,
                                     nwep_stream **pstream);

/**
 * @function
 *
 * `nwep_stream_respond` sends a response on a stream (server-side).
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_stream_respond(nwep_stream *stream,
                                     const nwep_response *resp);

/**
 * @function
 *
 * `nwep_stream_write` writes body data to a stream.
 *
 * Returns the number of bytes written, or a negative error code.
 */
NWEP_EXTERN nwep_ssize nwep_stream_write(nwep_stream *stream,
                                          const uint8_t *data, size_t len);

/**
 * @function
 *
 * `nwep_stream_end` signals the end of the stream (sends FIN).
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_stream_end(nwep_stream *stream);

/**
 * @function
 *
 * `nwep_stream_close` closes the stream with an error (sends RESET).
 */
NWEP_EXTERN void nwep_stream_close(nwep_stream *stream, int error);

/**
 * @function
 *
 * `nwep_stream_get_id` gets the stream ID.
 */
NWEP_EXTERN int64_t nwep_stream_get_id(const nwep_stream *stream);

/**
 * @function
 *
 * `nwep_stream_get_user_data` gets user data for the stream.
 */
NWEP_EXTERN void *nwep_stream_get_user_data(const nwep_stream *stream);

/**
 * @function
 *
 * `nwep_stream_set_user_data` sets user data for the stream.
 */
NWEP_EXTERN void nwep_stream_set_user_data(nwep_stream *stream,
                                            void *user_data);

/**
 * @function
 *
 * `nwep_stream_get_conn` gets the connection for a stream.
 */
NWEP_EXTERN nwep_conn *nwep_stream_get_conn(const nwep_stream *stream);

/**
 * @function
 *
 * `nwep_conn_notify` sends a NOTIFY to client, opening a new stream.
 * |conn| must be a server connection. |pstream| receives the stream.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :macro:`NWEP_ERR_INTERNAL_INVALID_STATE`
 *     Connection is not a server or not connected.
 * :macro:`NWEP_ERR_INTERNAL_NOMEM`
 *     Out of memory.
 * :macro:`NWEP_ERR_NETWORK_QUIC`
 *     Stream ID blocked.
 */
NWEP_EXTERN int nwep_conn_notify(nwep_conn *conn, const nwep_notify *notify,
                                  nwep_stream **pstream);

/**
 * @function
 *
 * `nwep_notify_build` builds a NOTIFY message.
 *
 * This function returns 0 if it succeeds, or a negative error code.
 */
NWEP_EXTERN int nwep_notify_build(nwep_msg *msg, nwep_header *headers,
                                   size_t max_headers, const char *event,
                                   const char *path, const uint8_t *notify_id,
                                   const uint8_t *body, size_t body_len);

/**
 * @function
 *
 * `nwep_notify_parse` parses a message into a notify structure.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :macro:`NWEP_ERR_PROTO_INVALID_MESSAGE`
 *     Message is not a notify.
 * :macro:`NWEP_ERR_PROTO_MISSING_HEADER`
 *     Required header is missing.
 */
NWEP_EXTERN int nwep_notify_parse(nwep_notify *notify, const nwep_msg *msg);

/**
 * @function
 *
 * `nwep_stream_is_server_initiated` returns nonzero if the stream was
 * initiated by the server.
 */
NWEP_EXTERN int nwep_stream_is_server_initiated(const nwep_stream *stream);

/**
 * @macrosection
 *
 * BLS12-381 cryptography
 *
 * Types and functions for BLS12-381 signatures used by anchor servers
 * for threshold-signed checkpoints.
 */

/**
 * @macro
 *
 * :macro:`NWEP_BLS_PUBKEY_LEN` is the length of a compressed BLS public key.
 */
#define NWEP_BLS_PUBKEY_LEN 48

/**
 * @macro
 *
 * :macro:`NWEP_BLS_PRIVKEY_LEN` is the length of a BLS private key (scalar).
 */
#define NWEP_BLS_PRIVKEY_LEN 32

/**
 * @macro
 *
 * :macro:`NWEP_BLS_SIG_LEN` is the length of a compressed BLS signature.
 */
#define NWEP_BLS_SIG_LEN 96

/**
 * @macro
 *
 * :macro:`NWEP_CHECKPOINT_DST` is the domain separation tag for checkpoints.
 */
#define NWEP_CHECKPOINT_DST "WEB/1-CHECKPOINT"

/**
 * @macro
 *
 * :macro:`NWEP_DEFAULT_ANCHOR_THRESHOLD` is the default threshold (5-of-7).
 */
#define NWEP_DEFAULT_ANCHOR_THRESHOLD 5

/**
 * @macro
 *
 * :macro:`NWEP_MAX_ANCHORS` is the maximum number of anchors in a set.
 */
#define NWEP_MAX_ANCHORS 32

/**
 * @macro
 *
 * :macro:`NWEP_DEFAULT_EPOCH_INTERVAL` is the default epoch interval (1 hour).
 */
#define NWEP_DEFAULT_EPOCH_INTERVAL (3600ULL * NWEP_SECONDS)

/**
 * @struct
 *
 * :type:`nwep_bls_keypair` holds a BLS12-381 keypair.
 */
typedef struct nwep_bls_keypair {
  uint8_t pubkey[NWEP_BLS_PUBKEY_LEN];
  uint8_t privkey[NWEP_BLS_PRIVKEY_LEN];
} nwep_bls_keypair;

/**
 * @struct
 *
 * :type:`nwep_bls_pubkey` holds a BLS12-381 public key.
 */
typedef struct nwep_bls_pubkey {
  uint8_t data[NWEP_BLS_PUBKEY_LEN];
} nwep_bls_pubkey;

/**
 * @struct
 *
 * :type:`nwep_bls_sig` holds a BLS12-381 signature.
 */
typedef struct nwep_bls_sig {
  uint8_t data[NWEP_BLS_SIG_LEN];
} nwep_bls_sig;

/**
 * @function
 *
 * `nwep_bls_keypair_generate` generates a new BLS12-381 keypair.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_bls_keypair_generate(nwep_bls_keypair *kp);

/**
 * @function
 *
 * `nwep_bls_keypair_from_seed` generates a BLS keypair deterministically.
 *
 * |ikm| is the input keying material (at least 32 bytes recommended).
 * |ikm_len| is the length of ikm.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_bls_keypair_from_seed(nwep_bls_keypair *kp,
                                            const uint8_t *ikm, size_t ikm_len);

/**
 * @function
 *
 * `nwep_bls_pubkey_serialize` serializes a public key to bytes.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_bls_pubkey_serialize(uint8_t out[NWEP_BLS_PUBKEY_LEN],
                                           const nwep_bls_pubkey *pk);

/**
 * @function
 *
 * `nwep_bls_pubkey_deserialize` deserializes a public key from bytes.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_bls_pubkey_deserialize(nwep_bls_pubkey *pk,
                                             const uint8_t in[NWEP_BLS_PUBKEY_LEN]);

/**
 * @function
 *
 * `nwep_bls_sign` signs a message with a BLS private key.
 *
 * |sig| receives the signature.
 * |kp| is the keypair.
 * |msg| is the message to sign.
 * |msg_len| is the message length.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_bls_sign(nwep_bls_sig *sig, const nwep_bls_keypair *kp,
                               const uint8_t *msg, size_t msg_len);

/**
 * @function
 *
 * `nwep_bls_verify` verifies a BLS signature.
 *
 * Returns 0 on success (valid), or a negative error code.
 */
NWEP_EXTERN int nwep_bls_verify(const nwep_bls_pubkey *pk,
                                 const nwep_bls_sig *sig, const uint8_t *msg,
                                 size_t msg_len);

/**
 * @function
 *
 * `nwep_bls_aggregate_sigs` aggregates multiple BLS signatures.
 *
 * |out| receives the aggregated signature.
 * |sigs| is an array of signatures.
 * |n| is the number of signatures.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_bls_aggregate_sigs(nwep_bls_sig *out,
                                         const nwep_bls_sig *sigs, size_t n);

/**
 * @function
 *
 * `nwep_bls_verify_aggregate` verifies an aggregated BLS signature.
 *
 * All signers must have signed the same message.
 *
 * |pks| is an array of public keys.
 * |n| is the number of public keys.
 * |sig| is the aggregated signature.
 * |msg| is the message.
 * |msg_len| is the message length.
 *
 * Returns 0 on success (valid), or a negative error code.
 */
NWEP_EXTERN int nwep_bls_verify_aggregate(const nwep_bls_pubkey *pks, size_t n,
                                           const nwep_bls_sig *sig,
                                           const uint8_t *msg, size_t msg_len);

/**
 * @struct
 *
 * :type:`nwep_anchor_set` manages a set of trusted anchors.
 */
typedef struct nwep_anchor_set nwep_anchor_set;

/**
 * @function
 *
 * `nwep_anchor_set_new` creates a new anchor set.
 *
 * |threshold| is the number of anchors required for a valid checkpoint.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_anchor_set_new(nwep_anchor_set **pset, size_t threshold);

/**
 * @function
 *
 * `nwep_anchor_set_free` frees an anchor set.
 */
NWEP_EXTERN void nwep_anchor_set_free(nwep_anchor_set *set);

/**
 * @function
 *
 * `nwep_anchor_set_add` adds an anchor public key to the set.
 *
 * |builtin| indicates if this is a built-in anchor (cannot be removed).
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_anchor_set_add(nwep_anchor_set *set,
                                     const nwep_bls_pubkey *pk, int builtin);

/**
 * @function
 *
 * `nwep_anchor_set_remove` removes an anchor from the set.
 *
 * Built-in anchors cannot be removed.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_anchor_set_remove(nwep_anchor_set *set,
                                        const nwep_bls_pubkey *pk);

/**
 * @function
 *
 * `nwep_anchor_set_size` returns the number of anchors in the set.
 */
NWEP_EXTERN size_t nwep_anchor_set_size(const nwep_anchor_set *set);

/**
 * @function
 *
 * `nwep_anchor_set_get` retrieves an anchor by index.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_anchor_set_get(const nwep_anchor_set *set, size_t idx,
                                     nwep_bls_pubkey *pk, int *builtin);

/**
 * @function
 *
 * `nwep_anchor_set_threshold` returns the threshold for the set.
 */
NWEP_EXTERN size_t nwep_anchor_set_threshold(const nwep_anchor_set *set);

/**
 * @function
 *
 * `nwep_anchor_set_contains` checks if a public key is in the set.
 *
 * Returns 1 if found, 0 if not found.
 */
NWEP_EXTERN int nwep_anchor_set_contains(const nwep_anchor_set *set,
                                          const nwep_bls_pubkey *pk);

/**
 * @macrosection
 *
 * Epoch checkpoints
 *
 * Signed checkpoints commit to the Merkle log state at a point in time.
 * Multiple anchors sign checkpoints to create threshold trust.
 */

/**
 * @struct
 *
 * :type:`nwep_checkpoint` represents a signed epoch checkpoint.
 */
typedef struct nwep_checkpoint {
  uint64_t epoch;
  nwep_tstamp timestamp;
  nwep_merkle_hash merkle_root;
  uint64_t log_size;
  nwep_bls_sig signature;
  nwep_bls_pubkey signers[NWEP_MAX_ANCHORS];
  size_t num_signers;
} nwep_checkpoint;

/**
 * @function
 *
 * `nwep_checkpoint_new` creates a new checkpoint proposal.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_checkpoint_new(nwep_checkpoint *cp, uint64_t epoch,
                                     nwep_tstamp timestamp,
                                     const nwep_merkle_hash *merkle_root,
                                     uint64_t log_size);

/**
 * @function
 *
 * `nwep_checkpoint_sign` signs a checkpoint with an anchor's key.
 *
 * Adds the signature to the checkpoint's aggregated signature.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_checkpoint_sign(nwep_checkpoint *cp,
                                      const nwep_bls_keypair *anchor_kp);

/**
 * @function
 *
 * `nwep_checkpoint_verify` verifies a checkpoint's signatures.
 *
 * |anchor_set| is the trusted anchor set.
 *
 * Returns 0 if valid (threshold reached), or a negative error code.
 */
NWEP_EXTERN int nwep_checkpoint_verify(const nwep_checkpoint *cp,
                                        const nwep_anchor_set *anchor_set);

/**
 * @function
 *
 * `nwep_checkpoint_encode` serializes a checkpoint.
 *
 * Returns the number of bytes written, or a negative error code.
 */
NWEP_EXTERN nwep_ssize nwep_checkpoint_encode(uint8_t *buf, size_t buflen,
                                               const nwep_checkpoint *cp);

/**
 * @function
 *
 * `nwep_checkpoint_decode` deserializes a checkpoint.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_checkpoint_decode(nwep_checkpoint *cp, const uint8_t *data,
                                        size_t datalen);

/**
 * @function
 *
 * `nwep_checkpoint_message` computes the message to be signed.
 *
 * This is the canonical encoding: epoch || timestamp || merkle_root || log_size
 *
 * Returns the number of bytes written (always 56), or a negative error code.
 */
NWEP_EXTERN nwep_ssize nwep_checkpoint_message(uint8_t *buf, size_t buflen,
                                                const nwep_checkpoint *cp);

/**
 * @macrosection
 *
 * Trust store
 *
 * Client-side trust management: stores verified anchors and checkpoints,
 * verifies identities against the Merkle log, and detects stale data.
 */

/**
 * @macro
 *
 * :macro:`NWEP_STALENESS_WARNING_NS` is the warning threshold (1 hour).
 */
#define NWEP_STALENESS_WARNING_NS (3600ULL * NWEP_SECONDS)

/**
 * @macro
 *
 * :macro:`NWEP_STALENESS_REJECT_NS` is the rejection threshold (24 hours).
 */
#define NWEP_STALENESS_REJECT_NS (86400ULL * NWEP_SECONDS)

/**
 * @macro
 *
 * :macro:`NWEP_IDENTITY_CACHE_TTL` is the default identity cache TTL (1 hour).
 */
#define NWEP_IDENTITY_CACHE_TTL (3600ULL * NWEP_SECONDS)

/**
 * @macro
 *
 * :macro:`NWEP_MAX_CHECKPOINTS` is the max checkpoints stored in trust store.
 */
#define NWEP_MAX_CHECKPOINTS 168

/**
 * @callback
 *
 * `nwep_trust_anchor_load_cb` loads anchors from persistent storage.
 * Returns number of anchors loaded, or negative error code.
 */
typedef int (*nwep_trust_anchor_load_cb)(void *user_data,
                                          nwep_bls_pubkey *anchors,
                                          size_t max_anchors);

/**
 * @callback
 *
 * `nwep_trust_anchor_save_cb` saves anchors to persistent storage.
 * Returns 0 on success, or negative error code.
 */
typedef int (*nwep_trust_anchor_save_cb)(void *user_data,
                                          const nwep_bls_pubkey *anchors,
                                          size_t count);

/**
 * @callback
 *
 * `nwep_trust_checkpoint_load_cb` loads checkpoints from persistent storage.
 * Returns number of checkpoints loaded, or negative error code.
 */
typedef int (*nwep_trust_checkpoint_load_cb)(void *user_data,
                                              nwep_checkpoint *checkpoints,
                                              size_t max_checkpoints);

/**
 * @callback
 *
 * `nwep_trust_checkpoint_save_cb` saves a checkpoint to persistent storage.
 * Returns 0 on success, or negative error code.
 */
typedef int (*nwep_trust_checkpoint_save_cb)(void *user_data,
                                              const nwep_checkpoint *cp);

/**
 * @struct
 *
 * :type:`nwep_trust_storage` holds optional persistence callbacks.
 */
typedef struct nwep_trust_storage {
  nwep_trust_anchor_load_cb anchor_load;
  nwep_trust_anchor_save_cb anchor_save;
  nwep_trust_checkpoint_load_cb checkpoint_load;
  nwep_trust_checkpoint_save_cb checkpoint_save;
  void *user_data;
} nwep_trust_storage;

/**
 * @struct
 *
 * :type:`nwep_trust_store` manages trusted anchors and checkpoints.
 */
typedef struct nwep_trust_store nwep_trust_store;

/**
 * @struct
 *
 * :type:`nwep_trust_settings` configures trust store behavior.
 */
typedef struct nwep_trust_settings {
  /**
   * :member:`staleness_warning_ns` is the warning threshold in nanoseconds.
   * Default: NWEP_STALENESS_WARNING_NS (1 hour).
   */
  nwep_duration staleness_warning_ns;
  /**
   * :member:`staleness_reject_ns` is the rejection threshold in nanoseconds.
   * Default: NWEP_STALENESS_REJECT_NS (24 hours).
   */
  nwep_duration staleness_reject_ns;
  /**
   * :member:`identity_cache_ttl` is the identity cache TTL in nanoseconds.
   * Default: NWEP_IDENTITY_CACHE_TTL (1 hour).
   */
  nwep_duration identity_cache_ttl;
  /**
   * :member:`anchor_threshold` is the minimum anchors for valid checkpoint.
   * Default: NWEP_DEFAULT_ANCHOR_THRESHOLD.
   */
  size_t anchor_threshold;
} nwep_trust_settings;

/**
 * @function
 *
 * `nwep_trust_settings_default` initializes settings to defaults.
 */
NWEP_EXTERN void nwep_trust_settings_default(nwep_trust_settings *settings);

/**
 * @function
 *
 * `nwep_trust_store_new` creates a new trust store.
 *
 * |settings| configures behavior (NULL for defaults).
 * |storage| provides optional persistence (NULL for in-memory only).
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_trust_store_new(nwep_trust_store **pstore,
                                      const nwep_trust_settings *settings,
                                      const nwep_trust_storage *storage);

/**
 * @function
 *
 * `nwep_trust_store_free` frees a trust store.
 */
NWEP_EXTERN void nwep_trust_store_free(nwep_trust_store *store);

/**
 * @function
 *
 * `nwep_trust_store_add_anchor` adds a trusted anchor.
 *
 * |builtin| indicates if this is a built-in anchor (cannot be removed).
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_trust_store_add_anchor(nwep_trust_store *store,
                                             const nwep_bls_pubkey *pk,
                                             int builtin);

/**
 * @function
 *
 * `nwep_trust_store_remove_anchor` removes a non-builtin anchor.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_trust_store_remove_anchor(nwep_trust_store *store,
                                                const nwep_bls_pubkey *pk);

/**
 * @function
 *
 * `nwep_trust_store_get_anchors` retrieves the anchor set.
 *
 * The returned anchor set is owned by the trust store; do not free it.
 */
NWEP_EXTERN const nwep_anchor_set *
nwep_trust_store_get_anchors(const nwep_trust_store *store);

/**
 * @function
 *
 * `nwep_trust_store_add_checkpoint` adds a verified checkpoint.
 *
 * The checkpoint is verified against the anchor set before storing.
 *
 * Returns 0 on success, or one of the following negative error codes:
 *
 * :macro:`NWEP_ERR_TRUST_QUORUM_NOT_REACHED`
 *     Checkpoint does not have enough valid signatures.
 * :macro:`NWEP_ERR_CRYPTO_SIGN_FAILED`
 *     Signature verification failed.
 */
NWEP_EXTERN int nwep_trust_store_add_checkpoint(nwep_trust_store *store,
                                                 const nwep_checkpoint *cp);

/**
 * @function
 *
 * `nwep_trust_store_get_latest_checkpoint` retrieves the most recent checkpoint.
 *
 * Returns 0 on success, or NWEP_ERR_TRUST_ENTRY_NOT_FOUND if no checkpoints.
 */
NWEP_EXTERN int
nwep_trust_store_get_latest_checkpoint(const nwep_trust_store *store,
                                        nwep_checkpoint *cp);

/**
 * @function
 *
 * `nwep_trust_store_get_checkpoint` retrieves a checkpoint by epoch.
 *
 * Returns 0 on success, or NWEP_ERR_TRUST_ENTRY_NOT_FOUND if not found.
 */
NWEP_EXTERN int nwep_trust_store_get_checkpoint(const nwep_trust_store *store,
                                                 uint64_t epoch,
                                                 nwep_checkpoint *cp);

/**
 * @function
 *
 * `nwep_trust_store_checkpoint_count` returns number of stored checkpoints.
 */
NWEP_EXTERN size_t
nwep_trust_store_checkpoint_count(const nwep_trust_store *store);

/**
 * @enum
 *
 * :type:`nwep_staleness` indicates checkpoint freshness status.
 */
typedef enum nwep_staleness {
  NWEP_STALENESS_FRESH = 0,
  NWEP_STALENESS_WARNING = 1,
  NWEP_STALENESS_REJECT = 2
} nwep_staleness;

/**
 * @function
 *
 * `nwep_trust_store_check_staleness` checks checkpoint freshness.
 *
 * |now| is the current timestamp.
 *
 * Returns staleness status.
 */
NWEP_EXTERN nwep_staleness
nwep_trust_store_check_staleness(const nwep_trust_store *store, nwep_tstamp now);

/**
 * @function
 *
 * `nwep_trust_store_get_staleness_age` returns age since last checkpoint.
 *
 * Returns 0 if no checkpoints stored.
 */
NWEP_EXTERN nwep_duration
nwep_trust_store_get_staleness_age(const nwep_trust_store *store,
                                    nwep_tstamp now);

/**
 * @struct
 *
 * :type:`nwep_verified_identity` holds a verified identity with proof.
 */
typedef struct nwep_verified_identity {
  nwep_nodeid nodeid;
  uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN];
  uint64_t log_index;
  uint64_t checkpoint_epoch;
  nwep_tstamp verified_at;
  int revoked;
} nwep_verified_identity;

/**
 * @function
 *
 * `nwep_trust_store_verify_identity` verifies an identity against a checkpoint.
 *
 * |entry| is the log entry claiming the identity.
 * |proof| is the inclusion proof for the entry.
 * |checkpoint| is the checkpoint to verify against (NULL for latest).
 *
 * Returns 0 if valid, or one of the following negative error codes:
 *
 * :macro:`NWEP_ERR_TRUST_INVALID_PROOF`
 *     Proof does not verify against checkpoint merkle root.
 * :macro:`NWEP_ERR_TRUST_ENTRY_NOT_FOUND`
 *     No checkpoints available.
 * :macro:`NWEP_ERR_TRUST_CHECKPOINT_STALE`
 *     Checkpoint is too old.
 */
NWEP_EXTERN int nwep_trust_store_verify_identity(
    nwep_trust_store *store, const nwep_merkle_entry *entry,
    const nwep_merkle_proof *proof, const nwep_checkpoint *checkpoint,
    nwep_tstamp now, nwep_verified_identity *result);

/**
 * @function
 *
 * `nwep_trust_store_cache_identity` caches a verified identity.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int
nwep_trust_store_cache_identity(nwep_trust_store *store,
                                 const nwep_verified_identity *identity);

/**
 * @function
 *
 * `nwep_trust_store_lookup_identity` looks up a cached identity by NodeID.
 *
 * Returns 0 if found and valid, or NWEP_ERR_TRUST_NODE_NOT_FOUND.
 */
NWEP_EXTERN int nwep_trust_store_lookup_identity(const nwep_trust_store *store,
                                                  const nwep_nodeid *nodeid,
                                                  nwep_tstamp now,
                                                  nwep_verified_identity *out);

/**
 * @struct
 *
 * :type:`nwep_equivocation` describes a detected equivocation.
 */
typedef struct nwep_equivocation {
  nwep_bls_pubkey anchor;
  uint64_t epoch;
  nwep_merkle_hash root1;
  nwep_merkle_hash root2;
} nwep_equivocation;

/**
 * @function
 *
 * `nwep_trust_store_check_equivocation` checks for conflicting checkpoints.
 *
 * Compares |cp| against stored checkpoints for the same epoch.
 *
 * Returns 0 if no equivocation, or NWEP_ERR_TRUST_EQUIVOCATION if detected.
 * If detected, |out| receives details (if not NULL).
 */
NWEP_EXTERN int nwep_trust_store_check_equivocation(nwep_trust_store *store,
                                                     const nwep_checkpoint *cp,
                                                     nwep_equivocation *out);
/**
 * @enum
 *
 * :type:`nwep_server_role` defines the server role types.
 */
typedef enum nwep_server_role {
  /**
   * :enum:`NWEP_ROLE_REGULAR` is a regular node (client connections, forwarding).
   */
  NWEP_ROLE_REGULAR = 0,
  /**
   * :enum:`NWEP_ROLE_LOG_SERVER` is a Merkle log server.
   */
  NWEP_ROLE_LOG_SERVER = 1,
  /**
   * :enum:`NWEP_ROLE_ANCHOR` is an anchor server (checkpoint signing).
   */
  NWEP_ROLE_ANCHOR = 2
} nwep_server_role;

/**
 * @macro
 *
 * :macro:`NWEP_ROLE_STR_REGULAR` is the string representation of regular role.
 */
#define NWEP_ROLE_STR_REGULAR "regular"

/**
 * @macro
 *
 * :macro:`NWEP_ROLE_STR_LOG_SERVER` is the string representation of log server role.
 */
#define NWEP_ROLE_STR_LOG_SERVER "log_server"

/**
 * @macro
 *
 * :macro:`NWEP_ROLE_STR_ANCHOR` is the string representation of anchor role.
 */
#define NWEP_ROLE_STR_ANCHOR "anchor"

/**
 * @function
 *
 * `nwep_role_from_str` converts a role string to enum.
 *
 * Returns the role enum, or NWEP_ROLE_REGULAR if unknown.
 */
NWEP_EXTERN nwep_server_role nwep_role_from_str(const char *role_str);

/**
 * @function
 *
 * `nwep_role_to_str` converts a role enum to string.
 *
 * Returns the role string.
 */
NWEP_EXTERN const char *nwep_role_to_str(nwep_server_role role);

/**
 * @struct
 *
 * :type:`nwep_log_server` is an opaque log server handle.
 */
typedef struct nwep_log_server nwep_log_server;

/**
 * @callback
 *
 * `nwep_log_authorize_cb` checks if a client is authorized to write entries.
 *
 * |nodeid| is the client's NodeID.
 * |entry| is the entry they want to write.
 *
 * Returns 0 if authorized, or NWEP_ERR_PROTO_UNAUTHORIZED if not.
 */
typedef int (*nwep_log_authorize_cb)(void *user_data, const nwep_nodeid *nodeid,
                                      const nwep_merkle_entry *entry);

/**
 * @struct
 *
 * :type:`nwep_log_server_settings` configures log server behavior.
 */
typedef struct nwep_log_server_settings {
  /**
   * :member:`authorize` is called before accepting write requests.
   * If NULL, only read operations are allowed.
   */
  nwep_log_authorize_cb authorize;
  /**
   * :member:`user_data` is passed to callbacks.
   */
  void *user_data;
} nwep_log_server_settings;

/**
 * @function
 *
 * `nwep_log_server_new` creates a new log server.
 *
 * |log| is the Merkle log to serve.
 * |settings| configures server behavior (NULL for defaults).
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_log_server_new(nwep_log_server **pserver,
                                     nwep_merkle_log *log,
                                     const nwep_log_server_settings *settings);

/**
 * @function
 *
 * `nwep_log_server_free` frees a log server.
 */
NWEP_EXTERN void nwep_log_server_free(nwep_log_server *server);

/**
 * @function
 *
 * `nwep_log_server_handle_request` handles a log server request.
 *
 * Handles paths:
 * - READ /log/entry/{index} - returns entry at index
 * - READ /log/proof/{index} - returns inclusion proof
 * - READ /log/size - returns current log size
 * - WRITE /log/entry - appends entry (if authorized)
 *
 * |stream| is the stream to respond on.
 * |request| is the incoming request.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_log_server_handle_request(nwep_log_server *server,
                                                nwep_stream *stream,
                                                const nwep_request *request);

/**
 * @function
 *
 * `nwep_log_server_get_log` returns the underlying Merkle log.
 */
NWEP_EXTERN nwep_merkle_log *nwep_log_server_get_log(nwep_log_server *server);

/**
 * @struct
 *
 * :type:`nwep_anchor_server` is an opaque anchor server handle.
 */
typedef struct nwep_anchor_server nwep_anchor_server;

/**
 * @callback
 *
 * `nwep_anchor_proposal_cb` is called when a checkpoint proposal is received.
 *
 * |cp| is the proposed checkpoint.
 * Returns 0 to sign and accept, or a negative error code to reject.
 */
typedef int (*nwep_anchor_proposal_cb)(void *user_data,
                                        const nwep_checkpoint *cp);

/**
 * @struct
 *
 * :type:`nwep_anchor_server_settings` configures anchor server behavior.
 */
typedef struct nwep_anchor_server_settings {
  /**
   * :member:`on_proposal` is called when receiving checkpoint proposals.
   * If NULL, all valid proposals are signed.
   */
  nwep_anchor_proposal_cb on_proposal;
  /**
   * :member:`user_data` is passed to callbacks.
   */
  void *user_data;
} nwep_anchor_server_settings;

/**
 * @function
 *
 * `nwep_anchor_server_new` creates a new anchor server.
 *
 * |keypair| is the BLS keypair for signing checkpoints.
 * |anchors| is the trusted anchor set.
 * |settings| configures server behavior (NULL for defaults).
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_anchor_server_new(nwep_anchor_server **pserver,
                                        const nwep_bls_keypair *keypair,
                                        nwep_anchor_set *anchors,
                                        const nwep_anchor_server_settings *settings);

/**
 * @function
 *
 * `nwep_anchor_server_free` frees an anchor server.
 */
NWEP_EXTERN void nwep_anchor_server_free(nwep_anchor_server *server);

/**
 * @function
 *
 * `nwep_anchor_server_handle_request` handles an anchor server request.
 *
 * Handles paths:
 * - READ /checkpoint/latest - returns latest finalized checkpoint
 * - READ /checkpoint/{epoch} - returns checkpoint for specific epoch
 * - WRITE /checkpoint/propose - receives checkpoint proposal
 * - WRITE /checkpoint/signature - receives signature for proposal
 *
 * |stream| is the stream to respond on.
 * |request| is the incoming request.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_anchor_server_handle_request(nwep_anchor_server *server,
                                                   nwep_stream *stream,
                                                   const nwep_request *request);

/**
 * @function
 *
 * `nwep_anchor_server_add_checkpoint` adds a finalized checkpoint.
 *
 * Call this after collecting enough signatures for a checkpoint.
 */
NWEP_EXTERN int nwep_anchor_server_add_checkpoint(nwep_anchor_server *server,
                                                   const nwep_checkpoint *cp);

/**
 * @function
 *
 * `nwep_anchor_server_get_latest` gets the latest finalized checkpoint.
 *
 * Returns 0 on success, or NWEP_ERR_TRUST_ENTRY_NOT_FOUND if none.
 */
NWEP_EXTERN int nwep_anchor_server_get_latest(const nwep_anchor_server *server,
                                               nwep_checkpoint *cp);

/**
 * @function
 *
 * `nwep_anchor_server_get_checkpoint` gets a checkpoint by epoch.
 *
 * Returns 0 on success, or NWEP_ERR_TRUST_ENTRY_NOT_FOUND if not found.
 */
NWEP_EXTERN int nwep_anchor_server_get_checkpoint(const nwep_anchor_server *server,
                                                   uint64_t epoch,
                                                   nwep_checkpoint *cp);

/**
 * @function
 *
 * `nwep_anchor_server_create_proposal` creates a checkpoint proposal.
 *
 * |log| is the Merkle log to checkpoint.
 * |epoch| is the epoch number.
 * |timestamp| is the checkpoint timestamp.
 * |cp| receives the unsigned checkpoint proposal.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_anchor_server_create_proposal(nwep_anchor_server *server,
                                                    nwep_merkle_log *log,
                                                    uint64_t epoch,
                                                    nwep_tstamp timestamp,
                                                    nwep_checkpoint *cp);

/**
 * @function
 *
 * `nwep_anchor_server_sign_proposal` signs a checkpoint proposal.
 *
 * |cp| is the checkpoint to sign (modified in place with signature).
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_anchor_server_sign_proposal(nwep_anchor_server *server,
                                                  nwep_checkpoint *cp);

/**
 * @function
 *
 * `nwep_conn_get_peer_role` gets the peer's announced server role.
 *
 * Returns the role enum, or NWEP_ROLE_REGULAR if not specified.
 */
NWEP_EXTERN nwep_server_role nwep_conn_get_peer_role(const nwep_conn *conn);

/**
 * @function
 *
 * `nwep_conn_set_required_role` sets the required role for the connection.
 *
 * Call before connecting. The connection will fail if the server
 * doesn't have the required role.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_conn_set_required_role(nwep_conn *conn,
                                             nwep_server_role role);

/**
 * @macrosection
 *
 * Caching and load balancing
 *
 * Optional infrastructure for caching verified identities and load
 * balancing across log server pools. Users can implement their own
 * caching strategies or use these built-in implementations.
 */

/**
 * @macro
 *
 * :macro:`NWEP_CACHE_DEFAULT_CAPACITY` is the default cache capacity.
 */
#define NWEP_CACHE_DEFAULT_CAPACITY 10000

/**
 * @macro
 *
 * :macro:`NWEP_CACHE_DEFAULT_TTL_NS` is the default TTL (1 hour).
 */
#define NWEP_CACHE_DEFAULT_TTL_NS (3600ULL * NWEP_SECONDS)

/**
 * @macro
 *
 * :macro:`NWEP_POOL_MAX_SERVERS` is the maximum servers in a pool.
 */
#define NWEP_POOL_MAX_SERVERS 32

/**
 * @macro
 *
 * :macro:`NWEP_POOL_HEALTH_CHECK_FAILURES` is failures before marking unhealthy.
 */
#define NWEP_POOL_HEALTH_CHECK_FAILURES 3

/**
 * @struct
 *
 * :type:`nwep_identity_cache` is an opaque identity cache handle.
 */
typedef struct nwep_identity_cache nwep_identity_cache;

/**
 * @struct
 *
 * :type:`nwep_cached_identity` represents a cached verified identity.
 */
typedef struct nwep_cached_identity {
  nwep_nodeid nodeid;
  uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN];
  uint64_t log_index;
  nwep_tstamp verified_at;
  nwep_tstamp expires_at;
} nwep_cached_identity;

/**
 * @struct
 *
 * :type:`nwep_identity_cache_settings` configures cache behavior.
 */
typedef struct nwep_identity_cache_settings {
  /**
   * :member:`capacity` is the maximum number of entries.
   * Default: NWEP_CACHE_DEFAULT_CAPACITY (10000)
   */
  size_t capacity;
  /**
   * :member:`ttl_ns` is the TTL in nanoseconds.
   * Default: NWEP_CACHE_DEFAULT_TTL_NS (1 hour)
   */
  nwep_tstamp ttl_ns;
} nwep_identity_cache_settings;

/**
 * @function
 *
 * `nwep_identity_cache_settings_default` initializes settings to defaults.
 */
NWEP_EXTERN void
nwep_identity_cache_settings_default(nwep_identity_cache_settings *settings);

/**
 * @function
 *
 * `nwep_identity_cache_new` creates a new identity cache.
 *
 * |settings| configures cache behavior (NULL for defaults).
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_identity_cache_new(nwep_identity_cache **pcache,
                                         const nwep_identity_cache_settings *settings);

/**
 * @function
 *
 * `nwep_identity_cache_free` frees an identity cache.
 */
NWEP_EXTERN void nwep_identity_cache_free(nwep_identity_cache *cache);

/**
 * @function
 *
 * `nwep_identity_cache_lookup` looks up an identity by NodeID.
 *
 * |now| is the current timestamp for TTL checking.
 * |identity| receives the cached identity if found and not expired.
 *
 * Returns 0 on success, NWEP_ERR_TRUST_ENTRY_NOT_FOUND if not found or expired.
 */
NWEP_EXTERN int nwep_identity_cache_lookup(nwep_identity_cache *cache,
                                            const nwep_nodeid *nodeid,
                                            nwep_tstamp now,
                                            nwep_cached_identity *identity);

/**
 * @function
 *
 * `nwep_identity_cache_store` stores a verified identity.
 *
 * |now| is the current timestamp for setting verified_at and expires_at.
 * |nodeid| is the NodeID to cache.
 * |pubkey| is the verified public key.
 * |log_index| is the log index where the identity was verified.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_identity_cache_store(nwep_identity_cache *cache,
                                           const nwep_nodeid *nodeid,
                                           const uint8_t pubkey[NWEP_ED25519_PUBKEY_LEN],
                                           uint64_t log_index,
                                           nwep_tstamp now);

/**
 * @function
 *
 * `nwep_identity_cache_invalidate` invalidates an entry by NodeID.
 *
 * Returns 0 on success, NWEP_ERR_TRUST_ENTRY_NOT_FOUND if not found.
 */
NWEP_EXTERN int nwep_identity_cache_invalidate(nwep_identity_cache *cache,
                                                const nwep_nodeid *nodeid);

/**
 * @function
 *
 * `nwep_identity_cache_clear` clears all entries from the cache.
 */
NWEP_EXTERN void nwep_identity_cache_clear(nwep_identity_cache *cache);

/**
 * @function
 *
 * `nwep_identity_cache_size` returns the number of entries in the cache.
 */
NWEP_EXTERN size_t nwep_identity_cache_size(const nwep_identity_cache *cache);

/**
 * @function
 *
 * `nwep_identity_cache_capacity` returns the cache capacity.
 */
NWEP_EXTERN size_t nwep_identity_cache_capacity(const nwep_identity_cache *cache);

/**
 * @function
 *
 * `nwep_identity_cache_on_rotation` handles key rotation notification.
 *
 * Invalidates the cached identity for |nodeid| since the key has changed.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_identity_cache_on_rotation(nwep_identity_cache *cache,
                                                 const nwep_nodeid *nodeid,
                                                 const uint8_t new_pubkey[NWEP_ED25519_PUBKEY_LEN],
                                                 uint64_t new_log_index,
                                                 nwep_tstamp now);

/**
 * @function
 *
 * `nwep_identity_cache_on_revocation` handles key revocation notification.
 *
 * Invalidates the cached identity for |nodeid| since the key has been revoked.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_identity_cache_on_revocation(nwep_identity_cache *cache,
                                                   const nwep_nodeid *nodeid);

/**
 * @struct
 *
 * :type:`nwep_log_server_pool` is an opaque server pool handle.
 */
typedef struct nwep_log_server_pool nwep_log_server_pool;

/**
 * @enum
 *
 * :type:`nwep_pool_strategy` defines the load balancing strategy.
 */
typedef enum nwep_pool_strategy {
  /**
   * :enum:`NWEP_POOL_ROUND_ROBIN` selects servers in round-robin order.
   */
  NWEP_POOL_ROUND_ROBIN = 0,
  /**
   * :enum:`NWEP_POOL_RANDOM` selects servers randomly.
   */
  NWEP_POOL_RANDOM = 1
} nwep_pool_strategy;

/**
 * @enum
 *
 * :type:`nwep_server_health` indicates server health status.
 */
typedef enum nwep_server_health {
  /**
   * :enum:`NWEP_SERVER_HEALTHY` means the server is responding normally.
   */
  NWEP_SERVER_HEALTHY = 0,
  /**
   * :enum:`NWEP_SERVER_UNHEALTHY` means the server has failed health checks.
   */
  NWEP_SERVER_UNHEALTHY = 1
} nwep_server_health;

/**
 * @struct
 *
 * :type:`nwep_pool_server` represents a server in the pool.
 */
typedef struct nwep_pool_server {
  char url[256];
  nwep_server_health health;
  int consecutive_failures;
  nwep_tstamp last_success;
  nwep_tstamp last_failure;
} nwep_pool_server;

/**
 * @struct
 *
 * :type:`nwep_log_server_pool_settings` configures pool behavior.
 */
typedef struct nwep_log_server_pool_settings {
  /**
   * :member:`strategy` is the load balancing strategy.
   */
  nwep_pool_strategy strategy;
  /**
   * :member:`max_failures` is failures before marking unhealthy.
   * Default: NWEP_POOL_HEALTH_CHECK_FAILURES (3)
   */
  int max_failures;
  /**
   * :member:`rand` is the random callback for RANDOM strategy.
   */
  nwep_rand rand;
} nwep_log_server_pool_settings;

/**
 * @function
 *
 * `nwep_log_server_pool_settings_default` initializes settings to defaults.
 */
NWEP_EXTERN void
nwep_log_server_pool_settings_default(nwep_log_server_pool_settings *settings);

/**
 * @function
 *
 * `nwep_log_server_pool_new` creates a new log server pool.
 *
 * |settings| configures pool behavior (NULL for defaults).
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_log_server_pool_new(nwep_log_server_pool **ppool,
                                          const nwep_log_server_pool_settings *settings);

/**
 * @function
 *
 * `nwep_log_server_pool_free` frees a log server pool.
 */
NWEP_EXTERN void nwep_log_server_pool_free(nwep_log_server_pool *pool);

/**
 * @function
 *
 * `nwep_log_server_pool_add` adds a server to the pool.
 *
 * |url| is the server URL (e.g., "web://...").
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_log_server_pool_add(nwep_log_server_pool *pool,
                                          const char *url);

/**
 * @function
 *
 * `nwep_log_server_pool_remove` removes a server from the pool.
 *
 * Returns 0 on success, NWEP_ERR_TRUST_ENTRY_NOT_FOUND if not found.
 */
NWEP_EXTERN int nwep_log_server_pool_remove(nwep_log_server_pool *pool,
                                             const char *url);

/**
 * @function
 *
 * `nwep_log_server_pool_select` selects a healthy server from the pool.
 *
 * |server| receives the selected server info.
 *
 * Returns 0 on success, NWEP_ERR_NETWORK_NO_SERVERS if no healthy servers.
 */
NWEP_EXTERN int nwep_log_server_pool_select(nwep_log_server_pool *pool,
                                             nwep_pool_server *server);

/**
 * @function
 *
 * `nwep_log_server_pool_mark_success` marks a server as successful.
 *
 * Resets failure count and updates last_success timestamp.
 */
NWEP_EXTERN void nwep_log_server_pool_mark_success(nwep_log_server_pool *pool,
                                                    const char *url,
                                                    nwep_tstamp now);

/**
 * @function
 *
 * `nwep_log_server_pool_mark_failure` marks a server as failed.
 *
 * Increments failure count and may mark server unhealthy.
 */
NWEP_EXTERN void nwep_log_server_pool_mark_failure(nwep_log_server_pool *pool,
                                                    const char *url,
                                                    nwep_tstamp now);

/**
 * @function
 *
 * `nwep_log_server_pool_size` returns the number of servers in the pool.
 */
NWEP_EXTERN size_t nwep_log_server_pool_size(const nwep_log_server_pool *pool);

/**
 * @function
 *
 * `nwep_log_server_pool_healthy_count` returns the number of healthy servers.
 */
NWEP_EXTERN size_t nwep_log_server_pool_healthy_count(const nwep_log_server_pool *pool);

/**
 * @function
 *
 * `nwep_log_server_pool_get` gets a server by index.
 *
 * Returns 0 on success, or a negative error code.
 */
NWEP_EXTERN int nwep_log_server_pool_get(const nwep_log_server_pool *pool,
                                          size_t index,
                                          nwep_pool_server *server);

/**
 * @function
 *
 * `nwep_log_server_pool_reset_health` resets all servers to healthy.
 */
NWEP_EXTERN void nwep_log_server_pool_reset_health(nwep_log_server_pool *pool);

/**
 * @struct
 *
 * :type:`nwep_cache_stats` holds cache statistics.
 */
typedef struct nwep_cache_stats {
  uint64_t hits;
  uint64_t misses;
  uint64_t evictions;
  uint64_t stores;
  uint64_t invalidations;
} nwep_cache_stats;

/**
 * @function
 *
 * `nwep_identity_cache_get_stats` gets cache statistics.
 */
NWEP_EXTERN void nwep_identity_cache_get_stats(const nwep_identity_cache *cache,
                                                nwep_cache_stats *stats);

/**
 * @function
 *
 * `nwep_identity_cache_reset_stats` resets cache statistics.
 */
NWEP_EXTERN void nwep_identity_cache_reset_stats(nwep_identity_cache *cache);

#ifdef __cplusplus
}
#endif

#endif /* !defined(NWEP_H) */
