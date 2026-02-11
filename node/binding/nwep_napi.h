#ifndef NWEP_NAPI_H
#define NWEP_NAPI_H

#include <node_api.h>
#include <nwep/nwep.h>
#include <string.h>

/*
 * nwep_napi_throw throws a JS Error with the nwep error string.
 * Returns NULL (suitable for returning from napi_callback).
 */
static inline napi_value nwep_napi_throw(napi_env env, int rv) {
  napi_throw_error(env, NULL, nwep_strerror(rv));
  return NULL;
}

/*
 * nwep_napi_throw_msg throws a JS Error with a custom message.
 * Returns NULL.
 */
static inline napi_value nwep_napi_throw_msg(napi_env env, const char *msg) {
  napi_throw_error(env, NULL, msg);
  return NULL;
}

/*
 * nwep_napi_throw_type throws a JS TypeError with a message.
 * Returns NULL.
 */
static inline napi_value nwep_napi_throw_type(napi_env env, const char *msg) {
  napi_throw_type_error(env, NULL, msg);
  return NULL;
}

/*
 * NWEP_NAPI_CALL wraps a napi_* call and returns NULL on failure.
 */
#define NWEP_NAPI_CALL(env, call)                                             \
  do {                                                                         \
    napi_status _s = (call);                                                   \
    if (_s != napi_ok) {                                                       \
      const napi_extended_error_info *_err;                                     \
      napi_get_last_error_info((env), &_err);                                  \
      napi_throw_error((env), NULL,                                            \
                       _err->error_message ? _err->error_message               \
                                           : "N-API call failed");             \
      return NULL;                                                             \
    }                                                                          \
  } while (0)

/*
 * NWEP_NAPI_CALL_VOID is like NWEP_NAPI_CALL but for void functions.
 */
#define NWEP_NAPI_CALL_VOID(env, call)                                        \
  do {                                                                         \
    napi_status _s = (call);                                                   \
    if (_s != napi_ok) {                                                       \
      const napi_extended_error_info *_err;                                     \
      napi_get_last_error_info((env), &_err);                                  \
      napi_throw_error((env), NULL,                                            \
                       _err->error_message ? _err->error_message               \
                                           : "N-API call failed");             \
      return;                                                                  \
    }                                                                          \
  } while (0)

/*
 * nwep_napi_get_args extracts up to max_argc arguments from callback_info.
 * Returns 0 on success, -1 on failure (exception already thrown).
 */
static inline int nwep_napi_get_args(napi_env env, napi_callback_info info,
                                      size_t min_argc, size_t max_argc,
                                      napi_value *argv, size_t *actual) {
  size_t argc = max_argc;
  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok) {
    napi_throw_error(env, NULL, "Failed to get callback arguments");
    return -1;
  }
  if (argc < min_argc) {
    napi_throw_type_error(env, NULL, "Not enough arguments");
    return -1;
  }
  if (actual) *actual = argc;
  return 0;
}

/*
 * nwep_napi_get_buffer extracts a Buffer's data pointer and length.
 * Returns 0 on success, -1 on failure.
 */
static inline int nwep_napi_get_buffer(napi_env env, napi_value val,
                                        uint8_t **data, size_t *len) {
  bool is_buf;
  if (napi_is_buffer(env, val, &is_buf) != napi_ok || !is_buf) {
    napi_throw_type_error(env, NULL, "Expected Buffer");
    return -1;
  }
  void *p;
  if (napi_get_buffer_info(env, val, &p, len) != napi_ok) {
    napi_throw_error(env, NULL, "Failed to get buffer info");
    return -1;
  }
  *data = (uint8_t *)p;
  return 0;
}

/*
 * nwep_napi_create_buffer creates a Buffer from raw data.
 */
static inline napi_value nwep_napi_create_buffer(napi_env env,
                                                   const uint8_t *data,
                                                   size_t len) {
  napi_value buf;
  void *p;
  if (napi_create_buffer_copy(env, len, data, &p, &buf) != napi_ok) {
    napi_throw_error(env, NULL, "Failed to create buffer");
    return NULL;
  }
  return buf;
}

/*
 * nwep_napi_get_string extracts a UTF-8 string into a caller-provided buffer.
 * Returns 0 on success, -1 on failure.
 */
static inline int nwep_napi_get_string(napi_env env, napi_value val, char *buf,
                                        size_t buflen, size_t *result_len) {
  napi_valuetype type;
  if (napi_typeof(env, val, &type) != napi_ok || type != napi_string) {
    napi_throw_type_error(env, NULL, "Expected string");
    return -1;
  }
  if (napi_get_value_string_utf8(env, val, buf, buflen, result_len) !=
      napi_ok) {
    napi_throw_error(env, NULL, "Failed to get string");
    return -1;
  }
  return 0;
}

/*
 * nwep_napi_get_uint32 extracts a uint32_t from a JS value.
 */
static inline int nwep_napi_get_uint32(napi_env env, napi_value val,
                                        uint32_t *out) {
  if (napi_get_value_uint32(env, val, out) != napi_ok) {
    napi_throw_type_error(env, NULL, "Expected unsigned integer");
    return -1;
  }
  return 0;
}

/*
 * nwep_napi_get_int64 extracts an int64_t from a BigInt JS value.
 */
static inline int nwep_napi_get_bigint_uint64(napi_env env, napi_value val,
                                               uint64_t *out) {
  bool lossless;
  if (napi_get_value_bigint_uint64(env, val, out, &lossless) != napi_ok) {
    napi_throw_type_error(env, NULL, "Expected BigInt");
    return -1;
  }
  return 0;
}

/*
 * nwep_napi_create_bigint_uint64 creates a BigInt from uint64_t.
 */
static inline napi_value nwep_napi_create_bigint(napi_env env, uint64_t val) {
  napi_value result;
  if (napi_create_bigint_uint64(env, val, &result) != napi_ok) {
    napi_throw_error(env, NULL, "Failed to create BigInt");
    return NULL;
  }
  return result;
}

/*
 * nwep_napi_get_external extracts the void* from an External value.
 */
static inline void *nwep_napi_get_external(napi_env env, napi_value val) {
  void *data;
  if (napi_get_value_external(env, val, &data) != napi_ok) {
    napi_throw_type_error(env, NULL, "Expected external value");
    return NULL;
  }
  return data;
}

/*
 * nwep_napi_set_named_property is a convenience for setting properties.
 */
static inline void nwep_napi_set_prop(napi_env env, napi_value obj,
                                       const char *name, napi_value val) {
  napi_set_named_property(env, obj, name, val);
}

/*
 * nwep_napi_keypair_to_js converts a nwep_keypair to a JS object.
 */
static inline napi_value nwep_napi_keypair_to_js(napi_env env,
                                                   const nwep_keypair *kp) {
  napi_value obj, pubkey, privkey;
  napi_create_object(env, &obj);
  pubkey = nwep_napi_create_buffer(env, kp->pubkey, NWEP_ED25519_PUBKEY_LEN);
  privkey = nwep_napi_create_buffer(env, kp->privkey, 64);
  if (!pubkey || !privkey) return NULL;
  nwep_napi_set_prop(env, obj, "pubkey", pubkey);
  nwep_napi_set_prop(env, obj, "privkey", privkey);
  return obj;
}

/*
 * nwep_napi_js_to_keypair extracts a nwep_keypair from a JS object.
 */
static inline int nwep_napi_js_to_keypair(napi_env env, napi_value obj,
                                            nwep_keypair *kp) {
  napi_value pubkey_val, privkey_val;
  uint8_t *pubdata, *privdata;
  size_t publen, privlen;

  if (napi_get_named_property(env, obj, "pubkey", &pubkey_val) != napi_ok ||
      napi_get_named_property(env, obj, "privkey", &privkey_val) != napi_ok) {
    napi_throw_type_error(env, NULL, "Keypair must have pubkey and privkey");
    return -1;
  }
  if (nwep_napi_get_buffer(env, pubkey_val, &pubdata, &publen) != 0 ||
      nwep_napi_get_buffer(env, privkey_val, &privdata, &privlen) != 0) {
    return -1;
  }
  if (publen != NWEP_ED25519_PUBKEY_LEN) {
    napi_throw_type_error(env, NULL, "pubkey must be 32 bytes");
    return -1;
  }
  if (privlen != 64) {
    napi_throw_type_error(env, NULL, "privkey must be 64 bytes");
    return -1;
  }
  memcpy(kp->pubkey, pubdata, NWEP_ED25519_PUBKEY_LEN);
  memcpy(kp->privkey, privdata, 64);
  return 0;
}

/*
 * nwep_napi_nodeid_to_js converts a nwep_nodeid to a JS Buffer.
 */
static inline napi_value nwep_napi_nodeid_to_js(napi_env env,
                                                  const nwep_nodeid *nid) {
  return nwep_napi_create_buffer(env, nid->data, NWEP_NODEID_LEN);
}

/*
 * nwep_napi_js_to_nodeid extracts a nwep_nodeid from a JS Buffer.
 */
static inline int nwep_napi_js_to_nodeid(napi_env env, napi_value val,
                                           nwep_nodeid *nid) {
  uint8_t *data;
  size_t len;
  if (nwep_napi_get_buffer(env, val, &data, &len) != 0) return -1;
  if (len != NWEP_NODEID_LEN) {
    napi_throw_type_error(env, NULL, "NodeID must be 32 bytes");
    return -1;
  }
  memcpy(nid->data, data, NWEP_NODEID_LEN);
  return 0;
}

/* Module registration declarations for each sub-module */
napi_value nwep_napi_init_constants(napi_env env, napi_value exports);
napi_value nwep_napi_init_error(napi_env env, napi_value exports);
napi_value nwep_napi_init_crypto(napi_env env, napi_value exports);
napi_value nwep_napi_init_encoding(napi_env env, napi_value exports);
napi_value nwep_napi_init_addr(napi_env env, napi_value exports);
napi_value nwep_napi_init_msg(napi_env env, napi_value exports);
napi_value nwep_napi_init_handshake(napi_env env, napi_value exports);
napi_value nwep_napi_init_log(napi_env env, napi_value exports);
napi_value nwep_napi_init_identity(napi_env env, napi_value exports);
napi_value nwep_napi_init_server(napi_env env, napi_value exports);
napi_value nwep_napi_init_client(napi_env env, napi_value exports);
napi_value nwep_napi_init_conn(napi_env env, napi_value exports);
napi_value nwep_napi_init_stream(napi_env env, napi_value exports);
napi_value nwep_napi_init_merkle(napi_env env, napi_value exports);
napi_value nwep_napi_init_anchor(napi_env env, napi_value exports);
napi_value nwep_napi_init_trust(napi_env env, napi_value exports);
napi_value nwep_napi_init_role(napi_env env, napi_value exports);
napi_value nwep_napi_init_cache(napi_env env, napi_value exports);

#endif /* !defined(NWEP_NAPI_H) */
