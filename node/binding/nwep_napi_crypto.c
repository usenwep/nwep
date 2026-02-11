#include "nwep_napi.h"

static napi_value napi_keypair_generate(napi_env env,
                                         napi_callback_info info) {
  nwep_keypair kp;
  int rv = nwep_keypair_generate(&kp);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_keypair_to_js(env, &kp);
}

static napi_value napi_keypair_from_seed(napi_env env,
                                          napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint8_t *data;
  size_t len;
  if (nwep_napi_get_buffer(env, argv[0], &data, &len) != 0) return NULL;
  if (len != 32) return nwep_napi_throw_type(env, "Seed must be 32 bytes");
  nwep_keypair kp;
  int rv = nwep_keypair_from_seed(&kp, data);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_keypair_to_js(env, &kp);
}

static napi_value napi_keypair_from_privkey(napi_env env,
                                             napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint8_t *data;
  size_t len;
  if (nwep_napi_get_buffer(env, argv[0], &data, &len) != 0) return NULL;
  if (len != 64)
    return nwep_napi_throw_type(env, "Private key must be 64 bytes");
  nwep_keypair kp;
  int rv = nwep_keypair_from_privkey(&kp, data);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_keypair_to_js(env, &kp);
}

static napi_value napi_nodeid_from_pubkey(napi_env env,
                                           napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint8_t *data;
  size_t len;
  if (nwep_napi_get_buffer(env, argv[0], &data, &len) != 0) return NULL;
  if (len != 32)
    return nwep_napi_throw_type(env, "Public key must be 32 bytes");
  nwep_nodeid nid;
  int rv = nwep_nodeid_from_pubkey(&nid, data);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_nodeid_to_js(env, &nid);
}

static napi_value napi_nodeid_from_keypair(napi_env env,
                                            napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_keypair kp;
  if (nwep_napi_js_to_keypair(env, argv[0], &kp) != 0) return NULL;
  nwep_nodeid nid;
  int rv = nwep_nodeid_from_keypair(&nid, &kp);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_nodeid_to_js(env, &nid);
}

static napi_value napi_nodeid_eq(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_nodeid a, b;
  if (nwep_napi_js_to_nodeid(env, argv[0], &a) != 0) return NULL;
  if (nwep_napi_js_to_nodeid(env, argv[1], &b) != 0) return NULL;
  napi_value result;
  napi_get_boolean(env, nwep_nodeid_eq(&a, &b), &result);
  return result;
}

static napi_value napi_nodeid_is_zero(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_nodeid nid;
  if (nwep_napi_js_to_nodeid(env, argv[0], &nid) != 0) return NULL;
  napi_value result;
  napi_get_boolean(env, nwep_nodeid_is_zero(&nid), &result);
  return result;
}

static napi_value napi_sign(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  uint8_t *msg;
  size_t msglen;
  if (nwep_napi_get_buffer(env, argv[0], &msg, &msglen) != 0) return NULL;
  nwep_keypair kp;
  if (nwep_napi_js_to_keypair(env, argv[1], &kp) != 0) return NULL;
  uint8_t sig[64];
  int rv = nwep_sign(sig, msg, msglen, &kp);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_create_buffer(env, sig, 64);
}

static napi_value napi_verify(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (nwep_napi_get_args(env, info, 3, 3, argv, NULL) != 0) return NULL;
  uint8_t *sig, *msg, *pubkey;
  size_t siglen, msglen, pklen;
  if (nwep_napi_get_buffer(env, argv[0], &sig, &siglen) != 0) return NULL;
  if (nwep_napi_get_buffer(env, argv[1], &msg, &msglen) != 0) return NULL;
  if (nwep_napi_get_buffer(env, argv[2], &pubkey, &pklen) != 0) return NULL;
  if (siglen != 64)
    return nwep_napi_throw_type(env, "Signature must be 64 bytes");
  if (pklen != 32)
    return nwep_napi_throw_type(env, "Public key must be 32 bytes");
  int rv = nwep_verify(sig, msg, msglen, pubkey);
  napi_value result;
  napi_get_boolean(env, rv == 0, &result);
  return result;
}

static napi_value napi_challenge_generate(napi_env env,
                                           napi_callback_info info) {
  uint8_t challenge[32];
  int rv = nwep_challenge_generate(challenge);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_create_buffer(env, challenge, 32);
}

static napi_value napi_challenge_sign(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  uint8_t *challenge;
  size_t clen;
  if (nwep_napi_get_buffer(env, argv[0], &challenge, &clen) != 0) return NULL;
  if (clen != 32)
    return nwep_napi_throw_type(env, "Challenge must be 32 bytes");
  nwep_keypair kp;
  if (nwep_napi_js_to_keypair(env, argv[1], &kp) != 0) return NULL;
  uint8_t response[64];
  int rv = nwep_challenge_sign(response, challenge, &kp);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_create_buffer(env, response, 64);
}

static napi_value napi_challenge_verify(napi_env env,
                                         napi_callback_info info) {
  napi_value argv[3];
  if (nwep_napi_get_args(env, info, 3, 3, argv, NULL) != 0) return NULL;
  uint8_t *response, *challenge, *pubkey;
  size_t rlen, clen, pklen;
  if (nwep_napi_get_buffer(env, argv[0], &response, &rlen) != 0) return NULL;
  if (nwep_napi_get_buffer(env, argv[1], &challenge, &clen) != 0) return NULL;
  if (nwep_napi_get_buffer(env, argv[2], &pubkey, &pklen) != 0) return NULL;
  if (rlen != 64)
    return nwep_napi_throw_type(env, "Response must be 64 bytes");
  if (clen != 32)
    return nwep_napi_throw_type(env, "Challenge must be 32 bytes");
  if (pklen != 32)
    return nwep_napi_throw_type(env, "Public key must be 32 bytes");
  int rv = nwep_challenge_verify(response, challenge, pubkey);
  napi_value result;
  napi_get_boolean(env, rv == 0, &result);
  return result;
}

static napi_value napi_random_bytes(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint32_t len;
  if (nwep_napi_get_uint32(env, argv[0], &len) != 0) return NULL;
  napi_value buf;
  void *data;
  NWEP_NAPI_CALL(env, napi_create_buffer(env, len, &data, &buf));
  int rv = nwep_random_bytes((uint8_t *)data, len);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return buf;
}

static napi_value napi_shamir_split(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  if (nwep_napi_get_args(env, info, 3, 3, argv, NULL) != 0) return NULL;
  uint8_t *secret;
  size_t slen;
  if (nwep_napi_get_buffer(env, argv[0], &secret, &slen) != 0) return NULL;
  if (slen != 32)
    return nwep_napi_throw_type(env, "Secret must be 32 bytes");
  uint32_t n, t;
  if (nwep_napi_get_uint32(env, argv[1], &n) != 0) return NULL;
  if (nwep_napi_get_uint32(env, argv[2], &t) != 0) return NULL;

  nwep_shamir_share *shares =
      (nwep_shamir_share *)malloc(n * sizeof(nwep_shamir_share));
  if (!shares) return nwep_napi_throw_msg(env, "Out of memory");

  int rv = nwep_shamir_split(secret, shares, n, t);
  if (rv != 0) {
    free(shares);
    return nwep_napi_throw(env, rv);
  }

  napi_value arr;
  napi_create_array_with_length(env, n, &arr);
  for (uint32_t i = 0; i < n; i++) {
    napi_value obj, idx_val, data_val;
    napi_create_object(env, &obj);
    napi_create_uint32(env, shares[i].index, &idx_val);
    data_val = nwep_napi_create_buffer(env, shares[i].data, 32);
    napi_set_named_property(env, obj, "index", idx_val);
    napi_set_named_property(env, obj, "data", data_val);
    napi_set_element(env, arr, i, obj);
  }
  free(shares);
  return arr;
}

static napi_value napi_shamir_combine(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  uint32_t num_shares;
  NWEP_NAPI_CALL(env, napi_get_array_length(env, argv[0], &num_shares));

  nwep_shamir_share *shares =
      (nwep_shamir_share *)malloc(num_shares * sizeof(nwep_shamir_share));
  if (!shares) return nwep_napi_throw_msg(env, "Out of memory");

  for (uint32_t i = 0; i < num_shares; i++) {
    napi_value elem, idx_val, data_val;
    napi_get_element(env, argv[0], i, &elem);
    napi_get_named_property(env, elem, "index", &idx_val);
    napi_get_named_property(env, elem, "data", &data_val);

    uint32_t idx;
    napi_get_value_uint32(env, idx_val, &idx);
    shares[i].index = (uint8_t)idx;

    uint8_t *data;
    size_t len;
    if (nwep_napi_get_buffer(env, data_val, &data, &len) != 0) {
      free(shares);
      return NULL;
    }
    memcpy(shares[i].data, data, 32);
  }

  uint8_t secret[32];
  int rv = nwep_shamir_combine(secret, shares, num_shares);
  free(shares);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_create_buffer(env, secret, 32);
}

static napi_value napi_trace_id_generate(napi_env env,
                                          napi_callback_info info) {
  uint8_t id[16];
  int rv = nwep_trace_id_generate(id);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_create_buffer(env, id, 16);
}

static napi_value napi_request_id_generate(napi_env env,
                                            napi_callback_info info) {
  uint8_t id[16];
  int rv = nwep_request_id_generate(id);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_create_buffer(env, id, 16);
}

napi_value nwep_napi_init_crypto(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"keypairGenerate", NULL, napi_keypair_generate, NULL, NULL, NULL,
       napi_default, NULL},
      {"keypairFromSeed", NULL, napi_keypair_from_seed, NULL, NULL, NULL,
       napi_default, NULL},
      {"keypairFromPrivkey", NULL, napi_keypair_from_privkey, NULL, NULL, NULL,
       napi_default, NULL},
      {"nodeidFromPubkey", NULL, napi_nodeid_from_pubkey, NULL, NULL, NULL,
       napi_default, NULL},
      {"nodeidFromKeypair", NULL, napi_nodeid_from_keypair, NULL, NULL, NULL,
       napi_default, NULL},
      {"nodeidEq", NULL, napi_nodeid_eq, NULL, NULL, NULL, napi_default, NULL},
      {"nodeidIsZero", NULL, napi_nodeid_is_zero, NULL, NULL, NULL,
       napi_default, NULL},
      {"sign", NULL, napi_sign, NULL, NULL, NULL, napi_default, NULL},
      {"verify", NULL, napi_verify, NULL, NULL, NULL, napi_default, NULL},
      {"challengeGenerate", NULL, napi_challenge_generate, NULL, NULL, NULL,
       napi_default, NULL},
      {"challengeSign", NULL, napi_challenge_sign, NULL, NULL, NULL,
       napi_default, NULL},
      {"challengeVerify", NULL, napi_challenge_verify, NULL, NULL, NULL,
       napi_default, NULL},
      {"randomBytes", NULL, napi_random_bytes, NULL, NULL, NULL, napi_default,
       NULL},
      {"shamirSplit", NULL, napi_shamir_split, NULL, NULL, NULL, napi_default,
       NULL},
      {"shamirCombine", NULL, napi_shamir_combine, NULL, NULL, NULL,
       napi_default, NULL},
      {"traceIdGenerate", NULL, napi_trace_id_generate, NULL, NULL, NULL,
       napi_default, NULL},
      {"requestIdGenerate", NULL, napi_request_id_generate, NULL, NULL, NULL,
       napi_default, NULL},
  };
  napi_define_properties(env, exports,
                         sizeof(props) / sizeof(props[0]), props);
  return exports;
}
