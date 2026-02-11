#include "nwep_napi.h"

static napi_value napi_conn_get_peer_identity(napi_env env,
                                                napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_conn *conn = (nwep_conn *)nwep_napi_get_external(env, argv[0]);
  if (!conn) return NULL;

  const nwep_identity *peer = nwep_conn_get_peer_identity(conn);
  if (!peer)
    return nwep_napi_throw_msg(env, "No peer identity available");

  napi_value pubkey =
      nwep_napi_create_buffer(env, peer->pubkey, NWEP_ED25519_PUBKEY_LEN);
  if (!pubkey) return NULL;

  napi_value nodeid = nwep_napi_nodeid_to_js(env, &peer->nodeid);
  if (!nodeid) return NULL;

  napi_value result;
  napi_create_object(env, &result);
  nwep_napi_set_prop(env, result, "pubkey", pubkey);
  nwep_napi_set_prop(env, result, "nodeid", nodeid);
  return result;
}

static napi_value napi_conn_get_local_identity(napi_env env,
                                                 napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_conn *conn = (nwep_conn *)nwep_napi_get_external(env, argv[0]);
  if (!conn) return NULL;

  const nwep_identity *local = nwep_conn_get_local_identity(conn);
  if (!local)
    return nwep_napi_throw_msg(env, "No local identity available");

  napi_value pubkey =
      nwep_napi_create_buffer(env, local->pubkey, NWEP_ED25519_PUBKEY_LEN);
  if (!pubkey) return NULL;

  napi_value nodeid = nwep_napi_nodeid_to_js(env, &local->nodeid);
  if (!nodeid) return NULL;

  napi_value result;
  napi_create_object(env, &result);
  nwep_napi_set_prop(env, result, "pubkey", pubkey);
  nwep_napi_set_prop(env, result, "nodeid", nodeid);
  return result;
}

static napi_value napi_conn_get_role(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_conn *conn = (nwep_conn *)nwep_napi_get_external(env, argv[0]);
  if (!conn) return NULL;

  const char *role = nwep_conn_get_role(conn);
  if (!role) {
    napi_value null_val;
    napi_get_null(env, &null_val);
    return null_val;
  }

  napi_value result;
  NWEP_NAPI_CALL(env,
                  napi_create_string_utf8(env, role, strlen(role), &result));
  return result;
}

static napi_value napi_conn_close(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_conn *conn = (nwep_conn *)nwep_napi_get_external(env, argv[0]);
  if (!conn) return NULL;

  int32_t error;
  if (napi_get_value_int32(env, argv[1], &error) != napi_ok)
    return nwep_napi_throw_type(env, "Expected integer error code");

  nwep_conn_close(conn, (int)error);
  return NULL;
}

static napi_value napi_conn_get_peer_role(napi_env env,
                                            napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_conn *conn = (nwep_conn *)nwep_napi_get_external(env, argv[0]);
  if (!conn) return NULL;

  nwep_server_role role = nwep_conn_get_peer_role(conn);

  napi_value result;
  NWEP_NAPI_CALL(env, napi_create_int32(env, (int32_t)role, &result));
  return result;
}

napi_value nwep_napi_init_conn(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"connGetPeerIdentity", NULL, napi_conn_get_peer_identity, NULL, NULL,
       NULL, napi_default, NULL},
      {"connGetLocalIdentity", NULL, napi_conn_get_local_identity, NULL, NULL,
       NULL, napi_default, NULL},
      {"connGetRole", NULL, napi_conn_get_role, NULL, NULL, NULL, napi_default,
       NULL},
      {"connClose", NULL, napi_conn_close, NULL, NULL, NULL, napi_default,
       NULL},
      {"connGetPeerRole", NULL, napi_conn_get_peer_role, NULL, NULL, NULL,
       napi_default, NULL},
  };
  napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]),
                         props);
  return exports;
}
