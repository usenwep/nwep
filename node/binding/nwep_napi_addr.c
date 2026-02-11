#include "nwep_napi.h"

static napi_value nwep_napi_addr_to_js(napi_env env, const nwep_addr *addr) {
  napi_value obj, ip_val, nodeid_val, port_val;
  napi_create_object(env, &obj);
  ip_val = nwep_napi_create_buffer(env, addr->ip, 16);
  nodeid_val = nwep_napi_nodeid_to_js(env, &addr->nodeid);
  napi_create_uint32(env, addr->port, &port_val);
  napi_set_named_property(env, obj, "ip", ip_val);
  napi_set_named_property(env, obj, "nodeid", nodeid_val);
  napi_set_named_property(env, obj, "port", port_val);
  return obj;
}

static int nwep_napi_js_to_addr(napi_env env, napi_value obj,
                                  nwep_addr *addr) {
  napi_value ip_val, nodeid_val, port_val;
  napi_get_named_property(env, obj, "ip", &ip_val);
  napi_get_named_property(env, obj, "nodeid", &nodeid_val);
  napi_get_named_property(env, obj, "port", &port_val);

  uint8_t *ip;
  size_t iplen;
  if (nwep_napi_get_buffer(env, ip_val, &ip, &iplen) != 0) return -1;
  if (iplen != 16) {
    napi_throw_type_error(env, NULL, "IP must be 16 bytes");
    return -1;
  }
  memcpy(addr->ip, ip, 16);
  if (nwep_napi_js_to_nodeid(env, nodeid_val, &addr->nodeid) != 0) return -1;
  uint32_t port;
  if (nwep_napi_get_uint32(env, port_val, &port) != 0) return -1;
  addr->port = (uint16_t)port;
  return 0;
}

static napi_value napi_addr_encode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  nwep_addr addr;
  if (nwep_napi_js_to_addr(env, argv[0], &addr) != 0) return NULL;
  char dest[NWEP_BASE58_ADDR_LEN + 1];
  size_t written = nwep_addr_encode(dest, sizeof(dest), &addr);
  if (written == 0) return nwep_napi_throw_msg(env, "addr_encode failed");
  napi_value result;
  napi_create_string_utf8(env, dest, written, &result);
  return result;
}

static napi_value napi_addr_decode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  char encoded[128];
  size_t len;
  if (nwep_napi_get_string(env, argv[0], encoded, sizeof(encoded), &len) != 0)
    return NULL;
  nwep_addr addr;
  int rv = nwep_addr_decode(&addr, encoded);
  if (rv != 0) return nwep_napi_throw(env, rv);
  return nwep_napi_addr_to_js(env, &addr);
}

static napi_value napi_url_parse(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  char str[NWEP_URL_MAX_LEN + 1];
  size_t len;
  if (nwep_napi_get_string(env, argv[0], str, sizeof(str), &len) != 0)
    return NULL;
  nwep_url url;
  int rv = nwep_url_parse(&url, str);
  if (rv != 0) return nwep_napi_throw(env, rv);

  napi_value obj, addr_val, path_val;
  napi_create_object(env, &obj);
  addr_val = nwep_napi_addr_to_js(env, &url.addr);
  napi_create_string_utf8(env, url.path, strlen(url.path), &path_val);
  napi_set_named_property(env, obj, "addr", addr_val);
  napi_set_named_property(env, obj, "path", path_val);
  return obj;
}

static napi_value napi_url_format(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;

  nwep_url url;
  memset(&url, 0, sizeof(url));

  napi_value addr_val, path_val;
  napi_get_named_property(env, argv[0], "addr", &addr_val);
  napi_get_named_property(env, argv[0], "path", &path_val);

  if (nwep_napi_js_to_addr(env, addr_val, &url.addr) != 0) return NULL;
  size_t path_len;
  if (nwep_napi_get_string(env, path_val, url.path, sizeof(url.path),
                           &path_len) != 0)
    return NULL;

  char dest[NWEP_URL_MAX_LEN + 1];
  size_t written = nwep_url_format(dest, sizeof(dest), &url);
  if (written == 0) return nwep_napi_throw_msg(env, "url_format failed");
  napi_value result;
  napi_create_string_utf8(env, dest, written, &result);
  return result;
}

static napi_value napi_addr_set_ipv4(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_addr addr;
  if (nwep_napi_js_to_addr(env, argv[0], &addr) != 0) return NULL;
  uint32_t ipv4;
  if (nwep_napi_get_uint32(env, argv[1], &ipv4) != 0) return NULL;
  nwep_addr_set_ipv4(&addr, ipv4);
  return nwep_napi_addr_to_js(env, &addr);
}

static napi_value napi_addr_set_ipv6(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  if (nwep_napi_get_args(env, info, 2, 2, argv, NULL) != 0) return NULL;
  nwep_addr addr;
  if (nwep_napi_js_to_addr(env, argv[0], &addr) != 0) return NULL;
  uint8_t *ipv6;
  size_t len;
  if (nwep_napi_get_buffer(env, argv[1], &ipv6, &len) != 0) return NULL;
  if (len != 16)
    return nwep_napi_throw_type(env, "IPv6 address must be 16 bytes");
  nwep_addr_set_ipv6(&addr, ipv6);
  return nwep_napi_addr_to_js(env, &addr);
}

napi_value nwep_napi_init_addr(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"addrEncode", NULL, napi_addr_encode, NULL, NULL, NULL, napi_default,
       NULL},
      {"addrDecode", NULL, napi_addr_decode, NULL, NULL, NULL, napi_default,
       NULL},
      {"urlParse", NULL, napi_url_parse, NULL, NULL, NULL, napi_default, NULL},
      {"urlFormat", NULL, napi_url_format, NULL, NULL, NULL, napi_default,
       NULL},
      {"addrSetIpv4", NULL, napi_addr_set_ipv4, NULL, NULL, NULL, napi_default,
       NULL},
      {"addrSetIpv6", NULL, napi_addr_set_ipv6, NULL, NULL, NULL, napi_default,
       NULL},
  };
  napi_define_properties(env, exports,
                         sizeof(props) / sizeof(props[0]), props);
  return exports;
}
