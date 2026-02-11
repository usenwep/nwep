#include "nwep_napi.h"

static napi_value napi_base58_encode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint8_t *src;
  size_t srclen;
  if (nwep_napi_get_buffer(env, argv[0], &src, &srclen) != 0) return NULL;
  size_t destlen = nwep_base58_encode_len(srclen);
  char *dest = (char *)malloc(destlen);
  if (!dest) return nwep_napi_throw_msg(env, "Out of memory");
  size_t written = nwep_base58_encode(dest, destlen, src, srclen);
  napi_value result;
  if (written == 0) {
    free(dest);
    return nwep_napi_throw_msg(env, "Base58 encode failed");
  }
  napi_create_string_utf8(env, dest, written, &result);
  free(dest);
  return result;
}

static napi_value napi_base58_decode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  char src[256];
  size_t srclen;
  if (nwep_napi_get_string(env, argv[0], src, sizeof(src), &srclen) != 0)
    return NULL;
  size_t destlen = nwep_base58_decode_len(srclen);
  uint8_t *dest = (uint8_t *)malloc(destlen);
  if (!dest) return nwep_napi_throw_msg(env, "Out of memory");
  size_t written = nwep_base58_decode(dest, destlen, src);
  if (written == 0) {
    free(dest);
    return nwep_napi_throw_msg(env, "Base58 decode failed");
  }
  napi_value result = nwep_napi_create_buffer(env, dest, written);
  free(dest);
  return result;
}

static napi_value napi_base64_encode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint8_t *src;
  size_t srclen;
  if (nwep_napi_get_buffer(env, argv[0], &src, &srclen) != 0) return NULL;
  size_t destlen = nwep_base64_encode_len(srclen);
  char *dest = (char *)malloc(destlen);
  if (!dest) return nwep_napi_throw_msg(env, "Out of memory");
  size_t written = nwep_base64_encode(dest, destlen, src, srclen);
  napi_value result;
  if (written == 0) {
    free(dest);
    return nwep_napi_throw_msg(env, "Base64 encode failed");
  }
  napi_create_string_utf8(env, dest, written, &result);
  free(dest);
  return result;
}

static napi_value napi_base64_decode(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  char src[8192];
  size_t srclen;
  if (nwep_napi_get_string(env, argv[0], src, sizeof(src), &srclen) != 0)
    return NULL;
  size_t destlen = nwep_base64_decode_len(srclen);
  uint8_t *dest = (uint8_t *)malloc(destlen);
  if (!dest) return nwep_napi_throw_msg(env, "Out of memory");
  size_t written = nwep_base64_decode(dest, destlen, src);
  if (written == 0) {
    free(dest);
    return nwep_napi_throw_msg(env, "Base64 decode failed");
  }
  napi_value result = nwep_napi_create_buffer(env, dest, written);
  free(dest);
  return result;
}

static napi_value napi_put_uint32be(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint32_t val;
  if (nwep_napi_get_uint32(env, argv[0], &val) != 0) return NULL;
  uint8_t buf[4];
  nwep_put_uint32be(buf, val);
  return nwep_napi_create_buffer(env, buf, 4);
}

static napi_value napi_get_uint32be(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint8_t *data;
  size_t len;
  if (nwep_napi_get_buffer(env, argv[0], &data, &len) != 0) return NULL;
  if (len < 4)
    return nwep_napi_throw_type(env, "Buffer must be at least 4 bytes");
  uint32_t val;
  nwep_get_uint32be(&val, data);
  napi_value result;
  napi_create_uint32(env, val, &result);
  return result;
}

static napi_value napi_put_uint16be(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint32_t val;
  if (nwep_napi_get_uint32(env, argv[0], &val) != 0) return NULL;
  uint8_t buf[2];
  nwep_put_uint16be(buf, (uint16_t)val);
  return nwep_napi_create_buffer(env, buf, 2);
}

static napi_value napi_get_uint16be(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  if (nwep_napi_get_args(env, info, 1, 1, argv, NULL) != 0) return NULL;
  uint8_t *data;
  size_t len;
  if (nwep_napi_get_buffer(env, argv[0], &data, &len) != 0) return NULL;
  if (len < 2)
    return nwep_napi_throw_type(env, "Buffer must be at least 2 bytes");
  uint16_t val;
  nwep_get_uint16be(&val, data);
  napi_value result;
  napi_create_uint32(env, val, &result);
  return result;
}

napi_value nwep_napi_init_encoding(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
      {"base58Encode", NULL, napi_base58_encode, NULL, NULL, NULL,
       napi_default, NULL},
      {"base58Decode", NULL, napi_base58_decode, NULL, NULL, NULL,
       napi_default, NULL},
      {"base64Encode", NULL, napi_base64_encode, NULL, NULL, NULL,
       napi_default, NULL},
      {"base64Decode", NULL, napi_base64_decode, NULL, NULL, NULL,
       napi_default, NULL},
      {"putUint32be", NULL, napi_put_uint32be, NULL, NULL, NULL, napi_default,
       NULL},
      {"getUint32be", NULL, napi_get_uint32be, NULL, NULL, NULL, napi_default,
       NULL},
      {"putUint16be", NULL, napi_put_uint16be, NULL, NULL, NULL, napi_default,
       NULL},
      {"getUint16be", NULL, napi_get_uint16be, NULL, NULL, NULL, napi_default,
       NULL},
  };
  napi_define_properties(env, exports,
                         sizeof(props) / sizeof(props[0]), props);
  return exports;
}
