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

#include <string.h>

/* Standard Base64 alphabet */
static const char base64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Reverse lookup table: ASCII char -> Base64 value (255 = invalid) */
static const uint8_t base64_map[256] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62,  255,
    255, 255, 63,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  255, 255,
    255, 0,   255, 255, 255, 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
    10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,
    25,  255, 255, 255, 255, 255, 255, 26,  27,  28,  29,  30,  31,  32,  33,
    34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
    49,  50,  51,  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255};

size_t nwep_base64_encode_len(size_t srclen) {
  /* Base64 produces 4 chars for every 3 bytes, plus padding */
  return ((srclen + 2) / 3) * 4 + 1;
}

size_t nwep_base64_decode_len(size_t srclen) {
  /* Base64 decodes 3 bytes from every 4 chars */
  return (srclen / 4) * 3 + 3;
}

size_t nwep_base64_encode(char *dest, size_t destlen, const uint8_t *src,
                          size_t srclen) {
  size_t i, j;
  uint32_t n;
  size_t full_groups;
  size_t remaining;
  size_t needed;

  if (dest == NULL || src == NULL) {
    return 0;
  }

  needed = nwep_base64_encode_len(srclen);
  if (destlen < needed) {
    return 0;
  }

  j = 0;
  full_groups = srclen / 3;
  remaining = srclen % 3;

  /* Encode full 3-byte groups */
  for (i = 0; i < full_groups; i++) {
    n = ((uint32_t)src[i * 3] << 16) | ((uint32_t)src[i * 3 + 1] << 8) |
        (uint32_t)src[i * 3 + 2];

    dest[j++] = base64_alphabet[(n >> 18) & 0x3f];
    dest[j++] = base64_alphabet[(n >> 12) & 0x3f];
    dest[j++] = base64_alphabet[(n >> 6) & 0x3f];
    dest[j++] = base64_alphabet[n & 0x3f];
  }

  /* Handle remaining bytes with padding */
  if (remaining == 1) {
    n = (uint32_t)src[full_groups * 3] << 16;
    dest[j++] = base64_alphabet[(n >> 18) & 0x3f];
    dest[j++] = base64_alphabet[(n >> 12) & 0x3f];
    dest[j++] = '=';
    dest[j++] = '=';
  } else if (remaining == 2) {
    n = ((uint32_t)src[full_groups * 3] << 16) |
        ((uint32_t)src[full_groups * 3 + 1] << 8);
    dest[j++] = base64_alphabet[(n >> 18) & 0x3f];
    dest[j++] = base64_alphabet[(n >> 12) & 0x3f];
    dest[j++] = base64_alphabet[(n >> 6) & 0x3f];
    dest[j++] = '=';
  }

  dest[j] = '\0';
  return j;
}

size_t nwep_base64_decode_n(uint8_t *dest, size_t destlen, const char *src,
                            size_t srclen) {
  size_t i, j;
  uint32_t n;
  uint8_t c0, c1, c2, c3;
  size_t padding = 0;
  size_t out_len;

  if (dest == NULL || src == NULL) {
    return 0;
  }

  /* Must be multiple of 4 */
  if (srclen == 0 || (srclen % 4) != 0) {
    return 0;
  }

  /* Count padding */
  if (src[srclen - 1] == '=') {
    padding++;
  }
  if (srclen > 1 && src[srclen - 2] == '=') {
    padding++;
  }

  out_len = (srclen / 4) * 3 - padding;
  if (out_len > destlen) {
    return 0;
  }

  j = 0;
  for (i = 0; i < srclen; i += 4) {
    c0 = base64_map[(uint8_t)src[i]];
    c1 = base64_map[(uint8_t)src[i + 1]];
    c2 = (src[i + 2] == '=') ? 0 : base64_map[(uint8_t)src[i + 2]];
    c3 = (src[i + 3] == '=') ? 0 : base64_map[(uint8_t)src[i + 3]];

    /* Check for invalid characters */
    if (c0 == 255 || c1 == 255) {
      return 0;
    }
    if (src[i + 2] != '=' && c2 == 255) {
      return 0;
    }
    if (src[i + 3] != '=' && c3 == 255) {
      return 0;
    }

    n = ((uint32_t)c0 << 18) | ((uint32_t)c1 << 12) | ((uint32_t)c2 << 6) |
        (uint32_t)c3;

    dest[j++] = (uint8_t)(n >> 16);

    if (src[i + 2] != '=') {
      dest[j++] = (uint8_t)(n >> 8);
    }
    if (src[i + 3] != '=') {
      dest[j++] = (uint8_t)n;
    }
  }

  return j;
}

size_t nwep_base64_decode(uint8_t *dest, size_t destlen, const char *src) {
  if (dest == NULL || src == NULL) {
    return 0;
  }
  return nwep_base64_decode_n(dest, destlen, src, strlen(src));
}
