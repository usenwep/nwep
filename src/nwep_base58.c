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

/* Bitcoin-style Base58 alphabet */
static const char base58_alphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* Reverse lookup table: ASCII char -> Base58 value (255 = invalid) */
static const uint8_t base58_map[256] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 0,   1,   2,   3,   4,   5,   6,   7,   8,   255, 255,
    255, 255, 255, 255, 255, 9,   10,  11,  12,  13,  14,  15,  16,  255, 17,
    18,  19,  20,  21,  255, 22,  23,  24,  25,  26,  27,  28,  29,  30,  31,
    32,  255, 255, 255, 255, 255, 255, 33,  34,  35,  36,  37,  38,  39,  40,
    41,  42,  43,  255, 44,  45,  46,  47,  48,  49,  50,  51,  52,  53,  54,
    55,  56,  57,  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255};

size_t nwep_base58_encode_len(size_t srclen) {
  /* Base58 encoding expands by approximately log(256)/log(58) ≈ 1.37 */
  /* Use ceiling of srclen * 138 / 100 + 1 for null terminator */
  return (srclen * 138 / 100) + 2;
}

size_t nwep_base58_decode_len(size_t srclen) {
  /* Base58 decoding contracts by approximately log(58)/log(256) ≈ 0.73 */
  return (srclen * 733 / 1000) + 1;
}

size_t nwep_base58_encode(char *dest, size_t destlen, const uint8_t *src,
                          size_t srclen) {
  size_t zeros = 0;
  size_t i, j, carry;
  size_t size;
  uint8_t *buf;
  size_t buf_size;
  size_t high;
  size_t written;

  if (dest == NULL || src == NULL || destlen == 0) {
    return 0;
  }

  /* Count leading zeros */
  while (zeros < srclen && src[zeros] == 0) {
    zeros++;
  }

  /* Allocate buffer for intermediate result */
  buf_size = (srclen - zeros) * 138 / 100 + 1;
  buf = (uint8_t *)calloc(buf_size, 1);
  if (buf == NULL) {
    return 0;
  }

  size = buf_size;
  high = size - 1;

  /* Convert to base58 */
  for (i = zeros; i < srclen; i++) {
    carry = src[i];
    j = size - 1;

    while (j > high || carry != 0) {
      carry += 256 * buf[j];
      buf[j] = carry % 58;
      carry /= 58;
      if (j == 0) {
        break;
      }
      j--;
    }
    high = j;
  }

  /* Skip leading zeros in buf */
  j = 0;
  while (j < size && buf[j] == 0) {
    j++;
  }

  /* Check if we have enough space */
  written = zeros + (size - j);
  if (written >= destlen) {
    free(buf);
    return 0;
  }

  /* Write leading '1's for each leading zero byte */
  for (i = 0; i < zeros; i++) {
    dest[i] = '1';
  }

  /* Write the encoded result */
  for (; j < size; i++, j++) {
    dest[i] = base58_alphabet[buf[j]];
  }

  dest[i] = '\0';
  free(buf);

  return i;
}

size_t nwep_base58_decode(uint8_t *dest, size_t destlen, const char *src) {
  size_t srclen;
  size_t zeros = 0;
  size_t i, j;
  uint32_t carry;
  size_t size;
  uint8_t *buf;
  size_t buf_size;
  size_t high;
  size_t written;
  uint8_t c;

  if (dest == NULL || src == NULL || destlen == 0) {
    return 0;
  }

  srclen = strlen(src);
  if (srclen == 0) {
    return 0;
  }

  /* Count leading '1's (representing leading zero bytes) */
  while (zeros < srclen && src[zeros] == '1') {
    zeros++;
  }

  /* Allocate buffer for intermediate result */
  buf_size = (srclen - zeros) * 733 / 1000 + 1;
  buf = (uint8_t *)calloc(buf_size, 1);
  if (buf == NULL) {
    return 0;
  }

  size = buf_size;
  high = size - 1;

  /* Convert from base58 */
  for (i = zeros; i < srclen; i++) {
    c = (uint8_t)src[i];
    carry = base58_map[c];

    if (carry == 255) {
      /* Invalid character */
      free(buf);
      return 0;
    }

    j = size - 1;
    while (j > high || carry != 0) {
      carry += 58 * buf[j];
      buf[j] = carry & 0xff;
      carry >>= 8;
      if (j == 0) {
        break;
      }
      j--;
    }
    high = j;
  }

  /* Skip leading zeros in buf */
  j = 0;
  while (j < size && buf[j] == 0) {
    j++;
  }

  /* Check if we have enough space */
  written = zeros + (size - j);
  if (written > destlen) {
    free(buf);
    return 0;
  }

  /* Write leading zeros */
  for (i = 0; i < zeros; i++) {
    dest[i] = 0;
  }

  /* Write decoded bytes */
  for (; j < size; i++, j++) {
    dest[i] = buf[j];
  }

  free(buf);
  return i;
}
