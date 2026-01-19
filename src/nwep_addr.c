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
#include <stdlib.h>
#include <string.h>

/* Address is Base58(IPv6 || NodeID) = Base58(48 bytes) */
#define NWEP_ADDR_RAW_LEN (16 + NWEP_NODEID_LEN) /* 48 bytes */

void nwep_addr_set_ipv4(nwep_addr *addr, uint32_t ipv4) {
  if (addr == NULL) {
    return;
  }

  /* IPv4-mapped IPv6: ::ffff:x.x.x.x */
  memset(addr->ip, 0, 10);
  addr->ip[10] = 0xff;
  addr->ip[11] = 0xff;
  addr->ip[12] = (ipv4 >> 24) & 0xff;
  addr->ip[13] = (ipv4 >> 16) & 0xff;
  addr->ip[14] = (ipv4 >> 8) & 0xff;
  addr->ip[15] = ipv4 & 0xff;
}

void nwep_addr_set_ipv6(nwep_addr *addr, const uint8_t ipv6[16]) {
  if (addr == NULL || ipv6 == NULL) {
    return;
  }

  memcpy(addr->ip, ipv6, 16);
}

size_t nwep_addr_encode(char *dest, size_t destlen, const nwep_addr *addr) {
  uint8_t raw[NWEP_ADDR_RAW_LEN];

  if (dest == NULL || addr == NULL || destlen == 0) {
    return 0;
  }

  /* Concatenate IPv6 and NodeID */
  memcpy(raw, addr->ip, 16);
  memcpy(raw + 16, addr->nodeid.data, NWEP_NODEID_LEN);

  return nwep_base58_encode(dest, destlen, raw, NWEP_ADDR_RAW_LEN);
}

int nwep_addr_decode(nwep_addr *addr, const char *encoded) {
  uint8_t raw[NWEP_ADDR_RAW_LEN];
  size_t decoded_len;

  if (addr == NULL || encoded == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(addr, 0, sizeof(*addr));

  decoded_len = nwep_base58_decode(raw, NWEP_ADDR_RAW_LEN, encoded);
  if (decoded_len != NWEP_ADDR_RAW_LEN) {
    return NWEP_ERR_IDENTITY_INVALID_ADDR;
  }

  /* Split into IPv6 and NodeID */
  memcpy(addr->ip, raw, 16);
  memcpy(addr->nodeid.data, raw + 16, NWEP_NODEID_LEN);
  addr->port = NWEP_DEFAULT_PORT;

  return 0;
}

int nwep_url_parse(nwep_url *url, const char *str) {
  const char *scheme_end;
  const char *addr_start;
  const char *addr_end;
  const char *port_start = NULL;
  const char *path_start = NULL;
  char addr_buf[128];
  size_t addr_len;
  int rv;

  if (url == NULL || str == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(url, 0, sizeof(*url));
  url->addr.port = NWEP_DEFAULT_PORT;
  url->path[0] = '/';

  /* Check for "web://" scheme */
  scheme_end = strstr(str, "://");
  if (scheme_end == NULL) {
    return NWEP_ERR_IDENTITY_INVALID_ADDR;
  }

  if (scheme_end - str != 3 || strncmp(str, "web", 3) != 0) {
    return NWEP_ERR_IDENTITY_INVALID_ADDR;
  }

  addr_start = scheme_end + 3;

  /* Check for bracketed address [address] */
  if (*addr_start == '[') {
    addr_start++;
    addr_end = strchr(addr_start, ']');
    if (addr_end == NULL) {
      return NWEP_ERR_IDENTITY_INVALID_ADDR;
    }

    /* Check for port after bracket */
    if (*(addr_end + 1) == ':') {
      port_start = addr_end + 2;
    } else if (*(addr_end + 1) == '/') {
      path_start = addr_end + 1;
    } else if (*(addr_end + 1) != '\0') {
      return NWEP_ERR_IDENTITY_INVALID_ADDR;
    }
  } else {
    /* No brackets - find end of address */
    addr_end = strpbrk(addr_start, ":/");
    if (addr_end == NULL) {
      addr_end = addr_start + strlen(addr_start);
    } else if (*addr_end == ':') {
      port_start = addr_end + 1;
    } else if (*addr_end == '/') {
      path_start = addr_end;
    }
  }

  /* Extract address portion */
  addr_len = (size_t)(addr_end - addr_start);
  if (addr_len == 0 || addr_len >= sizeof(addr_buf)) {
    return NWEP_ERR_IDENTITY_INVALID_ADDR;
  }

  memcpy(addr_buf, addr_start, addr_len);
  addr_buf[addr_len] = '\0';

  /* Decode Base58 address */
  rv = nwep_addr_decode(&url->addr, addr_buf);
  if (rv != 0) {
    return rv;
  }

  /* Parse port if present */
  if (port_start != NULL) {
    char *endptr;
    long port;
    const char *port_end;

    port_end = strchr(port_start, '/');
    if (port_end == NULL) {
      port_end = port_start + strlen(port_start);
    } else {
      path_start = port_end;
    }

    port = strtol(port_start, &endptr, 10);
    if (endptr != port_end || port < 1 || port > 65535) {
      return NWEP_ERR_IDENTITY_INVALID_ADDR;
    }

    url->addr.port = (uint16_t)port;
  }

  /* Copy path if present */
  if (path_start != NULL && *path_start != '\0') {
    size_t path_len = strlen(path_start);
    if (path_len >= sizeof(url->path)) {
      return NWEP_ERR_IDENTITY_INVALID_ADDR;
    }
    memcpy(url->path, path_start, path_len + 1);
  }

  return 0;
}

size_t nwep_url_format(char *dest, size_t destlen, const nwep_url *url) {
  char addr_buf[NWEP_BASE58_ADDR_LEN + 1];
  size_t addr_len;
  int rv;

  if (dest == NULL || url == NULL || destlen == 0) {
    return 0;
  }

  /* Encode address */
  addr_len = nwep_addr_encode(addr_buf, sizeof(addr_buf), &url->addr);
  if (addr_len == 0) {
    return 0;
  }

  /* Format URL */
  if (url->addr.port == NWEP_DEFAULT_PORT) {
    rv = snprintf(dest, destlen, "web://[%s]%s", addr_buf, url->path);
  } else {
    rv = snprintf(dest, destlen, "web://[%s]:%u%s", addr_buf, url->addr.port,
                  url->path);
  }

  if (rv < 0 || (size_t)rv >= destlen) {
    return 0;
  }

  return (size_t)rv;
}
