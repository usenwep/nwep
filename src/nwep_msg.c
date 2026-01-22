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

/*
 * Byte order helpers
 */

uint8_t *nwep_put_uint32be(uint8_t *p, uint32_t n) {
  p[0] = (uint8_t)(n >> 24);
  p[1] = (uint8_t)(n >> 16);
  p[2] = (uint8_t)(n >> 8);
  p[3] = (uint8_t)n;
  return p + 4;
}

const uint8_t *nwep_get_uint32be(uint32_t *dest, const uint8_t *p) {
  *dest = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
          ((uint32_t)p[2] << 8) | (uint32_t)p[3];
  return p + 4;
}

uint8_t *nwep_put_uint16be(uint8_t *p, uint16_t n) {
  p[0] = (uint8_t)(n >> 8);
  p[1] = (uint8_t)n;
  return p + 2;
}

const uint8_t *nwep_get_uint16be(uint16_t *dest, const uint8_t *p) {
  *dest = ((uint16_t)p[0] << 8) | (uint16_t)p[1];
  return p + 2;
}

/*
 * Header helpers
 */

void nwep_header_set(nwep_header *hdr, const char *name, const char *value) {
  if (hdr == NULL) {
    return;
  }
  hdr->name = (const uint8_t *)name;
  hdr->name_len = name ? strlen(name) : 0;
  hdr->value = (const uint8_t *)value;
  hdr->value_len = value ? strlen(value) : 0;
}

void nwep_header_set_n(nwep_header *hdr, const uint8_t *name, size_t name_len,
                       const uint8_t *value, size_t value_len) {
  if (hdr == NULL) {
    return;
  }
  hdr->name = name;
  hdr->name_len = name_len;
  hdr->value = value;
  hdr->value_len = value_len;
}

const nwep_header *nwep_msg_find_header(const nwep_msg *msg, const char *name) {
  size_t i;
  size_t name_len;

  if (msg == NULL || name == NULL || msg->headers == NULL) {
    return NULL;
  }

  name_len = strlen(name);

  for (i = 0; i < msg->header_count; i++) {
    if (msg->headers[i].name_len == name_len &&
        memcmp(msg->headers[i].name, name, name_len) == 0) {
      return &msg->headers[i];
    }
  }

  return NULL;
}

int nwep_header_value_eq(const nwep_header *hdr, const char *value) {
  size_t value_len;

  if (hdr == NULL || value == NULL) {
    return 0;
  }

  value_len = strlen(value);

  if (hdr->value_len != value_len) {
    return 0;
  }

  return memcmp(hdr->value, value, value_len) == 0;
}

/*
 * Message functions
 */

void nwep_msg_init(nwep_msg *msg, uint8_t type) {
  if (msg == NULL) {
    return;
  }
  memset(msg, 0, sizeof(*msg));
  msg->type = type;
}

size_t nwep_msg_encode_len(const nwep_msg *msg) {
  size_t len;
  size_t i;

  if (msg == NULL) {
    return 0;
  }

  /* Frame header (4 bytes) + message type (1 byte) */
  len = NWEP_FRAME_HEADER_SIZE + NWEP_MSG_TYPE_SIZE;

  /* Header count (4 bytes) */
  len += 4;

  /* Each header: name_len (4) + name + value_len (4) + value */
  for (i = 0; i < msg->header_count; i++) {
    len += 4 + msg->headers[i].name_len + 4 + msg->headers[i].value_len;
  }

  /* Body */
  len += msg->body_len;

  return len;
}

size_t nwep_msg_encode(uint8_t *dest, size_t destlen, const nwep_msg *msg) {
  uint8_t *p;
  size_t total_len;
  uint32_t payload_len;
  size_t i;

  if (dest == NULL || msg == NULL) {
    return 0;
  }

  total_len = nwep_msg_encode_len(msg);
  if (total_len == 0 || total_len > destlen) {
    return 0;
  }

  /* Validate message size */
  if (total_len > NWEP_DEFAULT_MAX_MESSAGE_SIZE + NWEP_FRAME_HEADER_SIZE) {
    return 0;
  }

  /* Validate header count */
  if (msg->header_count > NWEP_MAX_HEADERS) {
    return 0;
  }

  p = dest;

  /* Payload length (excludes the 4-byte length field itself) */
  payload_len = (uint32_t)(total_len - NWEP_FRAME_HEADER_SIZE);
  p = nwep_put_uint32be(p, payload_len);

  /* Message type */
  *p++ = msg->type;

  /* Header count */
  p = nwep_put_uint32be(p, (uint32_t)msg->header_count);

  /* Headers */
  for (i = 0; i < msg->header_count; i++) {
    const nwep_header *hdr = &msg->headers[i];

    /* Validate header size */
    if (hdr->name_len + hdr->value_len > NWEP_MAX_HEADER_SIZE) {
      return 0;
    }

    /* Name length and name */
    p = nwep_put_uint32be(p, (uint32_t)hdr->name_len);
    if (hdr->name_len > 0 && hdr->name != NULL) {
      memcpy(p, hdr->name, hdr->name_len);
      p += hdr->name_len;
    }

    /* Value length and value */
    p = nwep_put_uint32be(p, (uint32_t)hdr->value_len);
    if (hdr->value_len > 0 && hdr->value != NULL) {
      memcpy(p, hdr->value, hdr->value_len);
      p += hdr->value_len;
    }
  }

  /* Body */
  if (msg->body_len > 0 && msg->body != NULL) {
    memcpy(p, msg->body, msg->body_len);
    p += msg->body_len;
  }

  return (size_t)(p - dest);
}

int nwep_msg_decode_header(uint32_t *payload_len, const uint8_t *src,
                           size_t srclen) {
  if (payload_len == NULL || src == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  if (srclen < NWEP_FRAME_HEADER_SIZE) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  nwep_get_uint32be(payload_len, src);

  /* Validate payload length */
  if (*payload_len > NWEP_DEFAULT_MAX_MESSAGE_SIZE) {
    return NWEP_ERR_PROTO_MSG_TOO_LARGE;
  }

  return 0;
}

int nwep_msg_decode(nwep_msg *msg, const uint8_t *src, size_t srclen,
                    nwep_header *headers, size_t max_headers) {
  const uint8_t *p;
  const uint8_t *end;
  uint32_t payload_len;
  uint32_t header_count;
  size_t i;
  int rv;

  if (msg == NULL || src == NULL || headers == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }

  memset(msg, 0, sizeof(*msg));
  msg->headers = headers;

  /* Decode frame header */
  rv = nwep_msg_decode_header(&payload_len, src, srclen);
  if (rv != 0) {
    return rv;
  }

#ifdef NWEP_DEBUG
  fprintf(stderr, "[nwep_msg_decode] srclen=%zu, payload_len=%u\n", srclen,
          payload_len);
#endif

  /* Check we have the full message */
  if (srclen < NWEP_FRAME_HEADER_SIZE + payload_len) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  p = src + NWEP_FRAME_HEADER_SIZE;
  end = src + NWEP_FRAME_HEADER_SIZE + payload_len;

  /* Message type */
  if (p >= end) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }
  msg->type = *p++;

  /* Validate message type */
  if (msg->type > NWEP_MSG_NOTIFY) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }

  /* Header count */
  if (p + 4 > end) {
    return NWEP_ERR_PROTO_INVALID_MESSAGE;
  }
  p = nwep_get_uint32be(&header_count, p);

#ifdef NWEP_DEBUG
  fprintf(stderr, "[nwep_msg_decode] msg_type=%u, header_count=%u\n", msg->type,
          header_count);
#endif

  if (header_count > NWEP_MAX_HEADERS) {
    return NWEP_ERR_PROTO_TOO_MANY_HEADERS;
  }

  if (header_count > max_headers) {
    return NWEP_ERR_PROTO_TOO_MANY_HEADERS;
  }

  /* Decode headers */
  for (i = 0; i < header_count; i++) {
    uint32_t name_len, value_len;

    /* Name length */
    if (p + 4 > end) {
      return NWEP_ERR_PROTO_INVALID_HEADER;
    }
    p = nwep_get_uint32be(&name_len, p);

    /* Name */
    if (p + name_len > end) {
      return NWEP_ERR_PROTO_INVALID_HEADER;
    }
    headers[i].name = p;
    headers[i].name_len = name_len;
    p += name_len;

    /* Value length */
    if (p + 4 > end) {
      return NWEP_ERR_PROTO_INVALID_HEADER;
    }
    p = nwep_get_uint32be(&value_len, p);

    /* Value */
    if (p + value_len > end) {
      return NWEP_ERR_PROTO_INVALID_HEADER;
    }
    headers[i].value = p;
    headers[i].value_len = value_len;
    p += value_len;

    /* Check individual header size */
    if (name_len + value_len > NWEP_MAX_HEADER_SIZE) {
      return NWEP_ERR_PROTO_HEADER_TOO_LARGE;
    }
  }

  msg->header_count = header_count;

  /* Remaining bytes are the body */
  msg->body = p;
  msg->body_len = (size_t)(end - p);

  return 0;
}

/*
 * Trace ID / Request ID generation
 */

int nwep_trace_id_generate(uint8_t trace_id[16]) {
  if (trace_id == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }
  return nwep_random_bytes(trace_id, 16);
}

int nwep_request_id_generate(uint8_t request_id[16]) {
  if (request_id == NULL) {
    return NWEP_ERR_INTERNAL_NULL_PTR;
  }
  return nwep_random_bytes(request_id, 16);
}
