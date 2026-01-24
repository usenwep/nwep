/*
 * nwep NOTIFY message tests
 *
 * Tests for server-initiated bidirectional streaming via NOTIFY messages.
 */
#include <nwep/nwep.h>

#include <stdio.h>
#include <string.h>

/*
 * Simple assertion macros
 */
#define TEST_ASSERT(cond, msg)                                                 \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, (msg));         \
      return 1;                                                                \
    }                                                                          \
  } while (0)

#define TEST_PASS()                                                            \
  do {                                                                         \
    printf("PASS\n");                                                          \
    return 0;                                                                  \
  } while (0)

/*
 * Test: NOTIFY message building
 */
static int test_notify_build(void) {
  nwep_msg msg;
  nwep_header headers[8];
  uint8_t notify_id[NWEP_NOTIFY_ID_LEN];
  uint8_t body[] = "test payload";
  int rv;

  printf("Test: NOTIFY message building\n");

  /* Generate a notify ID */
  memset(notify_id, 0x42, NWEP_NOTIFY_ID_LEN);

  /* Build NOTIFY message with all fields */
  rv = nwep_notify_build(&msg, headers, 8, "update", "/resource/123",
                         notify_id, body, sizeof(body) - 1);
  TEST_ASSERT(rv == 0, "nwep_notify_build failed");
  TEST_ASSERT(msg.type == NWEP_MSG_NOTIFY, "Wrong message type");
  TEST_ASSERT(msg.header_count >= 3, "Expected at least 3 headers");

  /* Verify :event header */
  const nwep_header *event_hdr = nwep_msg_find_header(&msg, NWEP_HDR_EVENT);
  TEST_ASSERT(event_hdr != NULL, "Missing :event header");
  TEST_ASSERT(nwep_header_value_eq(event_hdr, "update"), ":event value mismatch");

  /* Verify :path header */
  const nwep_header *path_hdr = nwep_msg_find_header(&msg, NWEP_HDR_PATH);
  TEST_ASSERT(path_hdr != NULL, "Missing :path header");
  TEST_ASSERT(nwep_header_value_eq(path_hdr, "/resource/123"),
              ":path value mismatch");

  /* Verify notify-id header */
  const nwep_header *id_hdr = nwep_msg_find_header(&msg, NWEP_HDR_NOTIFY_ID);
  TEST_ASSERT(id_hdr != NULL, "Missing notify-id header");
  TEST_ASSERT(id_hdr->value_len == NWEP_NOTIFY_ID_LEN, "notify-id length mismatch");

  /* Verify body */
  TEST_ASSERT(msg.body_len == sizeof(body) - 1, "Body length mismatch");
  TEST_ASSERT(memcmp(msg.body, body, msg.body_len) == 0, "Body content mismatch");

  printf("  Built NOTIFY with event='update', path='/resource/123'\n");

  /* Build NOTIFY without optional fields */
  rv = nwep_notify_build(&msg, headers, 8, "delete", NULL, NULL, NULL, 0);
  TEST_ASSERT(rv == 0, "nwep_notify_build without optionals failed");
  TEST_ASSERT(msg.type == NWEP_MSG_NOTIFY, "Wrong message type");

  event_hdr = nwep_msg_find_header(&msg, NWEP_HDR_EVENT);
  TEST_ASSERT(event_hdr != NULL, "Missing :event header");
  TEST_ASSERT(nwep_header_value_eq(event_hdr, "delete"), ":event value mismatch");

  printf("  Built minimal NOTIFY with event='delete'\n");

  TEST_PASS();
}

/*
 * Test: NOTIFY message encoding/decoding roundtrip
 */
static int test_notify_encode_decode(void) {
  nwep_msg msg, decoded_msg;
  nwep_header headers[8], decoded_headers[8];
  nwep_notify notify;
  uint8_t notify_id[NWEP_NOTIFY_ID_LEN];
  uint8_t body[] = "notification payload";
  uint8_t buf[1024];
  size_t encoded_len;
  int rv;

  printf("Test: NOTIFY message encoding/decoding\n");

  /* Generate a notify ID */
  rv = nwep_random_bytes(notify_id, NWEP_NOTIFY_ID_LEN);
  TEST_ASSERT(rv == 0, "Failed to generate notify ID");

  /* Build NOTIFY message */
  rv = nwep_notify_build(&msg, headers, 8, "message", "/chat/room1",
                         notify_id, body, sizeof(body) - 1);
  TEST_ASSERT(rv == 0, "nwep_notify_build failed");

  /* Encode */
  encoded_len = nwep_msg_encode(buf, sizeof(buf), &msg);
  TEST_ASSERT(encoded_len > 0, "nwep_msg_encode failed");

  printf("  Encoded NOTIFY message: %zu bytes\n", encoded_len);

  /* Decode */
  rv = nwep_msg_decode(&decoded_msg, buf, encoded_len, decoded_headers, 8);
  TEST_ASSERT(rv == 0, "nwep_msg_decode failed");
  TEST_ASSERT(decoded_msg.type == NWEP_MSG_NOTIFY, "Decoded type mismatch");

  /* Parse as notify */
  rv = nwep_notify_parse(&notify, &decoded_msg);
  TEST_ASSERT(rv == 0, "nwep_notify_parse failed");
  TEST_ASSERT(notify.event != NULL, "Missing event");
  TEST_ASSERT(strncmp(notify.event, "message", 7) == 0, "Event mismatch");
  TEST_ASSERT(notify.path != NULL, "Missing path");
  TEST_ASSERT(strncmp(notify.path, "/chat/room1", 11) == 0, "Path mismatch");
  TEST_ASSERT(notify.has_notify_id, "notify_id not set");
  TEST_ASSERT(memcmp(notify.notify_id, notify_id, NWEP_NOTIFY_ID_LEN) == 0,
              "notify_id mismatch");
  TEST_ASSERT(notify.body_len == sizeof(body) - 1, "Body length mismatch");
  TEST_ASSERT(memcmp(notify.body, body, notify.body_len) == 0,
              "Body content mismatch");

  printf("  Decoded NOTIFY: event='%.*s', path='%.*s'\n",
         7, notify.event, 11, notify.path);

  TEST_PASS();
}

/*
 * Test: NOTIFY parse validation
 */
static int test_notify_parse_validation(void) {
  nwep_msg msg;
  nwep_header headers[8];
  nwep_notify notify;
  int rv;

  printf("Test: NOTIFY parse validation\n");

  /* Test: Wrong message type */
  nwep_msg_init(&msg, NWEP_MSG_REQUEST);
  msg.headers = headers;
  msg.header_count = 0;
  rv = nwep_notify_parse(&notify, &msg);
  TEST_ASSERT(rv == NWEP_ERR_PROTO_INVALID_MESSAGE,
              "Should reject non-NOTIFY message");
  printf("  Rejects non-NOTIFY message type\n");

  /* Test: Missing :event header */
  nwep_msg_init(&msg, NWEP_MSG_NOTIFY);
  msg.headers = headers;
  nwep_header_set(&headers[0], NWEP_HDR_PATH, "/test");
  msg.header_count = 1;
  rv = nwep_notify_parse(&notify, &msg);
  TEST_ASSERT(rv == NWEP_ERR_PROTO_MISSING_HEADER,
              "Should reject NOTIFY without :event");
  printf("  Rejects NOTIFY without :event header\n");

  /* Test: Valid minimal NOTIFY */
  nwep_msg_init(&msg, NWEP_MSG_NOTIFY);
  msg.headers = headers;
  nwep_header_set(&headers[0], NWEP_HDR_EVENT, "ping");
  msg.header_count = 1;
  rv = nwep_notify_parse(&notify, &msg);
  TEST_ASSERT(rv == 0, "Should accept minimal NOTIFY");
  TEST_ASSERT(notify.path == NULL, "Path should be NULL");
  TEST_ASSERT(notify.has_notify_id == 0, "Should not have notify_id");
  printf("  Accepts minimal NOTIFY with just :event\n");

  TEST_PASS();
}

/*
 * Test: NOTIFY message type constant
 */
static int test_notify_type_constant(void) {
  printf("Test: NOTIFY message type constant\n");

  TEST_ASSERT(NWEP_MSG_REQUEST == 0, "REQUEST should be 0");
  TEST_ASSERT(NWEP_MSG_RESPONSE == 1, "RESPONSE should be 1");
  TEST_ASSERT(NWEP_MSG_STREAM == 2, "STREAM should be 2");
  TEST_ASSERT(NWEP_MSG_NOTIFY == 3, "NOTIFY should be 3");

  printf("  Message types: REQUEST=0, RESPONSE=1, STREAM=2, NOTIFY=3\n");

  TEST_PASS();
}

/*
 * Test: NOTIFY header constants
 */
static int test_notify_header_constants(void) {
  printf("Test: NOTIFY header constants\n");

  TEST_ASSERT(strcmp(NWEP_HDR_EVENT, ":event") == 0,
              "NWEP_HDR_EVENT should be ':event'");
  TEST_ASSERT(strcmp(NWEP_HDR_NOTIFY_ID, "notify-id") == 0,
              "NWEP_HDR_NOTIFY_ID should be 'notify-id'");

  printf("  Headers: :event, notify-id\n");

  TEST_PASS();
}

/*
 * Test: nwep_notify struct initialization
 */
static int test_notify_struct(void) {
  nwep_notify notify;

  printf("Test: nwep_notify struct\n");

  memset(&notify, 0, sizeof(notify));

  /* Test field sizes */
  TEST_ASSERT(sizeof(notify.notify_id) == NWEP_NOTIFY_ID_LEN,
              "notify_id should be 16 bytes");

  /* Test field assignments */
  notify.event = "test_event";
  notify.path = "/test/path";
  notify.has_notify_id = 1;
  memset(notify.notify_id, 0xAB, NWEP_NOTIFY_ID_LEN);
  notify.body = (const uint8_t *)"body";
  notify.body_len = 4;

  TEST_ASSERT(strcmp(notify.event, "test_event") == 0, "event field");
  TEST_ASSERT(strcmp(notify.path, "/test/path") == 0, "path field");
  TEST_ASSERT(notify.has_notify_id == 1, "has_notify_id field");
  TEST_ASSERT(notify.notify_id[0] == 0xAB, "notify_id field");
  TEST_ASSERT(notify.body_len == 4, "body_len field");

  printf("  Struct has event, path, notify_id, has_notify_id, body, body_len\n");

  TEST_PASS();
}

/*
 * Test: NOTIFY ID length constant
 */
static int test_notify_id_len(void) {
  printf("Test: NOTIFY ID length constant\n");

  TEST_ASSERT(NWEP_NOTIFY_ID_LEN == 16, "NOTIFY_ID_LEN should be 16");

  printf("  NWEP_NOTIFY_ID_LEN = 16\n");

  TEST_PASS();
}

/*
 * Test: Message decode allows NOTIFY type
 */
static int test_msg_decode_notify(void) {
  nwep_msg msg;
  nwep_header headers[8];
  uint8_t buf[256];
  uint8_t *p = buf;
  size_t msg_len;
  int rv;

  printf("Test: Message decode allows NOTIFY type\n");

  /*
   * Manually construct a minimal NOTIFY message:
   * [4-byte length][1-byte type=3][4-byte header_count=1]
   * [4-byte name_len][name ":event"][4-byte value_len][value "test"]
   */
  p = buf + 4; /* Skip length for now */

  /* Type */
  *p++ = NWEP_MSG_NOTIFY;

  /* Header count */
  p = nwep_put_uint32be(p, 1);

  /* Header: :event = test */
  p = nwep_put_uint32be(p, 6); /* name len */
  memcpy(p, ":event", 6);
  p += 6;
  p = nwep_put_uint32be(p, 4); /* value len */
  memcpy(p, "test", 4);
  p += 4;

  /* Write length */
  msg_len = (size_t)(p - buf - 4);
  nwep_put_uint32be(buf, (uint32_t)msg_len);

  /* Decode */
  rv = nwep_msg_decode(&msg, buf, (size_t)(p - buf), headers, 8);
  TEST_ASSERT(rv == 0, "nwep_msg_decode should accept NOTIFY");
  TEST_ASSERT(msg.type == NWEP_MSG_NOTIFY, "Type should be NOTIFY");

  printf("  nwep_msg_decode accepts type=3 (NOTIFY)\n");

  /* Test invalid type (4 or higher should fail) */
  buf[4] = 4; /* Invalid type */
  rv = nwep_msg_decode(&msg, buf, (size_t)(p - buf), headers, 8);
  TEST_ASSERT(rv == NWEP_ERR_PROTO_INVALID_MESSAGE,
              "Should reject type > NOTIFY");

  printf("  nwep_msg_decode rejects type > 3\n");

  TEST_PASS();
}

int main(void) {
  int failed = 0;

  setbuf(stdout, NULL);

  printf("=== nwep NOTIFY message tests ===\n\n");

  /* Initialize nwep */
  printf("Initializing nwep...\n");
  nwep_init();
  printf("nwep initialized\n\n");

  failed += test_notify_type_constant();
  printf("\n");

  failed += test_notify_header_constants();
  printf("\n");

  failed += test_notify_id_len();
  printf("\n");

  failed += test_notify_struct();
  printf("\n");

  failed += test_notify_build();
  printf("\n");

  failed += test_notify_encode_decode();
  printf("\n");

  failed += test_notify_parse_validation();
  printf("\n");

  failed += test_msg_decode_notify();
  printf("\n");

  printf("=== Results: %d test(s) failed ===\n", failed);

  return failed;
}
