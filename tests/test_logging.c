/*
 * nwep logging tests
 *
 * Tests for Phase 11 structured logging and trace ID propagation.
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
 * Callback test state
 */
static int g_callback_called = 0;
static nwep_log_level g_last_level = NWEP_LOG_TRACE;
static char g_last_message[1024] = {0};
static char g_last_component[256] = {0};
static uint8_t g_last_trace_id[16] = {0};

static void test_log_callback(const nwep_log_entry *entry, void *user_data) {
  (void)user_data;
  g_callback_called++;
  g_last_level = entry->level;
  if (entry->message) {
    strncpy(g_last_message, entry->message, sizeof(g_last_message) - 1);
    g_last_message[sizeof(g_last_message) - 1] = '\0';
  }
  if (entry->component) {
    strncpy(g_last_component, entry->component, sizeof(g_last_component) - 1);
    g_last_component[sizeof(g_last_component) - 1] = '\0';
  }
  memcpy(g_last_trace_id, entry->trace_id, 16);
}

static void reset_callback_state(void) {
  g_callback_called = 0;
  g_last_level = NWEP_LOG_TRACE;
  g_last_message[0] = '\0';
  g_last_component[0] = '\0';
  memset(g_last_trace_id, 0, 16);
}

/*
 * Test: Log level string conversion
 */
static int test_log_level_str(void) {
  printf("Test: Log level string conversion\n");

  TEST_ASSERT(strcmp(nwep_log_level_str(NWEP_LOG_TRACE), "TRACE") == 0,
              "TRACE level string mismatch");
  TEST_ASSERT(strcmp(nwep_log_level_str(NWEP_LOG_DEBUG), "DEBUG") == 0,
              "DEBUG level string mismatch");
  TEST_ASSERT(strcmp(nwep_log_level_str(NWEP_LOG_INFO), "INFO") == 0,
              "INFO level string mismatch");
  TEST_ASSERT(strcmp(nwep_log_level_str(NWEP_LOG_WARN), "WARN") == 0,
              "WARN level string mismatch");
  TEST_ASSERT(strcmp(nwep_log_level_str(NWEP_LOG_ERROR), "ERROR") == 0,
              "ERROR level string mismatch");

  printf("  All level strings correct\n");
  TEST_PASS();
}

/*
 * Test: Log level filtering
 */
static int test_log_level_filtering(void) {
  printf("Test: Log level filtering\n");

  /* Set up callback */
  reset_callback_state();
  nwep_log_set_callback(test_log_callback, NULL);
  nwep_log_set_stderr(0); /* Disable stderr */

  /* Set level to WARN - should filter out TRACE, DEBUG, INFO */
  nwep_log_set_level(NWEP_LOG_WARN);
  TEST_ASSERT(nwep_log_get_level() == NWEP_LOG_WARN, "Level not set to WARN");

  /* These should be filtered */
  nwep_log_trace(NULL, "test", "trace message");
  TEST_ASSERT(g_callback_called == 0, "TRACE should be filtered at WARN level");

  nwep_log_debug(NULL, "test", "debug message");
  TEST_ASSERT(g_callback_called == 0, "DEBUG should be filtered at WARN level");

  nwep_log_info(NULL, "test", "info message");
  TEST_ASSERT(g_callback_called == 0, "INFO should be filtered at WARN level");

  /* These should pass */
  nwep_log_warn(NULL, "test", "warn message");
  TEST_ASSERT(g_callback_called == 1, "WARN should pass at WARN level");
  TEST_ASSERT(g_last_level == NWEP_LOG_WARN, "Level should be WARN");

  nwep_log_error(NULL, "test", "error message");
  TEST_ASSERT(g_callback_called == 2, "ERROR should pass at WARN level");
  TEST_ASSERT(g_last_level == NWEP_LOG_ERROR, "Level should be ERROR");

  printf("  Level filtering works correctly\n");

  /* Reset */
  nwep_log_set_callback(NULL, NULL);
  nwep_log_set_stderr(1);
  nwep_log_set_level(NWEP_LOG_INFO);

  TEST_PASS();
}

/*
 * Test: Callback receives correct data
 */
static int test_callback_data(void) {
  uint8_t trace_id[16];
  int rv;

  printf("Test: Callback receives correct data\n");

  /* Generate a trace ID */
  rv = nwep_trace_id_generate(trace_id);
  TEST_ASSERT(rv == 0, "Failed to generate trace ID");

  /* Set up callback */
  reset_callback_state();
  nwep_log_set_callback(test_log_callback, NULL);
  nwep_log_set_stderr(0);
  nwep_log_set_level(NWEP_LOG_TRACE);

  /* Log with trace ID */
  nwep_log_info(trace_id, "handshake", "Connection established from %s", "192.168.1.1");

  TEST_ASSERT(g_callback_called == 1, "Callback should be called once");
  TEST_ASSERT(g_last_level == NWEP_LOG_INFO, "Level should be INFO");
  TEST_ASSERT(strcmp(g_last_component, "handshake") == 0, "Component mismatch");
  TEST_ASSERT(strstr(g_last_message, "192.168.1.1") != NULL, "Message should contain IP");
  TEST_ASSERT(memcmp(g_last_trace_id, trace_id, 16) == 0, "Trace ID mismatch");

  printf("  Callback received correct level, component, message, and trace ID\n");

  /* Log without trace ID */
  reset_callback_state();
  nwep_log_debug(NULL, "crypto", "Key generated");

  TEST_ASSERT(g_callback_called == 1, "Callback should be called");
  TEST_ASSERT(g_last_level == NWEP_LOG_DEBUG, "Level should be DEBUG");
  TEST_ASSERT(strcmp(g_last_component, "crypto") == 0, "Component mismatch");

  /* Verify trace_id is zeroed when NULL */
  int is_zero = 1;
  for (int i = 0; i < 16; i++) {
    if (g_last_trace_id[i] != 0) {
      is_zero = 0;
      break;
    }
  }
  TEST_ASSERT(is_zero, "Trace ID should be zeroed when NULL");

  printf("  Handles NULL trace ID correctly\n");

  /* Reset */
  nwep_log_set_callback(NULL, NULL);
  nwep_log_set_stderr(1);
  nwep_log_set_level(NWEP_LOG_INFO);

  TEST_PASS();
}

/*
 * Test: JSON formatting
 */
static int test_json_format(void) {
  nwep_log_entry entry;
  char json_buf[2048];
  size_t len;
  uint8_t trace_id[16];

  printf("Test: JSON formatting\n");

  /* Generate trace ID */
  nwep_trace_id_generate(trace_id);

  /* Set up entry */
  entry.level = NWEP_LOG_INFO;
  entry.timestamp_ns = 0;
  memcpy(entry.trace_id, trace_id, 16);
  entry.component = "test";
  entry.message = "Hello, world!";

  /* Format as JSON */
  len = nwep_log_format_json(json_buf, sizeof(json_buf), &entry);
  TEST_ASSERT(len > 0, "JSON formatting failed");

  printf("  JSON: %s\n", json_buf);

  /* Verify JSON structure */
  TEST_ASSERT(strstr(json_buf, "\"timestamp\":") != NULL, "Missing timestamp");
  TEST_ASSERT(strstr(json_buf, "\"level\":\"INFO\"") != NULL, "Missing/wrong level");
  TEST_ASSERT(strstr(json_buf, "\"component\":\"test\"") != NULL, "Missing component");
  TEST_ASSERT(strstr(json_buf, "\"trace_id\":") != NULL, "Missing trace_id");
  TEST_ASSERT(strstr(json_buf, "\"message\":\"Hello, world!\"") != NULL, "Missing message");

  printf("  JSON format is correct\n");

  /* Test JSON escaping */
  entry.message = "Line1\nLine2\tTab\"Quote\\Backslash";
  len = nwep_log_format_json(json_buf, sizeof(json_buf), &entry);
  TEST_ASSERT(len > 0, "JSON formatting with special chars failed");
  TEST_ASSERT(strstr(json_buf, "\\n") != NULL, "Newline not escaped");
  TEST_ASSERT(strstr(json_buf, "\\t") != NULL, "Tab not escaped");
  TEST_ASSERT(strstr(json_buf, "\\\"") != NULL, "Quote not escaped");
  TEST_ASSERT(strstr(json_buf, "\\\\") != NULL, "Backslash not escaped");

  printf("  JSON escaping works correctly\n");

  TEST_PASS();
}

/*
 * Test: Trace ID generation and format
 */
static int test_trace_id(void) {
  uint8_t trace_id1[16], trace_id2[16];
  int rv;

  printf("Test: Trace ID generation\n");

  /* Generate two trace IDs */
  rv = nwep_trace_id_generate(trace_id1);
  TEST_ASSERT(rv == 0, "Failed to generate trace ID 1");

  rv = nwep_trace_id_generate(trace_id2);
  TEST_ASSERT(rv == 0, "Failed to generate trace ID 2");

  /* They should be different */
  TEST_ASSERT(memcmp(trace_id1, trace_id2, 16) != 0,
              "Two generated trace IDs should be different");

  /* Neither should be all zeros */
  int is_zero = 1;
  for (int i = 0; i < 16; i++) {
    if (trace_id1[i] != 0) {
      is_zero = 0;
      break;
    }
  }
  TEST_ASSERT(!is_zero, "Trace ID should not be all zeros");

  printf("  Trace IDs are unique and non-zero\n");

  TEST_PASS();
}

/*
 * Test: Request ID generation
 */
static int test_request_id(void) {
  uint8_t req_id1[16], req_id2[16];
  int rv;

  printf("Test: Request ID generation\n");

  /* Generate two request IDs */
  rv = nwep_request_id_generate(req_id1);
  TEST_ASSERT(rv == 0, "Failed to generate request ID 1");

  rv = nwep_request_id_generate(req_id2);
  TEST_ASSERT(rv == 0, "Failed to generate request ID 2");

  /* They should be different */
  TEST_ASSERT(memcmp(req_id1, req_id2, 16) != 0,
              "Two generated request IDs should be different");

  printf("  Request IDs are unique\n");

  TEST_PASS();
}

int main(void) {
  int failed = 0;

  setbuf(stdout, NULL);

  printf("=== nwep logging tests (Phase 11) ===\n\n");

  /* Initialize nwep */
  printf("Initializing nwep...\n");
  nwep_init();
  printf("nwep initialized\n\n");

  failed += test_log_level_str();
  printf("\n");

  failed += test_log_level_filtering();
  printf("\n");

  failed += test_callback_data();
  printf("\n");

  failed += test_json_format();
  printf("\n");

  failed += test_trace_id();
  printf("\n");

  failed += test_request_id();
  printf("\n");

  printf("=== Results: %d test(s) failed ===\n", failed);

  return failed;
}
