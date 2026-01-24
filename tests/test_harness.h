/*
 * nwep test harness
 *
 * libuv-based event loop integration for testing nwep
 */
#ifndef NWEP_TEST_HARNESS_H
#define NWEP_TEST_HARNESS_H

#include <nwep/nwep.h>
#include <uv.h>

#include <stdint.h>
#include <stdlib.h>

/*
 * Maximum UDP packet size
 */
#define TEST_MAX_PKTLEN 1500

/*
 * Test endpoint (client or server)
 */
typedef struct test_endpoint {
  /* libuv handles */
  uv_loop_t *loop;
  uv_udp_t udp;
  uv_timer_t timer;

  /* nwep handles */
  union {
    nwep_server *server;
    nwep_client *client;
  };
  int is_server;

  /* Keypair */
  nwep_keypair keypair;

  /* Local address */
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;

  /* Packet buffer */
  uint8_t pkt_buf[TEST_MAX_PKTLEN];

  /* Test state */
  int connected;
  int request_received;
  int response_received;
  int error;

  /* User data */
  void *user_data;
} test_endpoint;

/*
 * Initialize test endpoint as server
 */
int test_endpoint_init_server(test_endpoint *ep, uv_loop_t *loop,
                              const struct sockaddr *addr);

/*
 * Initialize test endpoint as client
 */
int test_endpoint_init_client(test_endpoint *ep, uv_loop_t *loop,
                              const struct sockaddr *local_addr);

/*
 * Connect client to server
 */
int test_endpoint_connect(test_endpoint *client, const nwep_url *url);

/*
 * Run the event loop until test completes or timeout
 */
int test_run(uv_loop_t *loop, int timeout_ms);

/*
 * Clean up test endpoint
 */
void test_endpoint_cleanup(test_endpoint *ep);

/*
 * Get current timestamp in nanoseconds
 */
uint64_t test_timestamp(void);

/*
 * Simple assertion macro
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
    return 0;                                                                   \
  } while (0)

#define TEST_FAIL(msg)                                                         \
  do {                                                                         \
    fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, (msg));           \
    return 1;                                                                   \
  } while (0)

#endif /* !defined(NWEP_TEST_HARNESS_H) */
