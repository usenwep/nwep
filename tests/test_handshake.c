/*
 * nwep handshake test
 *
 * Tests the basic QUIC handshake between client and server
 */
#define _GNU_SOURCE
#include "test_harness.h"

#include <stdio.h>
#include <string.h>

/*
 * Build URL for server
 */
static int build_server_url(nwep_url *url, test_endpoint *server) {
  struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&server->local_addr;
  nwep_nodeid nodeid;
  int rv;

  memset(url, 0, sizeof(*url));

  /* Get server's NodeID */
  rv = nwep_nodeid_from_pubkey(&nodeid, server->keypair.pubkey);
  if (rv != 0) {
    return rv;
  }

  /* Build URL */
  memcpy(url->addr.ip, &addr6->sin6_addr, 16);
  memcpy(&url->addr.nodeid, &nodeid, sizeof(nodeid));
  url->addr.port = ntohs(addr6->sin6_port);
  strcpy(url->path, "/test");

  return 0;
}

/*
 * Test: Basic handshake
 */
static int test_basic_handshake(void) {
  uv_loop_t loop;
  test_endpoint server, client;
  struct sockaddr_in6 server_addr;
  nwep_url url;
  int rv;

  printf("Test: basic handshake\n");

  /* Initialize loop */
  printf("  Initializing uv loop...\n");
  uv_loop_init(&loop);
  printf("  Loop initialized\n");

  /* Set up server address (localhost, random port) */
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin6_family = AF_INET6;
  server_addr.sin6_addr = in6addr_loopback;
  server_addr.sin6_port = 0; /* Let OS assign port */

  /* Initialize server */
  printf("  Initializing server endpoint...\n");
  rv = test_endpoint_init_server(&server, &loop, (struct sockaddr *)&server_addr);
  printf("  Server endpoint init returned %d\n", rv);
  TEST_ASSERT(rv == 0, "Failed to initialize server");

  printf("  Server listening on port %d\n",
         ntohs(((struct sockaddr_in6 *)&server.local_addr)->sin6_port));

  /* Initialize client */
  rv = test_endpoint_init_client(&client, &loop, NULL);
  TEST_ASSERT(rv == 0, "Failed to initialize client");

  /* Build URL for server */
  rv = build_server_url(&url, &server);
  TEST_ASSERT(rv == 0, "Failed to build server URL");

  /* Connect client to server */
  printf("  Connecting client to server...\n");
  rv = test_endpoint_connect(&client, &url);
  TEST_ASSERT(rv == 0, "Failed to connect client");

  /* Run event loop for up to 2 seconds */
  printf("  Running event loop...\n");
  fflush(stdout);
  test_run(&loop, 2000);
  printf("  Event loop finished.\n");
  fflush(stdout);

  /* Check results */
  printf("  Server connected: %d\n", server.connected);
  printf("  Client connected: %d\n", client.connected);
  printf("  Server error: %d\n", server.error);
  printf("  Client error: %d\n", client.error);
  fflush(stdout);

  /* Clean up */
  printf("  Cleaning up client...\n");
  fflush(stdout);
  test_endpoint_cleanup(&client);
  printf("  Cleaning up server...\n");
  fflush(stdout);
  test_endpoint_cleanup(&server);
  printf("  Closing loop...\n");
  fflush(stdout);
  uv_loop_close(&loop);
  printf("  Cleanup done.\n");
  fflush(stdout);

  /* Check if both sides connected */
  if (server.connected && client.connected) {
    printf("  QUIC handshake succeeded!\n");
    TEST_PASS();
  }

  /* Report errors */
  if (server.error || client.error) {
    printf("  Errors occurred during handshake\n");
    TEST_FAIL("Handshake errors");
  }

  TEST_FAIL("Handshake incomplete");
}

int main(void) {
  int failed = 0;

  setbuf(stdout, NULL); /* Disable stdout buffering for debug */

  printf("=== nwep handshake tests ===\n\n");

  /* Initialize nwep */
  printf("Initializing nwep...\n");
  nwep_init();
  printf("nwep initialized\n");

  failed += test_basic_handshake();

  printf("\n=== Results: %d test(s) failed ===\n", failed);

  return failed;
}
