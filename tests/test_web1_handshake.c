/*
 * nwep WEB/1 CONNECT/AUTHENTICATE handshake unit tests
 *
 * Tests the Phase 5 handshake message building, parsing, and verification
 * without requiring full QUIC stream integration.
 */
#define _GNU_SOURCE
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

#define TEST_FAIL(msg)                                                         \
  do {                                                                         \
    fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, (msg));           \
    return 1;                                                                  \
  } while (0)

/*
 * Test: CONNECT request building and parsing
 */
static int test_connect_request(void) {
  nwep_keypair client_keypair, server_keypair;
  nwep_handshake client_hs, server_hs;
  nwep_nodeid expected_server_nodeid;
  nwep_msg msg;
  nwep_header headers[16];
  uint8_t header_buf[1024];
  uint8_t wire_buf[2048];
  size_t wire_len;
  int rv;

  printf("Test: CONNECT request build/parse\n");

  /* Generate keypairs */
  rv = nwep_keypair_generate(&client_keypair);
  TEST_ASSERT(rv == 0, "Failed to generate client keypair");

  rv = nwep_keypair_generate(&server_keypair);
  TEST_ASSERT(rv == 0, "Failed to generate server keypair");

  /* Get server's expected NodeID */
  rv = nwep_nodeid_from_keypair(&expected_server_nodeid, &server_keypair);
  TEST_ASSERT(rv == 0, "Failed to compute server NodeID");

  /* Initialize client handshake with expected server */
  rv = nwep_handshake_client_init(&client_hs, &client_keypair, &expected_server_nodeid);
  TEST_ASSERT(rv == 0, "Failed to init client handshake");

  /* Initialize server handshake */
  rv = nwep_handshake_server_init(&server_hs, &server_keypair);
  TEST_ASSERT(rv == 0, "Failed to init server handshake");

  /* Client builds CONNECT request */
  rv = nwep_connect_request_build(&msg, headers, 16, header_buf, sizeof(header_buf), &client_hs);
  TEST_ASSERT(rv == 0, "Failed to build CONNECT request");
  TEST_ASSERT(msg.header_count >= 5, "CONNECT request missing headers");

  /* Verify required headers */
  const nwep_header *hdr;
  hdr = nwep_msg_find_header(&msg, NWEP_HDR_METHOD);
  TEST_ASSERT(hdr != NULL, "Missing :method header");
  TEST_ASSERT(nwep_header_value_eq(hdr, NWEP_METHOD_CONNECT), ":method not 'connect'");

  hdr = nwep_msg_find_header(&msg, NWEP_HDR_VERSION);
  TEST_ASSERT(hdr != NULL, "Missing :version header");
  TEST_ASSERT(nwep_header_value_eq(hdr, NWEP_PROTO_VER), ":version not 'WEB/1'");

  hdr = nwep_msg_find_header(&msg, NWEP_HDR_CLIENT_ID);
  TEST_ASSERT(hdr != NULL, "Missing client-id header");

  hdr = nwep_msg_find_header(&msg, NWEP_HDR_CHALLENGE);
  TEST_ASSERT(hdr != NULL, "Missing challenge header");

  /* Encode to wire format */
  wire_len = nwep_msg_encode(wire_buf, sizeof(wire_buf), &msg);
  TEST_ASSERT(wire_len > 0, "Failed to encode CONNECT request");

  printf("  CONNECT request encoded: %zu bytes\n", wire_len);

  /* Server decodes and parses */
  nwep_header parse_headers[16];
  nwep_msg parsed_msg;
  rv = nwep_msg_decode(&parsed_msg, wire_buf, wire_len, parse_headers, 16);
  TEST_ASSERT(rv == 0, "Failed to decode CONNECT request");
  TEST_ASSERT(parsed_msg.type == NWEP_MSG_REQUEST, "Wrong message type");

  /* Server parses CONNECT request into handshake state */
  rv = nwep_connect_request_parse(&server_hs, &parsed_msg);
  TEST_ASSERT(rv == 0, "Failed to parse CONNECT request");
  TEST_ASSERT(server_hs.state.server == NWEP_SERVER_STATE_AWAITING_CLIENT_AUTH,
              "Server state not AWAITING_CLIENT_AUTH");

  /* Verify server received client's pubkey */
  TEST_ASSERT(memcmp(server_hs.peer_pubkey, client_keypair.pubkey, 32) == 0,
              "Server didn't receive correct client pubkey");

  /* Verify server received client's challenge */
  TEST_ASSERT(memcmp(server_hs.peer_challenge, client_hs.local_challenge, 32) == 0,
              "Server didn't receive correct client challenge");

  printf("  Server state: %s\n", nwep_server_state_str(server_hs.state.server));

  /* Clean up */
  nwep_handshake_free(&client_hs);
  nwep_handshake_free(&server_hs);
  nwep_keypair_clear(&client_keypair);
  nwep_keypair_clear(&server_keypair);

  TEST_PASS();
}

/*
 * Test: CONNECT response building and parsing
 */
static int test_connect_response(void) {
  nwep_keypair client_keypair, server_keypair;
  nwep_handshake client_hs, server_hs;
  nwep_nodeid expected_server_nodeid;
  nwep_msg req_msg, resp_msg;
  nwep_header headers[16];
  uint8_t header_buf[1024];
  uint8_t wire_buf[2048];
  size_t wire_len;
  int rv;

  printf("Test: CONNECT response build/parse\n");

  /* Generate keypairs */
  rv = nwep_keypair_generate(&client_keypair);
  TEST_ASSERT(rv == 0, "Failed to generate client keypair");

  rv = nwep_keypair_generate(&server_keypair);
  TEST_ASSERT(rv == 0, "Failed to generate server keypair");

  /* Get server's expected NodeID */
  rv = nwep_nodeid_from_keypair(&expected_server_nodeid, &server_keypair);
  TEST_ASSERT(rv == 0, "Failed to compute server NodeID");

  /* Initialize handshakes */
  rv = nwep_handshake_client_init(&client_hs, &client_keypair, &expected_server_nodeid);
  TEST_ASSERT(rv == 0, "Failed to init client handshake");

  rv = nwep_handshake_server_init(&server_hs, &server_keypair);
  TEST_ASSERT(rv == 0, "Failed to init server handshake");

  /* Client builds and sends CONNECT request */
  rv = nwep_connect_request_build(&req_msg, headers, 16, header_buf, sizeof(header_buf), &client_hs);
  TEST_ASSERT(rv == 0, "Failed to build CONNECT request");

  wire_len = nwep_msg_encode(wire_buf, sizeof(wire_buf), &req_msg);
  TEST_ASSERT(wire_len > 0, "Failed to encode CONNECT request");

  /* Server parses request */
  nwep_header parse_headers[16];
  nwep_msg parsed_req;
  rv = nwep_msg_decode(&parsed_req, wire_buf, wire_len, parse_headers, 16);
  TEST_ASSERT(rv == 0, "Failed to decode CONNECT request");

  rv = nwep_connect_request_parse(&server_hs, &parsed_req);
  TEST_ASSERT(rv == 0, "Failed to parse CONNECT request");

  /* Server builds CONNECT response */
  memset(headers, 0, sizeof(headers));
  memset(header_buf, 0, sizeof(header_buf));
  rv = nwep_connect_response_build(&resp_msg, headers, 16, header_buf, sizeof(header_buf), &server_hs);
  TEST_ASSERT(rv == 0, "Failed to build CONNECT response");

  /* Verify required headers */
  const nwep_header *hdr;
  hdr = nwep_msg_find_header(&resp_msg, NWEP_HDR_STATUS);
  TEST_ASSERT(hdr != NULL, "Missing :status header");
  TEST_ASSERT(nwep_header_value_eq(hdr, NWEP_STATUS_OK), ":status not 'ok'");

  hdr = nwep_msg_find_header(&resp_msg, NWEP_HDR_SERVER_ID);
  TEST_ASSERT(hdr != NULL, "Missing server-id header");

  hdr = nwep_msg_find_header(&resp_msg, NWEP_HDR_SERVER_CHALLENGE);
  TEST_ASSERT(hdr != NULL, "Missing server-challenge header");

  hdr = nwep_msg_find_header(&resp_msg, NWEP_HDR_CHALLENGE_RESPONSE);
  TEST_ASSERT(hdr != NULL, "Missing challenge-response header");

  hdr = nwep_msg_find_header(&resp_msg, NWEP_HDR_TRANSCRIPT_SIG);
  TEST_ASSERT(hdr != NULL, "Missing transcript-sig header");

  /* Encode response */
  wire_len = nwep_msg_encode(wire_buf, sizeof(wire_buf), &resp_msg);
  TEST_ASSERT(wire_len > 0, "Failed to encode CONNECT response");

  printf("  CONNECT response encoded: %zu bytes\n", wire_len);

  /* Client decodes and parses response */
  nwep_header resp_parse_headers[16];
  nwep_msg parsed_resp;
  rv = nwep_msg_decode(&parsed_resp, wire_buf, wire_len, resp_parse_headers, 16);
  TEST_ASSERT(rv == 0, "Failed to decode CONNECT response");
  TEST_ASSERT(parsed_resp.type == NWEP_MSG_RESPONSE, "Wrong message type");

  /* Before parsing, check client and server transcript state */
  printf("  Server transcript after build: %zu bytes\n", server_hs.transcript_len);

  /* Client parses CONNECT response - this verifies Layer 2 & 3 and transcript */
  rv = nwep_connect_response_parse(&client_hs, &parsed_resp);
  if (rv != 0) {
    printf("  CONNECT response parse error: %s (%d)\n", nwep_strerror(rv), rv);
    printf("  Client transcript after parse: %zu bytes\n", client_hs.transcript_len);
    /* Compare first 32 bytes of transcripts */
    printf("  Server transcript[0:32]: ");
    for (int i = 0; i < 32 && (size_t)i < server_hs.transcript_len; i++) {
      printf("%02x", server_hs.transcript[i]);
    }
    printf("\n  Client transcript[0:32]: ");
    for (int i = 0; i < 32 && (size_t)i < client_hs.transcript_len; i++) {
      printf("%02x", client_hs.transcript[i]);
    }
    printf("\n");
    /* Compare last 32 bytes */
    printf("  Server transcript[-32:]: ");
    for (size_t i = (server_hs.transcript_len > 32 ? server_hs.transcript_len - 32 : 0);
         i < server_hs.transcript_len; i++) {
      printf("%02x", server_hs.transcript[i]);
    }
    printf("\n  Client transcript[-32:]: ");
    for (size_t i = (client_hs.transcript_len > 32 ? client_hs.transcript_len - 32 : 0);
         i < client_hs.transcript_len; i++) {
      printf("%02x", client_hs.transcript[i]);
    }
    printf("\n");
    /* Full comparison */
    int match = 1;
    if (server_hs.transcript_len != client_hs.transcript_len) {
      printf("  Transcript lengths differ!\n");
      match = 0;
    } else {
      for (size_t i = 0; i < server_hs.transcript_len; i++) {
        if (server_hs.transcript[i] != client_hs.transcript[i]) {
          printf("  Transcripts differ at byte %zu: server=%02x client=%02x\n",
                 i, server_hs.transcript[i], client_hs.transcript[i]);
          match = 0;
          break;
        }
      }
    }
    if (match) {
      printf("  Transcripts are IDENTICAL! Issue must be with signature/verification.\n");
      /* Check pubkeys */
      printf("  Server local pubkey: ");
      for (int i = 0; i < 8; i++) printf("%02x", server_keypair.pubkey[i]);
      printf("...\n");
      printf("  Client peer_pubkey:  ");
      for (int i = 0; i < 8; i++) printf("%02x", client_hs.peer_pubkey[i]);
      printf("...\n");
      int pubkey_match = memcmp(server_keypair.pubkey, client_hs.peer_pubkey, 32) == 0;
      printf("  Pubkeys match: %s\n", pubkey_match ? "YES" : "NO");
      /* Check signature from response */
      const nwep_header *sig_hdr = nwep_msg_find_header(&parsed_resp, NWEP_HDR_TRANSCRIPT_SIG);
      if (sig_hdr != NULL) {
        printf("  Signature header len: %zu\n", sig_hdr->value_len);
        uint8_t decoded_sig[64];
        size_t sig_len = nwep_base64_decode(decoded_sig, 64, (const char *)sig_hdr->value);
        printf("  Decoded sig len: %zu (expected 64)\n", sig_len);
      }
    }
  }
  TEST_ASSERT(rv == 0, "Failed to parse CONNECT response");
  TEST_ASSERT(client_hs.state.client == NWEP_CLIENT_STATE_SEND_AUTHENTICATE,
              "Client state not SEND_AUTHENTICATE");

  printf("  Client state: %s\n", nwep_client_state_str(client_hs.state.client));

  /* Verify client received server's pubkey */
  TEST_ASSERT(memcmp(client_hs.peer_pubkey, server_keypair.pubkey, 32) == 0,
              "Client didn't receive correct server pubkey");

  /* Clean up */
  nwep_handshake_free(&client_hs);
  nwep_handshake_free(&server_hs);
  nwep_keypair_clear(&client_keypair);
  nwep_keypair_clear(&server_keypair);

  TEST_PASS();
}

/*
 * Test: Full CONNECT/AUTHENTICATE handshake
 */
static int test_full_handshake(void) {
  nwep_keypair client_keypair, server_keypair;
  nwep_handshake client_hs, server_hs;
  nwep_nodeid expected_server_nodeid;
  nwep_msg msg;
  nwep_header headers[16];
  uint8_t header_buf[1024];
  uint8_t wire_buf[2048];
  size_t wire_len;
  int rv;

  printf("Test: Full CONNECT/AUTHENTICATE handshake\n");

  /* Generate keypairs */
  rv = nwep_keypair_generate(&client_keypair);
  TEST_ASSERT(rv == 0, "Failed to generate client keypair");

  rv = nwep_keypair_generate(&server_keypair);
  TEST_ASSERT(rv == 0, "Failed to generate server keypair");

  /* Get server's expected NodeID */
  rv = nwep_nodeid_from_keypair(&expected_server_nodeid, &server_keypair);
  TEST_ASSERT(rv == 0, "Failed to compute server NodeID");

  /* Initialize handshakes */
  rv = nwep_handshake_client_init(&client_hs, &client_keypair, &expected_server_nodeid);
  TEST_ASSERT(rv == 0, "Failed to init client handshake");

  rv = nwep_handshake_server_init(&server_hs, &server_keypair);
  TEST_ASSERT(rv == 0, "Failed to init server handshake");

  printf("  Step 1: Client -> Server: CONNECT request\n");

  /* 1. Client builds CONNECT request */
  rv = nwep_connect_request_build(&msg, headers, 16, header_buf, sizeof(header_buf), &client_hs);
  TEST_ASSERT(rv == 0, "Failed to build CONNECT request");

  wire_len = nwep_msg_encode(wire_buf, sizeof(wire_buf), &msg);
  TEST_ASSERT(wire_len > 0, "Failed to encode CONNECT request");

  /* Server parses CONNECT request */
  nwep_header parse_headers[16];
  nwep_msg parsed_msg;
  rv = nwep_msg_decode(&parsed_msg, wire_buf, wire_len, parse_headers, 16);
  TEST_ASSERT(rv == 0, "Failed to decode CONNECT request");

  rv = nwep_connect_request_parse(&server_hs, &parsed_msg);
  TEST_ASSERT(rv == 0, "Failed to parse CONNECT request");

  printf("    Server state: %s\n", nwep_server_state_str(server_hs.state.server));

  printf("  Step 2: Server -> Client: CONNECT response\n");

  /* 2. Server builds CONNECT response */
  memset(headers, 0, sizeof(headers));
  memset(header_buf, 0, sizeof(header_buf));
  rv = nwep_connect_response_build(&msg, headers, 16, header_buf, sizeof(header_buf), &server_hs);
  TEST_ASSERT(rv == 0, "Failed to build CONNECT response");

  wire_len = nwep_msg_encode(wire_buf, sizeof(wire_buf), &msg);
  TEST_ASSERT(wire_len > 0, "Failed to encode CONNECT response");

  /* Client parses CONNECT response */
  rv = nwep_msg_decode(&parsed_msg, wire_buf, wire_len, parse_headers, 16);
  TEST_ASSERT(rv == 0, "Failed to decode CONNECT response");

  printf("    Server transcript after build: %zu bytes\n", server_hs.transcript_len);

  rv = nwep_connect_response_parse(&client_hs, &parsed_msg);
  if (rv != 0) {
    printf("    CONNECT response parse error: %s (%d)\n", nwep_strerror(rv), rv);
    printf("    Client transcript after parse: %zu bytes\n", client_hs.transcript_len);
    /* Full comparison */
    if (server_hs.transcript_len == client_hs.transcript_len) {
      int match = 1;
      for (size_t i = 0; i < server_hs.transcript_len; i++) {
        if (server_hs.transcript[i] != client_hs.transcript[i]) {
          printf("    Transcripts differ at byte %zu\n", i);
          match = 0;
          break;
        }
      }
      if (match) {
        printf("    Transcripts are IDENTICAL\n");
        printf("    Server pubkey: %02x%02x...  Client peer_pubkey: %02x%02x...\n",
               server_keypair.pubkey[0], server_keypair.pubkey[1],
               client_hs.peer_pubkey[0], client_hs.peer_pubkey[1]);
      }
    } else {
      printf("    Transcript lengths differ: server=%zu client=%zu\n",
             server_hs.transcript_len, client_hs.transcript_len);
    }
  }
  TEST_ASSERT(rv == 0, "Failed to parse CONNECT response");

  printf("    Client state: %s\n", nwep_client_state_str(client_hs.state.client));

  printf("  Step 3: Client -> Server: AUTHENTICATE request\n");

  /* 3. Client builds AUTHENTICATE request */
  memset(headers, 0, sizeof(headers));
  memset(header_buf, 0, sizeof(header_buf));
  rv = nwep_auth_request_build(&msg, headers, 16, header_buf, sizeof(header_buf), &client_hs);
  TEST_ASSERT(rv == 0, "Failed to build AUTHENTICATE request");

  wire_len = nwep_msg_encode(wire_buf, sizeof(wire_buf), &msg);
  TEST_ASSERT(wire_len > 0, "Failed to encode AUTHENTICATE request");

  /* Server parses AUTHENTICATE request */
  rv = nwep_msg_decode(&parsed_msg, wire_buf, wire_len, parse_headers, 16);
  TEST_ASSERT(rv == 0, "Failed to decode AUTHENTICATE request");

  printf("    Server transcript before auth parse: %zu bytes\n", server_hs.transcript_len);
  printf("    Client transcript: %zu bytes\n", client_hs.transcript_len);

  rv = nwep_auth_request_parse(&server_hs, &parsed_msg);
  if (rv != 0) {
    printf("    AUTHENTICATE request parse error: %s (%d)\n", nwep_strerror(rv), rv);
    /* Check transcripts match */
    if (server_hs.transcript_len == client_hs.transcript_len) {
      int match = 1;
      for (size_t i = 0; i < server_hs.transcript_len; i++) {
        if (server_hs.transcript[i] != client_hs.transcript[i]) {
          printf("    Transcripts differ at byte %zu\n", i);
          match = 0;
          break;
        }
      }
      if (match) {
        printf("    Transcripts IDENTICAL\n");
      }
    } else {
      printf("    Transcript lengths differ: server=%zu client=%zu\n",
             server_hs.transcript_len, client_hs.transcript_len);
    }
    /* Check pubkeys */
    printf("    Client local pubkey: %02x%02x...  Server peer_pubkey: %02x%02x...\n",
           client_keypair.pubkey[0], client_keypair.pubkey[1],
           server_hs.peer_pubkey[0], server_hs.peer_pubkey[1]);
    int pk_match = memcmp(client_keypair.pubkey, server_hs.peer_pubkey, 32) == 0;
    printf("    Pubkeys match: %s\n", pk_match ? "YES" : "NO");
  }
  TEST_ASSERT(rv == 0, "Failed to parse AUTHENTICATE request");

  printf("    Server state: %s\n", nwep_server_state_str(server_hs.state.server));

  printf("  Step 4: Server -> Client: AUTHENTICATE response\n");

  /* 4. Server builds AUTHENTICATE response */
  memset(headers, 0, sizeof(headers));
  rv = nwep_auth_response_build(&msg, headers, 16, &server_hs);
  TEST_ASSERT(rv == 0, "Failed to build AUTHENTICATE response");

  wire_len = nwep_msg_encode(wire_buf, sizeof(wire_buf), &msg);
  TEST_ASSERT(wire_len > 0, "Failed to encode AUTHENTICATE response");

  /* Client parses AUTHENTICATE response */
  rv = nwep_msg_decode(&parsed_msg, wire_buf, wire_len, parse_headers, 16);
  TEST_ASSERT(rv == 0, "Failed to decode AUTHENTICATE response");

  rv = nwep_auth_response_parse(&client_hs, &parsed_msg);
  TEST_ASSERT(rv == 0, "Failed to parse AUTHENTICATE response");

  printf("    Client state: %s\n", nwep_client_state_str(client_hs.state.client));

  /* Verify both sides are connected */
  TEST_ASSERT(client_hs.state.client == NWEP_CLIENT_STATE_CONNECTED,
              "Client not in CONNECTED state");
  TEST_ASSERT(server_hs.state.server == NWEP_SERVER_STATE_CONNECTED,
              "Server not in CONNECTED state");

  printf("  Handshake complete!\n");

  /* Clean up */
  nwep_handshake_free(&client_hs);
  nwep_handshake_free(&server_hs);
  nwep_keypair_clear(&client_keypair);
  nwep_keypair_clear(&server_keypair);

  TEST_PASS();
}

/*
 * Test: Triple-layer verification
 */
static int test_triple_layer_verification(void) {
  nwep_keypair client_keypair, server_keypair;
  nwep_handshake client_hs;
  nwep_nodeid expected_server_nodeid;
  uint8_t challenge_sig[64];
  int rv;

  printf("Test: Triple-layer verification\n");

  /* Generate keypairs */
  rv = nwep_keypair_generate(&client_keypair);
  TEST_ASSERT(rv == 0, "Failed to generate client keypair");

  rv = nwep_keypair_generate(&server_keypair);
  TEST_ASSERT(rv == 0, "Failed to generate server keypair");

  /* Get server's expected NodeID */
  rv = nwep_nodeid_from_keypair(&expected_server_nodeid, &server_keypair);
  TEST_ASSERT(rv == 0, "Failed to compute server NodeID");

  /* Initialize client handshake */
  rv = nwep_handshake_client_init(&client_hs, &client_keypair, &expected_server_nodeid);
  TEST_ASSERT(rv == 0, "Failed to init client handshake");

  /* Simulate receiving server's pubkey (as if from TLS certificate) */
  memcpy(client_hs.peer_pubkey, server_keypair.pubkey, 32);

  /* Test Layer 1: TLS pubkey matches */
  printf("  Layer 1: TLS pubkey verification\n");
  rv = nwep_verify_layer1(&client_hs, server_keypair.pubkey);
  TEST_ASSERT(rv == 0, "Layer 1 verification failed");
  printf("    OK\n");

  /* Test Layer 2: NodeID derivation */
  printf("  Layer 2: NodeID derivation verification\n");
  rv = nwep_verify_layer2(&client_hs);
  TEST_ASSERT(rv == 0, "Layer 2 verification failed");
  printf("    OK\n");

  /* Test Layer 3: Challenge signature */
  printf("  Layer 3: Challenge signature verification\n");
  rv = nwep_challenge_sign(challenge_sig, client_hs.local_challenge, &server_keypair);
  TEST_ASSERT(rv == 0, "Failed to sign challenge");

  rv = nwep_verify_layer3(&client_hs, challenge_sig);
  TEST_ASSERT(rv == 0, "Layer 3 verification failed");
  printf("    OK\n");

  /* Test all layers at once */
  printf("  All layers combined\n");
  rv = nwep_verify_all_layers(&client_hs, server_keypair.pubkey, challenge_sig);
  TEST_ASSERT(rv == 0, "Combined verification failed");
  printf("    OK\n");

  /* Clean up */
  nwep_handshake_free(&client_hs);
  nwep_keypair_clear(&client_keypair);
  nwep_keypair_clear(&server_keypair);

  TEST_PASS();
}

/*
 * Test: MITM detection (NodeID mismatch)
 */
static int test_mitm_detection(void) {
  nwep_keypair client_keypair, server_keypair, attacker_keypair;
  nwep_handshake client_hs;
  nwep_nodeid expected_server_nodeid;
  int rv;

  printf("Test: MITM detection (NodeID mismatch)\n");

  /* Generate keypairs */
  rv = nwep_keypair_generate(&client_keypair);
  TEST_ASSERT(rv == 0, "Failed to generate client keypair");

  rv = nwep_keypair_generate(&server_keypair);
  TEST_ASSERT(rv == 0, "Failed to generate server keypair");

  rv = nwep_keypair_generate(&attacker_keypair);
  TEST_ASSERT(rv == 0, "Failed to generate attacker keypair");

  /* Get server's expected NodeID */
  rv = nwep_nodeid_from_keypair(&expected_server_nodeid, &server_keypair);
  TEST_ASSERT(rv == 0, "Failed to compute server NodeID");

  /* Initialize client handshake expecting real server */
  rv = nwep_handshake_client_init(&client_hs, &client_keypair, &expected_server_nodeid);
  TEST_ASSERT(rv == 0, "Failed to init client handshake");

  /* Simulate MITM: attacker provides their pubkey instead of real server's */
  memcpy(client_hs.peer_pubkey, attacker_keypair.pubkey, 32);

  printf("  Testing Layer 2 with MITM attacker pubkey...\n");

  /* Layer 2 should fail because attacker's NodeID != expected server's NodeID */
  rv = nwep_verify_layer2(&client_hs);
  TEST_ASSERT(rv == NWEP_ERR_CRYPTO_NODEID_MISMATCH, "Layer 2 should detect NodeID mismatch");
  printf("    Correctly detected MITM! (error: %s)\n", nwep_strerror(rv));

  /* Also test Layer 1 mismatch (TLS pubkey != expected) */
  printf("  Testing Layer 1 with wrong TLS pubkey...\n");
  rv = nwep_verify_layer1(&client_hs, server_keypair.pubkey);
  TEST_ASSERT(rv == NWEP_ERR_CRYPTO_PUBKEY_MISMATCH, "Layer 1 should detect pubkey mismatch");
  printf("    Correctly detected pubkey mismatch! (error: %s)\n", nwep_strerror(rv));

  /* Clean up */
  nwep_handshake_free(&client_hs);
  nwep_keypair_clear(&client_keypair);
  nwep_keypair_clear(&server_keypair);
  nwep_keypair_clear(&attacker_keypair);

  TEST_PASS();
}

/*
 * Test: Security-critical error detection (Phase 10)
 */
static int test_security_errors(void) {
  printf("Test: Security-critical error detection (Phase 10)\n");

  /* Test fatal error detection */
  printf("  Testing fatal error identification...\n");

  /* These should be fatal (terminate connection immediately) */
  TEST_ASSERT(nwep_err_is_fatal(NWEP_ERR_CRYPTO_NODEID_MISMATCH) == 1,
              "NODEID_MISMATCH should be fatal");
  TEST_ASSERT(nwep_err_is_fatal(NWEP_ERR_CRYPTO_PUBKEY_MISMATCH) == 1,
              "PUBKEY_MISMATCH should be fatal");
  TEST_ASSERT(nwep_err_is_fatal(NWEP_ERR_CRYPTO_CHALLENGE_FAILED) == 1,
              "CHALLENGE_FAILED should be fatal");
  TEST_ASSERT(nwep_err_is_fatal(NWEP_ERR_CRYPTO_SERVER_SIG_INVALID) == 1,
              "SERVER_SIG_INVALID should be fatal");
  TEST_ASSERT(nwep_err_is_fatal(NWEP_ERR_CRYPTO_CLIENT_SIG_INVALID) == 1,
              "CLIENT_SIG_INVALID should be fatal");
  TEST_ASSERT(nwep_err_is_fatal(NWEP_ERR_IDENTITY_REVOKED) == 1,
              "IDENTITY_REVOKED should be fatal");
  TEST_ASSERT(nwep_err_is_fatal(NWEP_ERR_PROTO_VERSION_MISMATCH) == 1,
              "VERSION_MISMATCH should be fatal");
  printf("    All security-critical errors correctly marked fatal\n");

  /* These should NOT be fatal */
  printf("  Testing non-fatal error identification...\n");
  TEST_ASSERT(nwep_err_is_fatal(NWEP_ERR_NETWORK_TIMEOUT) == 0,
              "NETWORK_TIMEOUT should not be fatal");
  TEST_ASSERT(nwep_err_is_fatal(NWEP_ERR_PROTO_INVALID_HEADER) == 0,
              "INVALID_HEADER should not be fatal");
  TEST_ASSERT(nwep_err_is_fatal(NWEP_ERR_INTERNAL_NOMEM) == 0,
              "NOMEM should not be fatal");
  TEST_ASSERT(nwep_err_is_fatal(0) == 0, "Success (0) should not be fatal");
  printf("    Non-fatal errors correctly identified\n");

  /* Test error category detection */
  printf("  Testing error category detection...\n");
  TEST_ASSERT(nwep_err_category(NWEP_ERR_CRYPTO_NODEID_MISMATCH) == NWEP_ERR_CAT_CRYPTO,
              "NODEID_MISMATCH should be CRYPTO category");
  TEST_ASSERT(nwep_err_category(NWEP_ERR_NETWORK_TIMEOUT) == NWEP_ERR_CAT_NETWORK,
              "TIMEOUT should be NETWORK category");
  TEST_ASSERT(nwep_err_category(NWEP_ERR_PROTO_VERSION_MISMATCH) == NWEP_ERR_CAT_PROTOCOL,
              "VERSION_MISMATCH should be PROTOCOL category");
  printf("    Error categories correctly identified\n");

  TEST_PASS();
}

/*
 * Test: 0-RTT method safety (Phase 10)
 */
static int test_0rtt_safety(void) {
  printf("Test: 0-RTT method safety (Phase 10)\n");

  /* Only READ should be allowed in 0-RTT */
  printf("  Testing 0-RTT allowed methods...\n");
  TEST_ASSERT(nwep_method_allowed_0rtt(NWEP_METHOD_READ) == 1,
              "READ should be allowed in 0-RTT");
  printf("    READ allowed in 0-RTT: OK\n");

  /* These should be rejected in 0-RTT */
  printf("  Testing 0-RTT rejected methods...\n");
  TEST_ASSERT(nwep_method_allowed_0rtt(NWEP_METHOD_WRITE) == 0,
              "WRITE should be rejected in 0-RTT");
  TEST_ASSERT(nwep_method_allowed_0rtt(NWEP_METHOD_UPDATE) == 0,
              "UPDATE should be rejected in 0-RTT");
  TEST_ASSERT(nwep_method_allowed_0rtt(NWEP_METHOD_DELETE) == 0,
              "DELETE should be rejected in 0-RTT");
  TEST_ASSERT(nwep_method_allowed_0rtt(NWEP_METHOD_CONNECT) == 0,
              "CONNECT should be rejected in 0-RTT");
  TEST_ASSERT(nwep_method_allowed_0rtt(NWEP_METHOD_AUTHENTICATE) == 0,
              "AUTHENTICATE should be rejected in 0-RTT");
  printf("    Non-idempotent methods rejected in 0-RTT: OK\n");

  /* Test idempotent method identification */
  printf("  Testing idempotent method identification...\n");
  TEST_ASSERT(nwep_method_is_idempotent(NWEP_METHOD_READ) == 1,
              "READ should be idempotent");
  TEST_ASSERT(nwep_method_is_idempotent(NWEP_METHOD_DELETE) == 1,
              "DELETE should be idempotent");
  TEST_ASSERT(nwep_method_is_idempotent(NWEP_METHOD_WRITE) == 0,
              "WRITE should not be idempotent");
  TEST_ASSERT(nwep_method_is_idempotent(NWEP_METHOD_UPDATE) == 0,
              "UPDATE should not be idempotent");
  printf("    Idempotent methods correctly identified: OK\n");

  TEST_PASS();
}

/*
 * Test: Transcript signing and verification
 */
static int test_transcript_signing(void) {
  nwep_keypair keypair;
  nwep_handshake hs;
  uint8_t signature[64];
  int rv;

  printf("Test: Transcript signing and verification\n");

  /* Generate keypair */
  rv = nwep_keypair_generate(&keypair);
  TEST_ASSERT(rv == 0, "Failed to generate keypair");

  /* Initialize handshake */
  rv = nwep_handshake_server_init(&hs, &keypair);
  TEST_ASSERT(rv == 0, "Failed to init handshake");

  /* Initialize transcript */
  rv = nwep_transcript_init(&hs);
  TEST_ASSERT(rv == 0, "Failed to init transcript");

  /* Add some content to transcript */
  rv = nwep_transcript_add_connect_request(&hs);
  TEST_ASSERT(rv == 0, "Failed to add CONNECT request to transcript");

  printf("  Transcript size: %zu bytes\n", hs.transcript_len);
  TEST_ASSERT(hs.transcript_len > 0, "Transcript should not be empty");

  /* Sign transcript */
  rv = nwep_transcript_sign(signature, &hs);
  TEST_ASSERT(rv == 0, "Failed to sign transcript");

  printf("  Transcript signed successfully\n");

  /* Set peer_pubkey to our own for self-verification test */
  memcpy(hs.peer_pubkey, keypair.pubkey, 32);

  /* Verify signature */
  rv = nwep_transcript_verify(&hs, signature);
  TEST_ASSERT(rv == 0, "Transcript signature verification failed");

  printf("  Transcript signature verified\n");

  /* Tamper with transcript and verify it fails */
  hs.transcript[0] ^= 0xFF;
  rv = nwep_transcript_verify(&hs, signature);
  TEST_ASSERT(rv != 0, "Tampered transcript should fail verification");
  printf("  Tampered transcript correctly rejected\n");

  /* Clean up */
  nwep_handshake_free(&hs);
  nwep_keypair_clear(&keypair);

  TEST_PASS();
}

int main(void) {
  int failed = 0;

  setbuf(stdout, NULL);

  printf("=== nwep WEB/1 handshake tests ===\n\n");

  /* Initialize nwep */
  printf("Initializing nwep...\n");
  nwep_init();
  printf("nwep initialized\n\n");

  failed += test_connect_request();
  printf("\n");

  failed += test_connect_response();
  printf("\n");

  failed += test_full_handshake();
  printf("\n");

  failed += test_triple_layer_verification();
  printf("\n");

  failed += test_mitm_detection();
  printf("\n");

  failed += test_transcript_signing();
  printf("\n");

  failed += test_security_errors();
  printf("\n");

  failed += test_0rtt_safety();
  printf("\n");

  printf("=== Results: %d test(s) failed ===\n", failed);

  return failed;
}
