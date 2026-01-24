/*
 * nwep test harness implementation
 */
#ifndef _WIN32
#  define _GNU_SOURCE
#endif

#include "test_harness.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

/*
 * Get current timestamp in nanoseconds
 */
uint64_t test_timestamp(void) {
#if defined(_WIN32)
  /* Windows: use QueryPerformanceCounter for high resolution */
  static LARGE_INTEGER frequency = {0};
  static int initialized = 0;
  LARGE_INTEGER counter;

  if (!initialized) {
    QueryPerformanceFrequency(&frequency);
    initialized = 1;
  }

  QueryPerformanceCounter(&counter);
  return (uint64_t)(counter.QuadPart * 1000000000ULL / frequency.QuadPart);
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

/* Forward declarations */
static void write_packets(test_endpoint *ep);

/*
 * Allocate buffer for UV
 */
static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  test_endpoint *ep = (test_endpoint *)handle->data;
  (void)suggested_size;
  buf->base = (char *)ep->pkt_buf;
  buf->len = TEST_MAX_PKTLEN;
}

/*
 * Handle received UDP packet
 */
static void recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                    const struct sockaddr *addr, unsigned flags) {
  test_endpoint *ep = (test_endpoint *)handle->data;
  nwep_path path;
  int rv;
  static int recv_count = 0;

  (void)buf;
  (void)flags;

  if (nread < 0) {
    ep->error = 1;
    return;
  }

  if (nread == 0 || addr == NULL) {
    return;
  }

  (void)recv_count;

  /* Build path */
  memset(&path, 0, sizeof(path));
  memcpy(&path.remote_addr, addr,
         addr->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6)
                                     : sizeof(struct sockaddr_in));
  path.remote_addrlen =
      addr->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6)
                                  : sizeof(struct sockaddr_in);
  memcpy(&path.local_addr, &ep->local_addr, ep->local_addrlen);
  path.local_addrlen = ep->local_addrlen;

  /* Process packet */
  if (ep->is_server) {
    rv = nwep_server_read(ep->server, &path, ep->pkt_buf, (size_t)nread,
                          test_timestamp());
  } else {
    rv = nwep_client_read(ep->client, &path, ep->pkt_buf, (size_t)nread,
                          test_timestamp());
  }

  if (rv != 0) {
    ep->error = 1;
  }

  /* After receiving data, try to write any pending responses immediately */
  write_packets(ep);
}

/*
 * Write outgoing packets
 */
static void write_packets(test_endpoint *ep) {
  nwep_path path;
  nwep_ssize nwrite;
  uv_buf_t buf;
  int rv;

  memset(&path, 0, sizeof(path));

  for (;;) {
    if (ep->is_server) {
      nwrite = nwep_server_write(ep->server, &path, ep->pkt_buf,
                                 TEST_MAX_PKTLEN, test_timestamp());
    } else {
      nwrite = nwep_client_write(ep->client, &path, ep->pkt_buf,
                                 TEST_MAX_PKTLEN, test_timestamp());
    }

    if (nwrite <= 0) {
      break;
    }

    buf.base = (char *)ep->pkt_buf;
    buf.len = (size_t)nwrite;

    /* Send packet */
    uv_udp_send_t *req = (uv_udp_send_t *)malloc(sizeof(uv_udp_send_t));
    if (req == NULL) {
      ep->error = 1;
      return;
    }

    rv = uv_udp_send(req, &ep->udp, &buf, 1,
                     (const struct sockaddr *)&path.remote_addr, NULL);
    if (rv < 0) {
      free(req);
      ep->error = 1;
      return;
    }
  }
}

/*
 * Timer callback for writing packets and handling expiry
 */
static void timer_cb(uv_timer_t *handle) {
  test_endpoint *ep = (test_endpoint *)handle->data;
  uint64_t now = test_timestamp();
  uint64_t expiry;
  int rv;

  /* Handle expiry */
  if (ep->is_server) {
    rv = nwep_server_handle_expiry(ep->server, now);
    expiry = nwep_server_get_expiry(ep->server);
  } else {
    rv = nwep_client_handle_expiry(ep->client, now);
    expiry = nwep_client_get_expiry(ep->client);
  }

  if (rv != 0) {
    ep->error = 1;
  }

  /* Write any pending packets */
  write_packets(ep);

  /* Schedule next timer */
  if (expiry != UINT64_MAX) {
    uint64_t delay_ns = expiry > now ? expiry - now : 0;
    uint64_t delay_ms = delay_ns / 1000000;
    if (delay_ms == 0) {
      delay_ms = 1;
    }
    uv_timer_start(&ep->timer, timer_cb, delay_ms, 0);
  } else {
    /* Default: check again in 50ms */
    uv_timer_start(&ep->timer, timer_cb, 50, 0);
  }
}

/*
 * nwep callback: connection established
 */
static int on_connect_cb(nwep_conn *conn, const nwep_identity *peer,
                         void *user_data) {
  test_endpoint *ep = (test_endpoint *)user_data;
  (void)conn;
  (void)peer;
  printf("  [%s] Connected!\n", ep->is_server ? "server" : "client");
  fflush(stdout);
  ep->connected = 1;
  return 0;
}

/*
 * nwep callback: connection closed
 */
static void on_disconnect_cb(nwep_conn *conn, int error, void *user_data) {
  test_endpoint *ep = (test_endpoint *)user_data;
  (void)conn;
  printf("  [%s] Disconnected (error=%d)\n", ep->is_server ? "server" : "client",
         error);
}

/*
 * nwep callback: request received (server)
 */
static int on_request_cb(nwep_conn *conn, nwep_stream *stream,
                         const nwep_request *req, void *user_data) {
  test_endpoint *ep = (test_endpoint *)user_data;
  nwep_response resp;
  nwep_header headers[1];

  (void)conn;

  printf("  [server] Request: %s %s\n", req->method, req->path);
  ep->request_received = 1;

  /* Send response */
  memset(&resp, 0, sizeof(resp));
  resp.status = NWEP_STATUS_OK;
  resp.headers = headers;
  resp.header_count = 0;

  nwep_stream_respond(stream, &resp);
  nwep_stream_end(stream);
  return 0;
}

/*
 * nwep callback: response received (client)
 */
static int on_response_cb(nwep_conn *conn, nwep_stream *stream,
                          const nwep_response *resp, void *user_data) {
  test_endpoint *ep = (test_endpoint *)user_data;
  (void)conn;
  (void)stream;

  printf("  [client] Response: %s\n", resp->status);
  ep->response_received = 1;
  return 0;
}

/*
 * nwep callback: random data
 */
static int rand_cb(uint8_t *data, size_t len, void *user_data) {
  (void)user_data;
  /* Simple random - use /dev/urandom in production */
  for (size_t i = 0; i < len; i++) {
    data[i] = (uint8_t)rand();
  }
  return 0;
}

/*
 * Initialize test endpoint as server
 */
int test_endpoint_init_server(test_endpoint *ep, uv_loop_t *loop,
                              const struct sockaddr *addr) {
  nwep_settings settings;
  nwep_callbacks callbacks;
  int rv;

  memset(ep, 0, sizeof(*ep));
  ep->loop = loop;
  ep->is_server = 1;

  /* Generate keypair */
  rv = nwep_keypair_generate(&ep->keypair);
  if (rv != 0) {
    fprintf(stderr, "Failed to generate keypair: %s\n", nwep_strerror(rv));
    return rv;
  }

  /* Set up settings */
  nwep_settings_default(&settings);

  /* Set up callbacks */
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.on_connect = on_connect_cb;
  callbacks.on_disconnect = on_disconnect_cb;
  callbacks.on_request = on_request_cb;
  callbacks.rand = rand_cb;

  /* Create server */
  rv = nwep_server_new(&ep->server, &settings, &callbacks, &ep->keypair, ep);
  if (rv != 0) {
    fprintf(stderr, "Failed to create server: %s\n", nwep_strerror(rv));
    return rv;
  }

  /* Initialize UDP socket */
  rv = uv_udp_init(loop, &ep->udp);
  if (rv < 0) {
    fprintf(stderr, "Failed to init UDP: %s\n", uv_strerror(rv));
    nwep_server_free(ep->server);
    return -1;
  }
  ep->udp.data = ep;

  /* Bind to address */
  rv = uv_udp_bind(&ep->udp, addr, 0);
  if (rv < 0) {
    fprintf(stderr, "Failed to bind UDP: %s\n", uv_strerror(rv));
    uv_close((uv_handle_t *)&ep->udp, NULL);
    nwep_server_free(ep->server);
    return -1;
  }

  /* Get actual bound address */
  int namelen = sizeof(ep->local_addr);
  rv = uv_udp_getsockname(&ep->udp, (struct sockaddr *)&ep->local_addr, &namelen);
  if (rv < 0) {
    fprintf(stderr, "Failed to get socket name: %s\n", uv_strerror(rv));
  }
  ep->local_addrlen = (socklen_t)namelen;

  /* Start receiving */
  rv = uv_udp_recv_start(&ep->udp, alloc_cb, recv_cb);
  if (rv < 0) {
    fprintf(stderr, "Failed to start recv: %s\n", uv_strerror(rv));
    uv_close((uv_handle_t *)&ep->udp, NULL);
    nwep_server_free(ep->server);
    return -1;
  }

  /* Initialize timer */
  uv_timer_init(loop, &ep->timer);
  ep->timer.data = ep;
  uv_timer_start(&ep->timer, timer_cb, 50, 0);

  return 0;
}

/*
 * Initialize test endpoint as client
 */
int test_endpoint_init_client(test_endpoint *ep, uv_loop_t *loop,
                              const struct sockaddr *local_addr) {
  nwep_settings settings;
  nwep_callbacks callbacks;
  int rv;

  memset(ep, 0, sizeof(*ep));
  ep->loop = loop;
  ep->is_server = 0;

  /* Generate keypair */
  rv = nwep_keypair_generate(&ep->keypair);
  if (rv != 0) {
    fprintf(stderr, "Failed to generate keypair: %s\n", nwep_strerror(rv));
    return rv;
  }

  /* Set up settings */
  nwep_settings_default(&settings);

  /* Set up callbacks */
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.on_connect = on_connect_cb;
  callbacks.on_disconnect = on_disconnect_cb;
  callbacks.on_response = on_response_cb;
  callbacks.rand = rand_cb;

  /* Create client */
  rv = nwep_client_new(&ep->client, &settings, &callbacks, &ep->keypair, ep);
  if (rv != 0) {
    fprintf(stderr, "Failed to create client: %s\n", nwep_strerror(rv));
    return rv;
  }

  /* Initialize UDP socket */
  rv = uv_udp_init(loop, &ep->udp);
  if (rv < 0) {
    fprintf(stderr, "Failed to init UDP: %s\n", uv_strerror(rv));
    nwep_client_free(ep->client);
    return -1;
  }
  ep->udp.data = ep;

  /* Bind to local address (or any) */
  if (local_addr != NULL) {
    rv = uv_udp_bind(&ep->udp, local_addr, 0);
  } else {
    struct sockaddr_in6 any;
    memset(&any, 0, sizeof(any));
    any.sin6_family = AF_INET6;
    rv = uv_udp_bind(&ep->udp, (struct sockaddr *)&any, 0);
  }
  if (rv < 0) {
    fprintf(stderr, "Failed to bind UDP: %s\n", uv_strerror(rv));
    uv_close((uv_handle_t *)&ep->udp, NULL);
    nwep_client_free(ep->client);
    return -1;
  }

  /* Get actual bound address */
  int namelen = sizeof(ep->local_addr);
  rv = uv_udp_getsockname(&ep->udp, (struct sockaddr *)&ep->local_addr, &namelen);
  if (rv < 0) {
    fprintf(stderr, "Failed to get socket name: %s\n", uv_strerror(rv));
  }
  ep->local_addrlen = (socklen_t)namelen;

  /* Start receiving */
  rv = uv_udp_recv_start(&ep->udp, alloc_cb, recv_cb);
  if (rv < 0) {
    fprintf(stderr, "Failed to start recv: %s\n", uv_strerror(rv));
    uv_close((uv_handle_t *)&ep->udp, NULL);
    nwep_client_free(ep->client);
    return -1;
  }

  /* Initialize timer */
  uv_timer_init(loop, &ep->timer);
  ep->timer.data = ep;
  uv_timer_start(&ep->timer, timer_cb, 50, 0);

  return 0;
}

/*
 * Connect client to server
 */
int test_endpoint_connect(test_endpoint *client, const nwep_url *url) {
  return nwep_client_connect(client->client, url,
                             (struct sockaddr *)&client->local_addr,
                             client->local_addrlen, test_timestamp());
}

/*
 * Timeout callback
 */
static void timeout_cb(uv_timer_t *handle) {
  int *timed_out = (int *)handle->data;
  *timed_out = 1;
}

/*
 * Close callback that does nothing
 */
static void empty_close_cb(uv_handle_t *handle) {
  (void)handle;
}

/*
 * Run the event loop until test completes or timeout
 */
int test_run(uv_loop_t *loop, int timeout_ms) {
  uv_timer_t timeout;
  int timed_out = 0;

  uv_timer_init(loop, &timeout);
  timeout.data = &timed_out;
  uv_timer_start(&timeout, timeout_cb, (uint64_t)timeout_ms, 0);

  while (!timed_out) {
    uv_run(loop, UV_RUN_ONCE);
  }

  /* Stop and close just this timeout timer */
  uv_timer_stop(&timeout);
  uv_close((uv_handle_t *)&timeout, empty_close_cb);
  uv_run(loop, UV_RUN_NOWAIT); /* Process the close */

  return 0;
}

/*
 * Clean up test endpoint
 */
void test_endpoint_cleanup(test_endpoint *ep) {
  if (ep->is_server && ep->server != NULL) {
    nwep_server_close(ep->server);
    nwep_server_free(ep->server);
    ep->server = NULL;
  } else if (!ep->is_server && ep->client != NULL) {
    nwep_client_close(ep->client);
    nwep_client_free(ep->client);
    ep->client = NULL;
  }

  uv_timer_stop(&ep->timer);
  if (!uv_is_closing((uv_handle_t *)&ep->timer)) {
    uv_close((uv_handle_t *)&ep->timer, empty_close_cb);
  }

  uv_udp_recv_stop(&ep->udp);
  if (!uv_is_closing((uv_handle_t *)&ep->udp)) {
    uv_close((uv_handle_t *)&ep->udp, empty_close_cb);
  }

  /* Run loop a few times to process the close callbacks */
  for (int i = 0; i < 10; i++) {
    uv_run(ep->loop, UV_RUN_NOWAIT);
  }

  nwep_keypair_clear(&ep->keypair);
}
