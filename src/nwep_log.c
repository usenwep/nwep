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

/* Enable POSIX features for clock_gettime and snprintf */
#if !defined(_WIN32)
#  if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 200112L
#    undef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200112L
#  endif
#endif

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <nwep/nwep.h>

#include <stdarg.h>
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
 * Global logger configuration
 */
static struct {
  nwep_log_level min_level;
  nwep_log_callback callback;
  void *user_data;
  int json_format;
  int stderr_enabled;
} g_logger = {
    .min_level = NWEP_LOG_INFO,
    .callback = NULL,
    .user_data = NULL,
    .json_format = 0,
    .stderr_enabled = 1,
};

const char *nwep_log_level_str(nwep_log_level level) {
  switch (level) {
  case NWEP_LOG_TRACE:
    return "TRACE";
  case NWEP_LOG_DEBUG:
    return "DEBUG";
  case NWEP_LOG_INFO:
    return "INFO";
  case NWEP_LOG_WARN:
    return "WARN";
  case NWEP_LOG_ERROR:
    return "ERROR";
  default:
    return "UNKNOWN";
  }
}

void nwep_log_set_level(nwep_log_level level) { g_logger.min_level = level; }

nwep_log_level nwep_log_get_level(void) { return g_logger.min_level; }

void nwep_log_set_callback(nwep_log_callback callback, void *user_data) {
  g_logger.callback = callback;
  g_logger.user_data = user_data;
}

void nwep_log_set_json(int enabled) { g_logger.json_format = enabled; }

void nwep_log_set_stderr(int enabled) { g_logger.stderr_enabled = enabled; }

/*
 * Escape a string for JSON output
 */
static size_t json_escape(char *dest, size_t destlen, const char *src) {
  size_t i = 0;
  size_t j = 0;

  if (dest == NULL || src == NULL || destlen == 0) {
    return 0;
  }

  while (src[i] != '\0' && j < destlen - 1) {
    char c = src[i++];
    switch (c) {
    case '"':
      if (j + 2 < destlen) {
        dest[j++] = '\\';
        dest[j++] = '"';
      }
      break;
    case '\\':
      if (j + 2 < destlen) {
        dest[j++] = '\\';
        dest[j++] = '\\';
      }
      break;
    case '\n':
      if (j + 2 < destlen) {
        dest[j++] = '\\';
        dest[j++] = 'n';
      }
      break;
    case '\r':
      if (j + 2 < destlen) {
        dest[j++] = '\\';
        dest[j++] = 'r';
      }
      break;
    case '\t':
      if (j + 2 < destlen) {
        dest[j++] = '\\';
        dest[j++] = 't';
      }
      break;
    default:
      if ((unsigned char)c < 0x20) {
        /* Control character - skip or escape as \uXXXX */
        if (j + 6 < destlen) {
          j += snprintf(dest + j, destlen - j, "\\u%04x", (unsigned char)c);
        }
      } else {
        dest[j++] = c;
      }
      break;
    }
  }

  dest[j] = '\0';
  return j;
}

/*
 * Format trace ID as hex string
 */
static void format_trace_id(char *dest, size_t destlen,
                            const uint8_t trace_id[16]) {
  size_t i;

  if (dest == NULL || destlen < 33 || trace_id == NULL) {
    if (dest != NULL && destlen > 0) {
      dest[0] = '\0';
    }
    return;
  }

  for (i = 0; i < 16; i++) {
    snprintf(dest + i * 2, 3, "%02x", trace_id[i]);
  }
}

/*
 * Get current timestamp in nanoseconds since epoch
 */
static uint64_t get_timestamp_ns(void) {
#if defined(_WIN32)
  /* Windows: use QueryPerformanceCounter for high resolution */
  static LARGE_INTEGER frequency = {0};
  static LARGE_INTEGER start_counter = {0};
  static uint64_t start_time_ns = 0;
  static int initialized = 0;

  if (!initialized) {
    FILETIME ft;
    ULARGE_INTEGER uli;

    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start_counter);

    /* Get current time in 100-nanosecond intervals since Jan 1, 1601 */
    GetSystemTimeAsFileTime(&ft);
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    /* Convert to nanoseconds since Unix epoch (Jan 1, 1970) */
    /* 11644473600 seconds between 1601 and 1970 */
    start_time_ns = (uli.QuadPart - 116444736000000000ULL) * 100ULL;
    initialized = 1;
  }

  {
    LARGE_INTEGER counter;
    uint64_t elapsed_ns;

    QueryPerformanceCounter(&counter);
    elapsed_ns = (uint64_t)((counter.QuadPart - start_counter.QuadPart) *
                            1000000000ULL / frequency.QuadPart);
    return start_time_ns + elapsed_ns;
  }
#elif defined(HAVE_CLOCK_GETTIME) || defined(__linux__) || defined(__APPLE__)
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
  }
  /* Fallback to seconds precision */
  return (uint64_t)time(NULL) * 1000000000ULL;
#else
  /* Fallback to seconds precision */
  return (uint64_t)time(NULL) * 1000000000ULL;
#endif
}

/*
 * Get current timestamp in ISO 8601 format
 */
static void get_timestamp(char *dest, size_t destlen) {
  time_t now;
  struct tm tm_buf;
  struct tm *tm_info;

  if (dest == NULL || destlen < 25) {
    return;
  }

  time(&now);
#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
  /* MSVC and MinGW use reversed argument order: (tm*, time_t*) */
  gmtime_s(&tm_buf, &now);
  tm_info = &tm_buf;
#elif defined(__STDC_LIB_EXT1__) || defined(__STDC_SECURE_LIB__)
  /* C11 Annex K uses: (time_t*, tm*) */
  gmtime_s(&now, &tm_buf);
  tm_info = &tm_buf;
#else
  tm_info = gmtime(&now);
  if (tm_info != NULL) {
    tm_buf = *tm_info;
    tm_info = &tm_buf;
  }
#endif

  if (tm_info != NULL) {
    strftime(dest, destlen, "%Y-%m-%dT%H:%M:%SZ", tm_info);
  } else {
    dest[0] = '\0';
  }
}

void nwep_log_write(nwep_log_level level, const uint8_t *trace_id,
                    const char *component, const char *fmt, ...) {
  va_list args;
  char msg_buf[1024];
  char escaped_msg[2048];
  char escaped_component[256];
  char trace_id_hex[33];
  char timestamp[32];
  char json_buf[4096];
  FILE *out;

  /* Check log level */
  if (level < g_logger.min_level) {
    return;
  }

  /* Format the message */
  va_start(args, fmt);
  vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
  va_end(args);

  /* Use callback if set */
  if (g_logger.callback != NULL) {
    nwep_log_entry entry;
    entry.level = level;
    entry.timestamp_ns = get_timestamp_ns();
    if (trace_id != NULL) {
      memcpy(entry.trace_id, trace_id, 16);
    } else {
      memset(entry.trace_id, 0, 16);
    }
    entry.component = component;
    entry.message = msg_buf;

    g_logger.callback(&entry, g_logger.user_data);
    return;
  }

  /* Check if stderr output is enabled */
  if (!g_logger.stderr_enabled) {
    return;
  }

  out = stderr;

  /* Format trace ID */
  if (trace_id != NULL) {
    format_trace_id(trace_id_hex, sizeof(trace_id_hex), trace_id);
  } else {
    trace_id_hex[0] = '\0';
  }

  if (g_logger.json_format) {
    /* JSON output */
    get_timestamp(timestamp, sizeof(timestamp));
    json_escape(escaped_msg, sizeof(escaped_msg), msg_buf);
    json_escape(escaped_component, sizeof(escaped_component),
                component ? component : "nwep");

    if (trace_id != NULL) {
      snprintf(json_buf, sizeof(json_buf),
               "{\"timestamp\":\"%s\",\"level\":\"%s\",\"component\":\"%s\","
               "\"trace_id\":\"%s\",\"message\":\"%s\"}\n",
               timestamp, nwep_log_level_str(level), escaped_component,
               trace_id_hex, escaped_msg);
    } else {
      snprintf(json_buf, sizeof(json_buf),
               "{\"timestamp\":\"%s\",\"level\":\"%s\",\"component\":\"%s\","
               "\"message\":\"%s\"}\n",
               timestamp, nwep_log_level_str(level), escaped_component,
               escaped_msg);
    }

    fputs(json_buf, out);
  } else {
    /* Plain text output */
    get_timestamp(timestamp, sizeof(timestamp));

    if (trace_id != NULL) {
      fprintf(out, "[%s] [%s] [%s] [%s] %s\n", timestamp,
              nwep_log_level_str(level), component ? component : "nwep",
              trace_id_hex, msg_buf);
    } else {
      fprintf(out, "[%s] [%s] [%s] %s\n", timestamp, nwep_log_level_str(level),
              component ? component : "nwep", msg_buf);
    }
  }

  fflush(out);
}

void nwep_log_trace(const uint8_t *trace_id, const char *component,
                    const char *fmt, ...) {
  va_list args;
  char msg_buf[1024];

  va_start(args, fmt);
  vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
  va_end(args);

  nwep_log_write(NWEP_LOG_TRACE, trace_id, component, "%s", msg_buf);
}

void nwep_log_debug(const uint8_t *trace_id, const char *component,
                    const char *fmt, ...) {
  va_list args;
  char msg_buf[1024];

  va_start(args, fmt);
  vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
  va_end(args);

  nwep_log_write(NWEP_LOG_DEBUG, trace_id, component, "%s", msg_buf);
}

void nwep_log_info(const uint8_t *trace_id, const char *component,
                   const char *fmt, ...) {
  va_list args;
  char msg_buf[1024];

  va_start(args, fmt);
  vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
  va_end(args);

  nwep_log_write(NWEP_LOG_INFO, trace_id, component, "%s", msg_buf);
}

void nwep_log_warn(const uint8_t *trace_id, const char *component,
                   const char *fmt, ...) {
  va_list args;
  char msg_buf[1024];

  va_start(args, fmt);
  vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
  va_end(args);

  nwep_log_write(NWEP_LOG_WARN, trace_id, component, "%s", msg_buf);
}

void nwep_log_error(const uint8_t *trace_id, const char *component,
                    const char *fmt, ...) {
  va_list args;
  char msg_buf[1024];

  va_start(args, fmt);
  vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
  va_end(args);

  nwep_log_write(NWEP_LOG_ERROR, trace_id, component, "%s", msg_buf);
}

size_t nwep_log_format_json(char *dest, size_t destlen,
                            const nwep_log_entry *entry) {
  char escaped_msg[2048];
  char escaped_component[256];
  char trace_id_hex[33];
  char timestamp[32];
  int rv;

  if (dest == NULL || destlen == 0 || entry == NULL) {
    return 0;
  }

  get_timestamp(timestamp, sizeof(timestamp));
  json_escape(escaped_msg, sizeof(escaped_msg),
              entry->message ? entry->message : "");
  json_escape(escaped_component, sizeof(escaped_component),
              entry->component ? entry->component : "nwep");

  /* Check if trace_id is non-zero */
  int has_trace_id = 0;
  for (int i = 0; i < 16; i++) {
    if (entry->trace_id[i] != 0) {
      has_trace_id = 1;
      break;
    }
  }

  if (has_trace_id) {
    format_trace_id(trace_id_hex, sizeof(trace_id_hex), entry->trace_id);
    rv = snprintf(dest, destlen,
                  "{\"timestamp\":\"%s\",\"level\":\"%s\",\"component\":\"%s\","
                  "\"trace_id\":\"%s\",\"message\":\"%s\"}",
                  timestamp, nwep_log_level_str(entry->level), escaped_component,
                  trace_id_hex, escaped_msg);
  } else {
    rv = snprintf(dest, destlen,
                  "{\"timestamp\":\"%s\",\"level\":\"%s\",\"component\":\"%s\","
                  "\"message\":\"%s\"}",
                  timestamp, nwep_log_level_str(entry->level), escaped_component,
                  escaped_msg);
  }

  if (rv < 0) {
    return 0;
  }

  return (size_t)rv;
}
