#include "kx_parser.h"

static int kx_is_space(uint8_t ch) {
  return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r';
}

kx_err kx_parse_lockfile(const uint8_t* in_ptr,
                         size_t in_len,
                         uint8_t* out_ptr,
                         size_t out_cap,
                         size_t* out_len) {
  size_t start = 0;
  size_t end = in_len;
  size_t required_len = 0;
  size_t i = 0;
  size_t write_index = 0;

  if (in_ptr == 0 || out_len == 0) {
    return KX_E_INVALID_ARG;
  }

  while (start < in_len && kx_is_space(in_ptr[start])) {
    start += 1;
  }

  while (end > start && kx_is_space(in_ptr[end - 1])) {
    end -= 1;
  }

  if (start >= end) {
    *out_len = 0;
    return KX_E_PARSE;
  }

  if (in_ptr[start] != '{' || in_ptr[end - 1] != '}') {
    *out_len = 0;
    return KX_E_SCHEMA;
  }

  for (i = start; i < end; i += 1) {
    if (in_ptr[i] != '\r') {
      required_len += 1;
    }
  }

  *out_len = required_len;
  if (out_ptr == 0 || out_cap < required_len) {
    return KX_E_BUFFER_TOO_SMALL;
  }

  for (i = start; i < end; i += 1) {
    if (in_ptr[i] != '\r') {
      out_ptr[write_index] = in_ptr[i];
      write_index += 1;
    }
  }

  return KX_OK;
}
