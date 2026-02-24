#ifndef KX_PARSER_H
#define KX_PARSER_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  KX_OK = 0,
  KX_E_INVALID_ARG = 1,
  KX_E_PARSE = 2,
  KX_E_SCHEMA = 3,
  KX_E_OOM = 4,
  KX_E_INTERNAL = 5,
  KX_E_BUFFER_TOO_SMALL = 6
} kx_err;

kx_err kx_parse_lockfile(const uint8_t* in_ptr,
                         size_t in_len,
                         uint8_t* out_ptr,
                         size_t out_cap,
                         size_t* out_len);

#endif
