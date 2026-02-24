type
  KxErr* {.size: sizeof(cint).} = enum
    KX_OK = 0
    KX_E_INVALID_ARG = 1
    KX_E_PARSE = 2
    KX_E_SCHEMA = 3
    KX_E_OOM = 4
    KX_E_INTERNAL = 5
    KX_E_BUFFER_TOO_SMALL = 6

proc isSpace(ch: uint8): bool {.inline.} =
  ch == uint8(' ') or ch == uint8('\t') or ch == uint8('\n') or ch == uint8('\r')

proc kx_parse_lockfile*(in_ptr: ptr uint8,
                        in_len: csize_t,
                        out_ptr: ptr uint8,
                        out_cap: csize_t,
                        out_len: ptr csize_t): KxErr {.
    cdecl, exportc: "kx_parse_lockfile".} =
  if in_ptr.isNil or out_len.isNil:
    return KX_E_INVALID_ARG

  try:
    let input = cast[ptr UncheckedArray[uint8]](in_ptr)
    let output = cast[ptr UncheckedArray[uint8]](out_ptr)
    var start = 0
    var finish = int(in_len)
    while start < int(in_len) and isSpace(input[start]):
      inc(start)
    while finish > start and isSpace(input[finish - 1]):
      dec(finish)

    if start >= finish:
      out_len[] = 0
      return KX_E_PARSE

    if input[start] != uint8('{') or input[finish - 1] != uint8('}'):
      out_len[] = 0
      return KX_E_SCHEMA

    var required = 0
    var i = start
    while i < finish:
      if input[i] != uint8('\r'):
        inc(required)
      inc(i)

    out_len[] = csize_t(required)
    if out_ptr.isNil or int(out_cap) < required:
      return KX_E_BUFFER_TOO_SMALL

    var writeIndex = 0
    i = start
    while i < finish:
      if input[i] != uint8('\r'):
        output[writeIndex] = input[i]
        inc(writeIndex)
      inc(i)

    return KX_OK
  except OutOfMemDefect:
    return KX_E_OOM
  except CatchableError:
    return KX_E_INTERNAL
  except Defect:
    return KX_E_INTERNAL
  except:
    return KX_E_INTERNAL
