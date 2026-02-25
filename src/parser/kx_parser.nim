import std/[algorithm, json, strutils]

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

proc isBareKeyChar(ch: char): bool {.inline.} =
  (ch >= 'a' and ch <= 'z') or
  (ch >= 'A' and ch <= 'Z') or
  (ch >= '0' and ch <= '9') or
  ch == '_' or ch == '-'

proc decodeBytes(input: ptr UncheckedArray[uint8], in_len: int): string =
  result = newString(in_len)
  for i in 0..<in_len:
    result[i] = char(input[i])

proc stripLineComment(line: string): string =
  var in_string = false
  var escaping = false
  for i, ch in line:
    if in_string:
      if escaping:
        escaping = false
      elif ch == '\\':
        escaping = true
      elif ch == '"':
        in_string = false
    elif ch == '"':
      in_string = true
    elif ch == '#':
      return line[0..<i]
  return line

proc splitHeaderPath(path_text: string): seq[string] =
  result = @[]
  let trimmed = path_text.strip
  if trimmed.len == 0:
    raise newException(ValueError, "empty header path")

  var part_start = 0
  for i, ch in trimmed:
    if ch == '.':
      if i == part_start:
        raise newException(ValueError, "empty path segment")
      let part = trimmed[part_start..<i].strip
      if part.len == 0:
        raise newException(ValueError, "empty path segment")
      for key_ch in part:
        if not isBareKeyChar(key_ch):
          raise newException(ValueError, "invalid key segment")
      result.add(part)
      part_start = i + 1

  if part_start >= trimmed.len:
    raise newException(ValueError, "empty path segment")
  let tail = trimmed[part_start..^1].strip
  if tail.len == 0:
    raise newException(ValueError, "empty path segment")
  for key_ch in tail:
    if not isBareKeyChar(key_ch):
      raise newException(ValueError, "invalid key segment")
  result.add(tail)

proc ensureObject(parent: JsonNode, key: string): JsonNode =
  if not parent.hasKey(key):
    parent[key] = newJObject()
  let child = parent[key]
  if child.kind != JObject:
    raise newException(ValueError, "path key is not object")
  return child

proc ensureArray(parent: JsonNode, key: string): JsonNode =
  if not parent.hasKey(key):
    parent[key] = newJArray()
  let child = parent[key]
  if child.kind != JArray:
    raise newException(ValueError, "path key is not array")
  return child

proc resolveTable(root: JsonNode, segments: seq[string]): JsonNode =
  var current = root
  for seg in segments:
    current = ensureObject(current, seg)
  return current

proc resolveArrayTable(root: JsonNode, segments: seq[string]): JsonNode =
  if segments.len == 0:
    raise newException(ValueError, "empty array table path")

  var parent = root
  for i in 0..<(segments.len - 1):
    parent = ensureObject(parent, segments[i])

  let arr = ensureArray(parent, segments[^1])
  let item = newJObject()
  arr.add(item)
  return item

proc parseTomlString(raw: string): string =
  if raw.len < 2 or raw[0] != '"' or raw[^1] != '"':
    raise newException(ValueError, "invalid string")

  result = ""
  var i = 1
  while i < raw.len - 1:
    let ch = raw[i]
    if ch == '\\':
      inc(i)
      if i >= raw.len - 1:
        raise newException(ValueError, "invalid escape")
      let esc = raw[i]
      case esc
      of '"': result.add('"')
      of '\\': result.add('\\')
      of 'n': result.add('\n')
      of 'r': result.add('\r')
      of 't': result.add('\t')
      else: raise newException(ValueError, "unsupported escape")
    else:
      result.add(ch)
    inc(i)

proc splitArrayItems(content: string): seq[string] =
  result = @[]
  var current = ""
  var in_string = false
  var escaping = false

  for ch in content:
    if in_string:
      current.add(ch)
      if escaping:
        escaping = false
      elif ch == '\\':
        escaping = true
      elif ch == '"':
        in_string = false
      continue

    case ch
    of '"':
      in_string = true
      current.add(ch)
    of ',':
      let item = current.strip
      if item.len == 0:
        raise newException(ValueError, "empty array item")
      result.add(item)
      current.setLen(0)
    else:
      current.add(ch)

  if in_string:
    raise newException(ValueError, "unterminated string")

  let tail = current.strip
  if tail.len != 0:
    result.add(tail)
  elif content.strip.len != 0:
    raise newException(ValueError, "trailing comma")

proc parseTomlScalar(text: string): JsonNode =
  let trimmed = text.strip
  if trimmed.len == 0:
    raise newException(ValueError, "empty value")

  if trimmed[0] == '"':
    return %parseTomlString(trimmed)

  if trimmed == "true":
    return %true
  if trimmed == "false":
    return %false

  var all_digits = true
  for ch in trimmed:
    if ch < '0' or ch > '9':
      all_digits = false
      break
  if all_digits:
    return %parseBiggestInt(trimmed)

  raise newException(ValueError, "unsupported value type")

proc parseTomlValue(text: string): JsonNode =
  let trimmed = text.strip
  if trimmed.len == 0:
    raise newException(ValueError, "empty value")

  if trimmed[0] == '[':
    if trimmed[^1] != ']':
      raise newException(ValueError, "invalid array")
    let inner = trimmed[1..<trimmed.len - 1].strip
    result = newJArray()
    if inner.len == 0:
      return
    let items = splitArrayItems(inner)
    for item in items:
      let value = parseTomlScalar(item)
      if value.kind == JArray or value.kind == JObject:
        raise newException(ValueError, "nested values are not allowed")
      result.add(value)
    return

  return parseTomlScalar(trimmed)

proc parseAssignmentLine(line: string): tuple[key: string, value: JsonNode] =
  var sep = -1
  var in_string = false
  var escaping = false

  for i, ch in line:
    if in_string:
      if escaping:
        escaping = false
      elif ch == '\\':
        escaping = true
      elif ch == '"':
        in_string = false
      continue

    if ch == '"':
      in_string = true
      continue

    if ch == '=':
      sep = i
      break

  if sep <= 0:
    raise newException(ValueError, "missing '='")

  let key_text = line[0..<sep].strip
  if key_text.len == 0:
    raise newException(ValueError, "empty key")
  for ch in key_text:
    if not isBareKeyChar(ch):
      raise newException(ValueError, "invalid key")

  let value_text = line[sep + 1..^1]
  return (key: key_text, value: parseTomlValue(value_text))

proc parseTomlDocument(input: string): JsonNode =
  result = newJObject()
  var current = result

  for raw_line in input.splitLines():
    let line = stripLineComment(raw_line).strip
    if line.len == 0:
      continue

    if line.startsWith("[["):
      if not line.endsWith("]]"):
        raise newException(ValueError, "invalid array table")
      let header = line[2..<line.len - 2]
      let segments = splitHeaderPath(header)
      current = resolveArrayTable(result, segments)
      continue

    if line.startsWith("["):
      if not line.endsWith("]") or line.startsWith("[["):
        raise newException(ValueError, "invalid table")
      let header = line[1..<line.len - 1]
      let segments = splitHeaderPath(header)
      current = resolveTable(result, segments)
      continue

    let assignment = parseAssignmentLine(line)
    current[assignment.key] = assignment.value

proc canonicalizeJson(node: JsonNode): JsonNode =
  case node.kind
  of JObject:
    result = newJObject()
    var keys: seq[string] = @[]
    for key, _ in node:
      keys.add(key)
    keys.sort(system.cmp[string])
    for key in keys:
      result[key] = canonicalizeJson(node[key])
  of JArray:
    result = newJArray()
    for child in node:
      result.add(canonicalizeJson(child))
  else:
    result = node

proc parseAndCanonicalize(input_text: string): string =
  let trimmed = input_text.strip
  if trimmed.len == 0:
    raise newException(ValueError, "empty input")

  let parsed =
    if trimmed[0] == '{' and trimmed[^1] == '}':
      parseJson(trimmed)
    else:
      parseTomlDocument(trimmed)
  let canonical = canonicalizeJson(parsed)
  return $canonical

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
    let source = decodeBytes(input, int(in_len))
    let canonical = parseAndCanonicalize(source)

    out_len[] = csize_t(canonical.len)
    if out_ptr.isNil or int(out_cap) < canonical.len:
      return KX_E_BUFFER_TOO_SMALL

    for i in 0..<canonical.len:
      output[i] = uint8(canonical[i])
    return KX_OK
  except OutOfMemDefect:
    return KX_E_OOM
  except JsonParsingError:
    return KX_E_PARSE
  except ValueError:
    return KX_E_PARSE
  except CatchableError:
    return KX_E_INTERNAL
  except Defect:
    return KX_E_INTERNAL
  except:
    return KX_E_INTERNAL
