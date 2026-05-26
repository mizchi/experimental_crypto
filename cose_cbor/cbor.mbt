// CBOR (Concise Binary Object Representation) — RFC 8949
//
// This is a minimum-viable encoder/decoder. Supported:
//   - unsigned integer (major type 0)
//   - negative integer (major type 1)
//   - byte string (major type 2)
//   - text string (major type 3, UTF-8)
//   - array (major type 4)
//   - map (major type 5, preserves insertion order)
//   - tagged values (major type 6) — needed for COSE_Sign1
//   - simple values (major type 7): false (20), true (21), null (22),
//     undefined (23)
//   - float16 / float32 / float64 (major type 7) — decode only, encoded
//     payload is preserved as `Float64` (half/single widened to double).
//
// Out of scope for this minimum:
//   - indefinite-length encoding
//   - bignums / big floats / decimal fractions

///|
pub(all) enum CborValue {
  Uint(UInt64)
  // `Nint(n)` represents the negative integer `-1 - n`. So `Nint(0)` is -1,
  // `Nint(9)` is -10, and `Nint(0xFFFFFFFFFFFFFFFF)` is -2^64 (the smallest
  // CBOR-representable integer in major type 1).
  Nint(UInt64)
  Bytes(Bytes)
  Text(String)
  Array(Array[CborValue])
  // Preserves insertion order — COSE deterministic-encoding rules
  // (RFC 9052 §4.4) require canonical ordering on the wire, so giving the
  // caller exact control over the order is more useful than dict-style
  // semantics that re-order keys.
  Map(Array[(CborValue, CborValue)])
  Tag(UInt64, CborValue)
  Bool(Bool)
  Null
  Undefined
  Float(Double)
} derive(Debug)

///|
pub suberror CborError {
  TruncatedInput
  InvalidInitialByte(Byte)
  InvalidUtf8
  IntegerTooLarge
  IndefiniteLengthUnsupported
  TrailingBytes(Int)
  NestingTooDeep
  // Reserved-for-future / illegal additional-info value (28..30 in any
  // major type, or simple values 24 with payload < 32).
  InvalidEncoding(String)
} derive(Debug)

///|
const MAX_DEPTH : Int = 64

// --- Encoding ------------------------------------------------------------

///|
pub fn encode(v : CborValue) -> Bytes {
  let buf = Buffer()
  encode_into(buf, v)
  buf.to_bytes()
}

///|
fn encode_into(buf : Buffer, v : CborValue) -> Unit {
  match v {
    Uint(n) => write_head(buf, 0, n)
    Nint(n) => write_head(buf, 1, n)
    Bytes(b) => {
      write_head(buf, 2, b.length().to_uint64())
      buf.write_bytes(b)
    }
    Text(s) => {
      let utf8 = @utf8.encode(s[:])
      write_head(buf, 3, utf8.length().to_uint64())
      buf.write_bytes(utf8)
    }
    Array(items) => {
      write_head(buf, 4, items.length().to_uint64())
      for item in items {
        encode_into(buf, item)
      }
    }
    Map(pairs) => {
      write_head(buf, 5, pairs.length().to_uint64())
      for pair in pairs {
        let (k, v) = pair
        encode_into(buf, k)
        encode_into(buf, v)
      }
    }
    Tag(t, inner) => {
      write_head(buf, 6, t)
      encode_into(buf, inner)
    }
    Bool(b) => buf.write_byte((if b { 0xF5 } else { 0xF4 }).to_byte())
    Null => buf.write_byte(b'\xF6')
    Undefined => buf.write_byte(b'\xF7')
    // Always encode floats as the 8-byte float64 form (major type 7,
    // additional info 27). RFC 8949 §3.3 allows shorter forms, but COSE
    // verification only needs to round-trip the bytes we received and
    // CTAP2 canonical never writes floats anyway. Easier to be correct
    // here than to fight IEEE-754 narrowing rules.
    Float(d) => {
      buf.write_byte(b'\xFB')
      let bits = d.reinterpret_as_uint64()
      write_be_u64(buf, bits)
    }
  }
}

///|
// Write the initial byte + argument for major type 0..7 per RFC 8949 §3.
//
// Major type goes in the top 3 bits of the initial byte. The bottom 5 bits
// ("additional info") encode the argument width:
//   0..23   → argument is the additional-info value itself
//   24      → 1 more byte
//   25      → 2 more bytes (big-endian)
//   26      → 4 more bytes (big-endian)
//   27      → 8 more bytes (big-endian)
fn write_head(buf : Buffer, mt : Int, arg : UInt64) -> Unit {
  let mt_bits = (mt & 0x7) << 5
  if arg < 24UL {
    buf.write_byte((mt_bits | arg.to_int()).to_byte())
  } else if arg < 0x100UL {
    buf.write_byte((mt_bits | 24).to_byte())
    buf.write_byte(arg.to_int().to_byte())
  } else if arg < 0x10000UL {
    buf.write_byte((mt_bits | 25).to_byte())
    write_be_u16(buf, arg.to_uint())
  } else if arg < 0x100000000UL {
    buf.write_byte((mt_bits | 26).to_byte())
    write_be_u32(buf, arg.to_uint())
  } else {
    buf.write_byte((mt_bits | 27).to_byte())
    write_be_u64(buf, arg)
  }
}

///|
fn write_be_u16(buf : Buffer, v : UInt) -> Unit {
  buf.write_byte(((v >> 8) & 0xFF).to_byte())
  buf.write_byte((v & 0xFF).to_byte())
}

///|
fn write_be_u32(buf : Buffer, v : UInt) -> Unit {
  buf.write_byte(((v >> 24) & 0xFF).to_byte())
  buf.write_byte(((v >> 16) & 0xFF).to_byte())
  buf.write_byte(((v >> 8) & 0xFF).to_byte())
  buf.write_byte((v & 0xFF).to_byte())
}

///|
fn write_be_u64(buf : Buffer, v : UInt64) -> Unit {
  for i = 7; i >= 0; i = i - 1 {
    buf.write_byte(((v >> (i * 8)) & 0xFFUL).to_int().to_byte())
  }
}

// --- Decoding ------------------------------------------------------------

///|
pub fn decode(b : Bytes) -> CborValue raise CborError {
  let dec = Decoder::{ input: b, pos: 0 }
  let v = decode_value(dec, 0)
  if dec.pos != b.length() {
    raise TrailingBytes(b.length() - dec.pos)
  }
  v
}

///|
// `decode_first` consumes a single CBOR item and returns it together with
// the number of bytes consumed. Useful for COSE_Sign1, where the outer
// item may be wrapped in a tag and the caller wants to know exactly how
// many bytes the inner structure occupied.
pub fn decode_first(b : Bytes) -> (CborValue, Int) raise CborError {
  let dec = Decoder::{ input: b, pos: 0 }
  let v = decode_value(dec, 0)
  (v, dec.pos)
}

///|
priv struct Decoder {
  input : Bytes
  mut pos : Int
}

///|
fn Decoder::read_byte(self : Decoder) -> Byte raise CborError {
  if self.pos >= self.input.length() {
    raise TruncatedInput
  }
  let b = self.input[self.pos]
  self.pos = self.pos + 1
  b
}

///|
fn Decoder::read_bytes(self : Decoder, n : Int) -> Bytes raise CborError {
  if n < 0 {
    raise InvalidEncoding("negative length")
  }
  if self.pos + n > self.input.length() {
    raise TruncatedInput
  }
  let out = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = self.input[self.pos + i]
  }
  self.pos = self.pos + n
  Bytes::from_array(out)
}

///|
fn Decoder::read_be(self : Decoder, n : Int) -> UInt64 raise CborError {
  let mut acc = 0UL
  for i = 0; i < n; i = i + 1 {
    let b = self.read_byte()
    acc = (acc << 8) | b.to_uint64()
  }
  acc
}

///|
fn decode_value(dec : Decoder, depth : Int) -> CborValue raise CborError {
  if depth > MAX_DEPTH {
    raise NestingTooDeep
  }
  let ib = dec.read_byte()
  let ib_int = ib.to_int()
  let mt = (ib_int >> 5) & 0x7
  let ai = ib_int & 0x1F
  // Indefinite-length: AI = 31 on major types 2..5 (and the "break" stop
  // code 0xFF on major type 7). Not implementing this — CTAP2 canonical
  // encoding (the only flavor COSE_Sign1 needs) forbids it anyway.
  if ai == 31 {
    raise IndefiniteLengthUnsupported
  }
  // AI 28..30 are reserved by RFC 8949; any decoder that ignores them
  // would silently accept ill-formed input.
  if ai >= 28 && ai <= 30 {
    raise InvalidEncoding("reserved additional info")
  }
  let arg : UInt64 = if ai < 24 {
    ai.to_uint64()
  } else if ai == 24 {
    dec.read_be(1)
  } else if ai == 25 {
    dec.read_be(2)
  } else if ai == 26 {
    dec.read_be(4)
  } else {
    dec.read_be(8)
  }
  match mt {
    0 => Uint(arg)
    1 => Nint(arg)
    2 => {
      let len = check_length(arg)
      Bytes(dec.read_bytes(len))
    }
    3 => {
      let len = check_length(arg)
      let bytes = dec.read_bytes(len)
      let s = @utf8.decode(bytes[:]) catch { _ => raise InvalidUtf8 }
      Text(s)
    }
    4 => {
      let len = check_length(arg)
      let items : Array[CborValue] = []
      for i = 0; i < len; i = i + 1 {
        items.push(decode_value(dec, depth + 1))
      }
      Array(items)
    }
    5 => {
      let len = check_length(arg)
      let pairs : Array[(CborValue, CborValue)] = []
      for i = 0; i < len; i = i + 1 {
        let k = decode_value(dec, depth + 1)
        let v = decode_value(dec, depth + 1)
        pairs.push((k, v))
      }
      Map(pairs)
    }
    6 => {
      let inner = decode_value(dec, depth + 1)
      Tag(arg, inner)
    }
    7 =>
      match ai {
        20 => Bool(false)
        21 => Bool(true)
        22 => Null
        23 => Undefined
        // Half-precision float (decode only — widen to double).
        25 => Float(half_to_double(arg.to_int()))
        // Single-precision float.
        26 => {
          let bits = arg.to_uint()
          Float(Float::reinterpret_from_uint(bits).to_double())
        }
        // Double-precision float.
        27 => Float(arg.reinterpret_as_double())
        24 =>
          if arg < 32UL {
            // RFC 8949 §3.3: simple value 0..31 MUST be in the immediate
            // form (one byte), so the two-byte form here is malformed.
            raise InvalidEncoding("simple value 0..31 must be immediate")
          } else {
            // Simple values 32..255 — not needed for COSE. Reject so a
            // caller doesn't silently lose data.
            raise InvalidEncoding("unsupported simple value")
          }
        _ => raise InvalidEncoding("unsupported simple/float value")
      }
    _ => raise InvalidInitialByte(ib)
  }
}

///|
fn check_length(n : UInt64) -> Int raise CborError {
  // Int is 32-bit; CBOR allows lengths up to 2^64-1 but a single string /
  // array of that size won't fit in memory anyway. Cap at MaxInt so the
  // `Bytes` allocation path stays honest.
  if n > 0x7FFFFFFFUL {
    raise IntegerTooLarge
  }
  n.to_int()
}

///|
// Decode RFC 8949 §3.3 / IEEE-754 binary16 into a binary64.
// 1 sign + 5 exponent + 10 mantissa bits.
fn half_to_double(bits : Int) -> Double {
  let sign = (bits >> 15) & 0x1
  let exp = (bits >> 10) & 0x1F
  let mant = bits & 0x3FF
  let d : Double = if exp == 0 {
    // Subnormal: value = (-1)^sign * 2^-14 * (mant / 1024)
    mant.to_double() * 5.960464477539063e-8 // 2^-24
  } else if exp == 31 {
    if mant == 0 {
      // ±Infinity
      let bits_f64 = 0x7FF0000000000000UL
      bits_f64.reinterpret_as_double()
    } else {
      // NaN — payload preservation isn't strictly defined for CBOR;
      // emit a quiet NaN.
      let bits_f64 = 0x7FF8000000000000UL
      bits_f64.reinterpret_as_double()
    }
  } else {
    // Normal: value = (-1)^sign * 2^(exp-15) * (1 + mant/1024)
    let unbiased = exp - 15
    let m = 1.0 + mant.to_double() / 1024.0
    m * pow2(unbiased)
  }
  if sign == 1 {
    -d
  } else {
    d
  }
}

///|
// Branch-light integer power-of-two helper for half-float widening.
// Only called with `exp` in [-14, 15] so the loop is tiny.
fn pow2(exp : Int) -> Double {
  let mut e = exp
  let mut r = 1.0
  if e >= 0 {
    while e > 0 {
      r = r * 2.0
      e = e - 1
    }
  } else {
    while e < 0 {
      r = r / 2.0
      e = e + 1
    }
  }
  r
}

// --- Convenience accessors ----------------------------------------------

///|
// Return the value associated with an integer key in a CBOR map. Returns
// `None` if the value is not a map or the key is absent. COSE protected /
// unprotected headers use integer label maps almost exclusively, so this
// is the workhorse for `cose`.
pub fn map_get_int(v : CborValue, key : Int64) -> CborValue? {
  match v {
    Map(pairs) => {
      for pair in pairs {
        let (k, val) = pair
        match k {
          Uint(n) =>
            if key >= 0L && n == key.reinterpret_as_uint64() {
              return Some(val)
            }
          Nint(n) =>
            // Nint(n) = -1 - n  ⇒  n = -1 - key  (valid only when key<0)
            if key < 0L {
              let expected = (-1L - key).reinterpret_as_uint64()
              if n == expected {
                return Some(val)
              }
            }
          _ => ()
        }
      }
      None
    }
    _ => None
  }
}

///|
// Look up a text-keyed value in a CBOR map. WebAuthn's
// `attestationObject` uses string keys ("fmt", "authData", "attStmt"),
// so this is the text-key analogue of `map_get_int`.
pub fn map_get_str(v : CborValue, key : String) -> CborValue? {
  match v {
    Map(pairs) => {
      for pair in pairs {
        let (k, val) = pair
        match k {
          Text(s) => if s == key { return Some(val) }
          _ => ()
        }
      }
      None
    }
    _ => None
  }
}
