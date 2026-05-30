// Bech32 (BIP-173) decoding, as used by age key encodings:
//   recipients  "age1..."             (HRP "age")
//   identities  "AGE-SECRET-KEY-1..." (HRP "age-secret-key")
//
// age uses the original Bech32 checksum (not Bech32m). Strings are
// case-insensitive but MUST NOT mix cases.

///|
pub suberror Bech32Error {
  Bech32Format(String)
  Bech32Checksum
} derive(Debug)

///|
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

///|
fn bech32_char_value(c : Char) -> Int {
  let n = c.to_int()
  for i in 0..<BECH32_CHARSET.length() {
    if BECH32_CHARSET.get_char(i).unwrap().to_int() == n {
      return i
    }
  }
  -1
}

///|
fn bech32_polymod(values : Array[Int]) -> Int {
  let gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  let mut chk = 1
  for v in values {
    let b = chk >> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v
    for i in 0..<5 {
      if ((b >> i) & 1) != 0 {
        chk = chk ^ gen[i]
      }
    }
  }
  chk
}

///|
fn bech32_hrp_expand(hrp : String) -> Array[Int] {
  let out : Array[Int] = []
  for c in hrp {
    out.push(c.to_int() >> 5)
  }
  out.push(0)
  for c in hrp {
    out.push(c.to_int() & 31)
  }
  out
}

///|
// Convert a sequence of 5-bit groups to 8-bit bytes, rejecting non-zero
// padding bits and >4 leftover bits (canonical decode).
fn bech32_5_to_8(data : Array[Int]) -> Bytes raise Bech32Error {
  let out : Array[Byte] = []
  let mut acc = 0
  let mut bits = 0
  for v in data {
    acc = (acc << 5) | v
    bits = bits + 5
    while bits >= 8 {
      bits = bits - 8
      out.push(((acc >> bits) & 0xff).to_byte())
    }
  }
  if bits >= 5 {
    raise Bech32Format("excess padding bits")
  }
  if (acc & ((1 << bits) - 1)) != 0 {
    raise Bech32Format("non-zero padding bits")
  }
  Bytes::makei(out.length(), fn(i) { out[i] })
}

///|
fn ascii_to_lower(s : String) -> String {
  let buf = StringBuilder::new()
  for c in s {
    let n = c.to_int()
    if n >= 0x41 && n <= 0x5a {
      buf.write_char((n + 0x20).to_char().unwrap())
    } else {
      buf.write_char(c)
    }
  }
  buf.to_string()
}

///|
fn has_upper(s : String) -> Bool {
  for c in s {
    let n = c.to_int()
    if n >= 0x41 && n <= 0x5a {
      return true
    }
  }
  false
}

///|
fn has_lower(s : String) -> Bool {
  for c in s {
    let n = c.to_int()
    if n >= 0x61 && n <= 0x7a {
      return true
    }
  }
  false
}

///|
/// Decode a Bech32 string into its (lowercased) HRP and the payload bytes.
/// Verifies the Bech32 checksum and rejects mixed case / malformed input.
pub fn bech32_decode(input : String) -> (String, Bytes) raise Bech32Error {
  if has_upper(input) && has_lower(input) {
    raise Bech32Format("mixed case")
  }
  let s = ascii_to_lower(input)
  // Separator is the last '1'.
  let mut sep = -1
  for i in 0..<s.length() {
    if s.get_char(i).unwrap() == '1' {
      sep = i
    }
  }
  if sep < 1 {
    raise Bech32Format("missing or misplaced separator")
  }
  if s.length() - sep - 1 < 6 {
    raise Bech32Format("data part too short")
  }
  let hrp = StringBuilder::new()
  for i in 0..<sep {
    hrp.write_char(s.get_char(i).unwrap())
  }
  let hrp_str = hrp.to_string()
  let data : Array[Int] = []
  for i = sep + 1; i < s.length(); i = i + 1 {
    let v = bech32_char_value(s.get_char(i).unwrap())
    if v < 0 {
      raise Bech32Format("invalid data character")
    }
    data.push(v)
  }
  // Checksum: polymod(hrp_expand || data) must be 1 (Bech32).
  let combined = bech32_hrp_expand(hrp_str)
  for v in data {
    combined.push(v)
  }
  if bech32_polymod(combined) != 1 {
    raise Bech32Checksum
  }
  // Drop the 6-symbol checksum and convert 5-bit -> 8-bit.
  let payload5 : Array[Int] = []
  for i = 0; i < data.length() - 6; i = i + 1 {
    payload5.push(data[i])
  }
  (hrp_str, bech32_5_to_8(payload5))
}
