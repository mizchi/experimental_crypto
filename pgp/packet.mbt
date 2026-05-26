// OpenPGP packet framing (RFC 9580 §4 / RFC 4880 §4).
//
// We support both "old" and "new" packet headers. The new format is the
// modern default. Partial body lengths (used for streaming literal data
// packets) are NOT supported — they're never used for signed-message
// armor in practice.

///|
pub(all) struct PgpPacket {
  tag : Int // RFC 4880 §4.3 packet tag (Signature=2, PublicKey=6, UserID=13, …)
  body : Bytes
}

///|
/// Parse a sequence of OpenPGP packets out of `data`.
pub fn parse_packets(data : Bytes) -> Array[PgpPacket] raise PgpError {
  let out : Array[PgpPacket] = []
  let mut pos = 0
  while pos < data.length() {
    let (pkt, next) = read_packet(data, pos)
    out.push(pkt)
    pos = next
  }
  out
}

///|
fn read_packet(data : Bytes, start : Int) -> (PgpPacket, Int) raise PgpError {
  if start >= data.length() {
    raise PacketTooShort("packet header")
  }
  let header = data[start].to_int()
  if (header & 0x80) == 0 {
    raise ArmorMalformed("packet header high bit not set: 0x" + header.to_string())
  }
  if (header & 0x40) == 0 {
    // Old format: 10TTTTLL where TTTT is tag (4 bits) and LL is length type.
    let tag = (header >> 2) & 0x0F
    let len_type = header & 0x03
    let (len, hdr_len) = match len_type {
      0 => (data[start + 1].to_int(), 2)
      1 => {
        let hi = data[start + 1].to_int()
        let lo = data[start + 2].to_int()
        ((hi << 8) | lo, 3)
      }
      2 => {
        let b1 = data[start + 1].to_int()
        let b2 = data[start + 2].to_int()
        let b3 = data[start + 3].to_int()
        let b4 = data[start + 4].to_int()
        ((b1 << 24) | (b2 << 16) | (b3 << 8) | b4, 5)
      }
      _ => raise ArmorMalformed("indeterminate length not supported")
    }
    if start + hdr_len + len > data.length() {
      raise PacketTooShort("packet body (old)")
    }
    let body = bytes_slice(data, start + hdr_len, start + hdr_len + len)
    ({ tag, body }, start + hdr_len + len)
  } else {
    // New format: 11TTTTTT where the lower 6 bits are the tag.
    let tag = header & 0x3F
    let first = data[start + 1].to_int()
    let (len, hdr_len) = if first < 192 {
      (first, 2)
    } else if first <= 223 {
      // 2-byte: (first - 192) << 8 + second + 192
      let second = data[start + 2].to_int()
      (((first - 192) << 8) + second + 192, 3)
    } else if first == 255 {
      let b1 = data[start + 2].to_int()
      let b2 = data[start + 3].to_int()
      let b3 = data[start + 4].to_int()
      let b4 = data[start + 5].to_int()
      ((b1 << 24) | (b2 << 16) | (b3 << 8) | b4, 6)
    } else {
      raise ArmorMalformed(
        "partial-body length not supported (first=" + first.to_string() + ")",
      )
    }
    if start + hdr_len + len > data.length() {
      raise PacketTooShort("packet body (new)")
    }
    let body = bytes_slice(data, start + hdr_len, start + hdr_len + len)
    ({ tag, body }, start + hdr_len + len)
  }
}

///|
fn bytes_slice(b : Bytes, start : Int, end : Int) -> Bytes {
  Bytes::makei(end - start, fn(i) { b[start + i] })
}

// ─── MPI (Multi-Precision Integer, RFC 4880 §3.2) ────────────────────────

///|
// Returns (value_bytes, bytes_consumed). The first 2 bytes encode the
// length in bits (big-endian); the remainder is the big-endian magnitude.
pub fn read_mpi(data : Bytes, start : Int) -> (Bytes, Int) raise PgpError {
  if start + 2 > data.length() {
    raise InvalidMpi("MPI header")
  }
  let bits = (data[start].to_int() << 8) | data[start + 1].to_int()
  let bytes = (bits + 7) / 8
  if start + 2 + bytes > data.length() {
    raise InvalidMpi("MPI body")
  }
  let value = bytes_slice(data, start + 2, start + 2 + bytes)
  (value, 2 + bytes)
}
