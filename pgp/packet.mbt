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
    raise ArmorMalformed(
      "packet header high bit not set: 0x" + header.to_string(),
    )
  }
  if (header & 0x40) == 0 {
    // Old format: 10TTTTLL where TTTT is tag (4 bits) and LL is length type.
    let tag = (header >> 2) & 0x0F
    let len_type = header & 0x03
    let (len, hdr_len) = match len_type {
      0 => {
        require_available(data, start, 2, "old packet one-octet length")
        (data[start + 1].to_int(), 2)
      }
      1 => {
        require_available(data, start, 3, "old packet two-octet length")
        let hi = data[start + 1].to_int()
        let lo = data[start + 2].to_int()
        ((hi << 8) | lo, 3)
      }
      2 => {
        require_available(data, start, 5, "old packet four-octet length")
        let b1 = data[start + 1].to_int()
        let b2 = data[start + 2].to_int()
        let b3 = data[start + 3].to_int()
        let b4 = data[start + 4].to_int()
        ((b1 << 24) | (b2 << 16) | (b3 << 8) | b4, 5)
      }
      _ => raise ArmorMalformed("indeterminate length not supported")
    }
    require_body_available(data, start, hdr_len, len, "packet body (old)")
    let body = bytes_slice(data, start + hdr_len, start + hdr_len + len)
    ({ tag, body }, start + hdr_len + len)
  } else {
    // New format: 11TTTTTT where the lower 6 bits are the tag.
    let tag = header & 0x3F
    require_available(data, start, 2, "new packet length")
    let first = data[start + 1].to_int()
    let (len, hdr_len) = if first < 192 {
      (first, 2)
    } else if first <= 223 {
      // 2-byte: (first - 192) << 8 + second + 192
      require_available(data, start, 3, "new packet two-octet length")
      let second = data[start + 2].to_int()
      (((first - 192) << 8) + second + 192, 3)
    } else if first == 255 {
      require_available(data, start, 6, "new packet five-octet length")
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
    require_body_available(data, start, hdr_len, len, "packet body (new)")
    let body = bytes_slice(data, start + hdr_len, start + hdr_len + len)
    ({ tag, body }, start + hdr_len + len)
  }
}

///|
fn require_available(
  data : Bytes,
  start : Int,
  needed : Int,
  ctx : String,
) -> Unit raise PgpError {
  if start + needed > data.length() {
    raise PacketTooShort(ctx)
  }
}

///|
fn require_body_available(
  data : Bytes,
  start : Int,
  hdr_len : Int,
  len : Int,
  ctx : String,
) -> Unit raise PgpError {
  if len < 0 {
    raise ArmorMalformed("packet length too large")
  }
  if start + hdr_len > data.length() || len > data.length() - start - hdr_len {
    raise PacketTooShort(ctx)
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
  validate_mpi_minimal(bits, value)
  (value, 2 + bytes)
}

///|
fn validate_mpi_minimal(bits : Int, value : Bytes) -> Unit raise PgpError {
  if bits == 0 {
    if value.length() != 0 {
      raise InvalidMpi("zero MPI must have no body")
    }
    return
  }
  if value.length() == 0 {
    raise InvalidMpi("non-zero MPI missing body")
  }
  let used = if bits % 8 == 0 { 8 } else { bits % 8 }
  let first = value[0].to_int()
  let unused_mask = (0xff << used) & 0xff
  if (first & unused_mask) != 0 {
    raise InvalidMpi("MPI bit length shorter than encoded value")
  }
  let top_bit = 1 << (used - 1)
  if (first & top_bit) == 0 {
    raise InvalidMpi("MPI bit length is not minimal")
  }
}
