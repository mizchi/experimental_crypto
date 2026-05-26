// OpenPGP Signature Packet v4 (RFC 9580 §5.2.3 / RFC 4880 §5.2.3) and
// v6 (RFC 9580 §5.2.3).
//
// v4 layout:
//   1 octet  version  (4)
//   1 octet  signature type
//   1 octet  pubkey algorithm
//   1 octet  hash algorithm
//   2 octets hashed subpacket length (N)
//   N octets hashed subpackets
//   2 octets unhashed subpacket length (M)
//   M octets unhashed subpackets
//   2 octets left 16 bits of hash value (quick check)
//   K octets signature material (algorithm-specific MPIs)
//
// v6 layout (RFC 9580 §5.2.3):
//   1 octet  version  (6)
//   1 octet  signature type
//   1 octet  pubkey algorithm
//   1 octet  hash algorithm
//   4 octets hashed subpacket length (N)    ← was 2 in v4
//   N octets hashed subpackets
//   4 octets unhashed subpacket length (M)  ← was 2 in v4
//   M octets unhashed subpackets
//   2 octets left 16 bits of hash value
//   1 octet  salt length (S)                ← NEW
//   S octets salt                           ← NEW; also prepended to hash input
//   K octets signature material (Ed25519: 64 raw bytes, no MPI wrap)

///|
pub(all) struct PgpSignature {
  version : Int
  sig_type : Int
  pubkey_algo : Int
  hash_algo : Int
  // Prelude: version..end of hashed subpackets. Length is 6+N for v4,
  // 8+N for v6.
  hashed_subpackets_raw : Bytes
  hashed_subpackets_body : Bytes // N bytes (the subpacket area only)
  left16 : UInt
  // v6 salt; b"" for v4.
  salt : Bytes
  signature_material : Bytes
}

///|
/// Parse a Signature Packet body (tag 2 contents). Handles v4 and v6.
pub fn parse_signature_packet(body : Bytes) -> PgpSignature raise PgpError {
  if body.length() < 6 {
    raise PacketTooShort("signature packet header")
  }
  let version = body[0].to_int()
  if version != 4 && version != 6 {
    raise UnsupportedPacketVersion(version)
  }
  let sig_type = body[1].to_int()
  let pubkey_algo = body[2].to_int()
  let hash_algo = body[3].to_int()
  // Hashed-subpacket length field is 2 bytes (v4) or 4 bytes (v6).
  let len_field = if version == 6 { 4 } else { 2 }
  if body.length() < 4 + len_field {
    raise PacketTooShort("hashed-subpacket length")
  }
  let hashed_len = if version == 6 {
    (body[4].to_int() << 24) |
    (body[5].to_int() << 16) |
    (body[6].to_int() << 8) |
    body[7].to_int()
  } else {
    (body[4].to_int() << 8) | body[5].to_int()
  }
  let hashed_start = 4 + len_field
  if hashed_start + hashed_len + len_field > body.length() {
    raise PacketTooShort("hashed subpacket area")
  }
  let hashed_subpackets_body = bytes_slice(
    body,
    hashed_start,
    hashed_start + hashed_len,
  )
  // Prelude for trailer: version..end of hashed subpackets.
  let hashed_subpackets_raw = bytes_slice(body, 0, hashed_start + hashed_len)
  let unhashed_len_pos = hashed_start + hashed_len
  let unhashed_len = if version == 6 {
    (body[unhashed_len_pos].to_int() << 24) |
    (body[unhashed_len_pos + 1].to_int() << 16) |
    (body[unhashed_len_pos + 2].to_int() << 8) |
    body[unhashed_len_pos + 3].to_int()
  } else {
    (body[unhashed_len_pos].to_int() << 8) | body[unhashed_len_pos + 1].to_int()
  }
  let after_unhashed = unhashed_len_pos + len_field + unhashed_len
  if after_unhashed + 2 > body.length() {
    raise PacketTooShort("unhashed subpacket area / left16")
  }
  let left16 = (body[after_unhashed].to_uint() << 8) |
    body[after_unhashed + 1].to_uint()
  // v6 inserts: 1-byte salt_len || S-byte salt before the signature material.
  let (salt, sig_material_start) = if version == 6 {
    let salt_len_pos = after_unhashed + 2
    if salt_len_pos >= body.length() {
      raise PacketTooShort("v6 salt length")
    }
    let salt_len = body[salt_len_pos].to_int()
    if salt_len_pos + 1 + salt_len > body.length() {
      raise PacketTooShort("v6 salt")
    }
    let s = bytes_slice(body, salt_len_pos + 1, salt_len_pos + 1 + salt_len)
    (s, salt_len_pos + 1 + salt_len)
  } else {
    (b"", after_unhashed + 2)
  }
  let signature_material = bytes_slice(body, sig_material_start, body.length())
  {
    version,
    sig_type,
    pubkey_algo,
    hash_algo,
    hashed_subpackets_raw,
    hashed_subpackets_body,
    left16,
    salt,
    signature_material,
  }
}

///|
fn _unused_field(_p : PgpSignature) -> Unit {
  let _ = _p.hashed_subpackets_body
  let _ = _p.left16
  let _ = _p.salt
}

///|
/// Build the digest to be verified for a Signature Packet over `message`.
///
/// Per RFC 4880 §5.2.4 (v4):
///   data_to_hash = message || hashed_subpackets_raw || trailer
///   trailer       = 0x04 || 0xFF || uint32_be(len(hashed_subpackets_raw))
///
/// Per RFC 9580 §5.2.4 (v6):
///   data_to_hash = salt || message || hashed_subpackets_raw || trailer
///   trailer       = 0x06 || 0xFF || uint32_be(len(hashed_subpackets_raw))
///   (the salt is prepended to the hash input; it is NOT included in the
///   trailer length count)
pub fn compute_signature_digest(
  sig : PgpSignature,
  message : Bytes,
) -> Bytes raise PgpError {
  let prelude = sig.hashed_subpackets_raw
  let prelude_len = prelude.length()
  let salt_len = sig.salt.length()
  let total = salt_len + message.length() + prelude_len + 6
  let buf = FixedArray::make(total, b'\x00')
  let mut off = 0
  for i = 0; i < salt_len; i = i + 1 {
    buf[off + i] = sig.salt[i]
  }
  off = off + salt_len
  for i = 0; i < message.length(); i = i + 1 {
    buf[off + i] = message[i]
  }
  off = off + message.length()
  for i = 0; i < prelude_len; i = i + 1 {
    buf[off + i] = prelude[i]
  }
  off = off + prelude_len
  // Trailer: 04/06 FF <uint32 BE of prelude_len>.
  buf[off] = if sig.version == 6 { b'\x06' } else { b'\x04' }
  buf[off + 1] = b'\xff'
  buf[off + 2] = ((prelude_len.reinterpret_as_uint() >> 24) & 0xffU).to_byte()
  buf[off + 3] = ((prelude_len.reinterpret_as_uint() >> 16) & 0xffU).to_byte()
  buf[off + 4] = ((prelude_len.reinterpret_as_uint() >> 8) & 0xffU).to_byte()
  buf[off + 5] = (prelude_len.reinterpret_as_uint() & 0xffU).to_byte()
  let payload = Bytes::makei(total, fn(j) { buf[j] })
  hash_with_algo(sig.hash_algo, payload)
}

///|
fn hash_with_algo(algo : Int, data : Bytes) -> Bytes raise PgpError {
  if algo == hash_sha256 {
    @hash.sha256(data)
  } else if algo == hash_sha384 {
    @hash.sha384(data)
  } else if algo == hash_sha512 {
    @hash.sha512(data)
  } else {
    raise UnsupportedHashAlgo(algo)
  }
}
