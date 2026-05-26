// OpenPGP Signature Packet v4 (RFC 9580 §5.2.3 / RFC 4880 §5.2.3).
//
// Layout:
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

///|
pub(all) struct PgpSignature {
  version : Int
  sig_type : Int
  pubkey_algo : Int
  hash_algo : Int
  // Raw bytes including the 2-byte length prefix — needed to reconstruct
  // the "v4 signature header" portion of the to-be-hashed prelude.
  hashed_subpackets_raw : Bytes // 6 + N: starts with the 6-byte header (vsn..hashed_len)
  hashed_subpackets_body : Bytes // N bytes (the subpacket area only)
  left16 : UInt
  signature_material : Bytes
}

///|
/// Parse a Signature Packet body (tag 2 contents).
pub fn parse_signature_packet(body : Bytes) -> PgpSignature raise PgpError {
  if body.length() < 6 {
    raise PacketTooShort("signature packet header")
  }
  let version = body[0].to_int()
  if version != 4 {
    raise UnsupportedPacketVersion(version)
  }
  let sig_type = body[1].to_int()
  let pubkey_algo = body[2].to_int()
  let hash_algo = body[3].to_int()
  let hashed_len = (body[4].to_int() << 8) | body[5].to_int()
  if 6 + hashed_len + 2 > body.length() {
    raise PacketTooShort("hashed subpacket area")
  }
  let hashed_subpackets_body = bytes_slice(body, 6, 6 + hashed_len)
  // For the signed-prelude reconstruction we keep the header + length +
  // body (everything from byte 0 to 6+hashed_len).
  let hashed_subpackets_raw = bytes_slice(body, 0, 6 + hashed_len)
  let unhashed_len_pos = 6 + hashed_len
  let unhashed_len =
    (body[unhashed_len_pos].to_int() << 8) |
    body[unhashed_len_pos + 1].to_int()
  let after_unhashed = unhashed_len_pos + 2 + unhashed_len
  if after_unhashed + 2 > body.length() {
    raise PacketTooShort("unhashed subpacket area / left16")
  }
  let left16 =
    (body[after_unhashed].to_uint() << 8) | body[after_unhashed + 1].to_uint()
  let sig_material_start = after_unhashed + 2
  let signature_material = bytes_slice(
    body,
    sig_material_start,
    body.length(),
  )
  {
    version,
    sig_type,
    pubkey_algo,
    hash_algo,
    hashed_subpackets_raw,
    hashed_subpackets_body,
    left16,
    signature_material,
  }
}

///|
fn _unused_field(_p : PgpSignature) -> Unit {
  let _ = _p.hashed_subpackets_body
  let _ = _p.left16
}

///|
/// Build the digest to be verified for a Signature Packet over `message`.
///
/// Per RFC 4880 §5.2.4:
///   data_to_hash = message || hashed_subpackets_raw || trailer
///   trailer       = 0x04 || 0xFF || uint32_be(length_of_hashed_subpackets_raw)
///   digest        = H_hash_algo(data_to_hash)
pub fn compute_signature_digest(
  sig : PgpSignature,
  message : Bytes,
) -> Bytes raise PgpError {
  let prelude = sig.hashed_subpackets_raw
  // Concat message || prelude || trailer in one buffer.
  let prelude_len = prelude.length()
  let total = message.length() + prelude_len + 6
  let buf = FixedArray::make(total, b'\x00')
  for i = 0; i < message.length(); i = i + 1 {
    buf[i] = message[i]
  }
  for i = 0; i < prelude_len; i = i + 1 {
    buf[message.length() + i] = prelude[i]
  }
  // Trailer: 04 FF <uint32 BE of prelude_len>.
  let off = message.length() + prelude_len
  buf[off] = b'\x04'
  buf[off + 1] = b'\xff'
  buf[off + 2] = ((prelude_len.to_uint() >> 24) & 0xffU).to_byte()
  buf[off + 3] = ((prelude_len.to_uint() >> 16) & 0xffU).to_byte()
  buf[off + 4] = ((prelude_len.to_uint() >> 8) & 0xffU).to_byte()
  buf[off + 5] = (prelude_len.to_uint() & 0xffU).to_byte()
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

///|
// Returns the expected digest length for a given hash algorithm ID.
fn hash_len(algo : Int) -> Int raise PgpError {
  if algo == hash_sha256 {
    32
  } else if algo == hash_sha384 {
    48
  } else if algo == hash_sha512 {
    64
  } else {
    raise UnsupportedHashAlgo(algo)
  }
}
