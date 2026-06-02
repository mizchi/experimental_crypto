// QUIC v1 packet protection crypto (RFC 9001) — the Initial-packet key
// derivation, AEAD payload protection, and header protection that HTTP/3 sits
// on. Handshake / 1-RTT keys come from the TLS 1.3 key schedule (mizchi/tls13);
// this module covers the QUIC-specific Initial secrets (derived from the
// client's Destination Connection ID and a version salt) and the wire-protection
// primitives that apply to every packet-number space.
//
// AEAD here is AES-128-GCM (the Initial AEAD, RFC 9001 §5.2) and header
// protection is the AES variant (§5.4.3). ChaCha20-based protection is not
// covered yet.

///|
pub suberror QuicError {
  Aead(@aead.AeadError)
  BadLength(String)
} derive(Debug)

///|
/// QUIC v1 Initial salt (RFC 9001 §5.2).
let initial_salt : Bytes = b"\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a"

///|
fn u16be(v : Int) -> Bytes {
  Bytes::makei(2, fn(i) {
    if i == 0 {
      ((v >> 8) & 0xff).to_byte()
    } else {
      (v & 0xff).to_byte()
    }
  })
}

///|
fn concat(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for p in parts {
    total += p.length()
  }
  let out = FixedArray::make(total, b'\x00')
  let mut off = 0
  for p in parts {
    for i in 0..<p.length() {
      out[off + i] = p[i]
    }
    off += p.length()
  }
  Bytes::makei(total, fn(i) { out[i] })
}

///|
fn ascii(s : String) -> Bytes {
  Bytes::makei(s.length(), fn(i) {
    (s.get_char(i).unwrap().to_int() & 0xff).to_byte()
  })
}

///|
/// TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1) with an empty context, as QUIC
/// uses it. `label` is the bare label; the "tls13 " prefix is added here.
pub fn expand_label(secret : Bytes, label : String, length : Int) -> Bytes {
  let full = ascii("tls13 " + label)
  let info = concat([
    u16be(length),
    Bytes::makei(1, fn(_i) { full.length().to_byte() }),
    full,
    b"\x00", // zero-length context
  ])
  @hkdf.expand(@hkdf.Sha256, secret, info, length) catch {
    _ => abort("quic expand_label")
  }
}

///|
/// The packet-protection keys for one direction / packet-number space.
pub struct PacketKeys {
  secret : Bytes
  key : Bytes
  iv : Bytes
  hp : Bytes
}

///|
pub fn PacketKeys::key_bytes(self : PacketKeys) -> Bytes {
  self.key
}

///|
pub fn PacketKeys::iv_bytes(self : PacketKeys) -> Bytes {
  self.iv
}

///|
pub fn PacketKeys::hp_bytes(self : PacketKeys) -> Bytes {
  self.hp
}

///|
pub fn PacketKeys::secret_bytes(self : PacketKeys) -> Bytes {
  self.secret
}

///|
// Derive key/iv/hp from a traffic secret (RFC 9001 §5.1, AES-128-GCM sizes).
fn packet_keys_from_secret(secret : Bytes) -> PacketKeys {
  {
    secret,
    key: expand_label(secret, "quic key", 16),
    iv: expand_label(secret, "quic iv", 12),
    hp: expand_label(secret, "quic hp", 16),
  }
}

///|
/// Derive the client and server Initial packet keys from the client's
/// Destination Connection ID (RFC 9001 §5.2). Returns `(client, server)`.
pub fn initial_keys(dst_connection_id : Bytes) -> (PacketKeys, PacketKeys) {
  let initial_secret = @hkdf.extract(
    @hkdf.Sha256,
    initial_salt,
    dst_connection_id,
  )
  let client = packet_keys_from_secret(
    expand_label(initial_secret, "client in", 32),
  )
  let server = packet_keys_from_secret(
    expand_label(initial_secret, "server in", 32),
  )
  (client, server)
}

///|
/// The per-packet AEAD nonce: the 12-byte IV XORed with the 62-bit packet
/// number, right-aligned (RFC 9001 §5.3).
pub fn packet_nonce(
  iv : Bytes,
  packet_number : UInt64,
) -> Bytes raise QuicError {
  if iv.length() != 12 {
    raise BadLength("iv must be 12 bytes")
  }
  Bytes::makei(12, fn(i) {
    let from_end = 12 - 1 - i
    let pn_byte = if from_end < 8 {
      ((packet_number >> (from_end * 8)) & 0xffUL).to_int()
    } else {
      0
    }
    (iv[i].to_int() ^ pn_byte).to_byte()
  })
}

///|
/// AEAD-protect a packet payload (AES-128-GCM). `header` is the packet header
/// used as additional data; `packet_number` selects the nonce.
pub fn seal_payload(
  keys : PacketKeys,
  packet_number : UInt64,
  header : Bytes,
  payload : Bytes,
) -> Bytes raise QuicError {
  let nonce = packet_nonce(keys.iv, packet_number)
  @aead.seal(@aead.Aes128Gcm, keys.key, nonce, header, payload) catch {
    e => raise Aead(e)
  }
}

///|
/// AEAD-open a protected packet payload. Raises on tag failure.
pub fn open_payload(
  keys : PacketKeys,
  packet_number : UInt64,
  header : Bytes,
  sealed_pkt : Bytes,
) -> Bytes raise QuicError {
  let nonce = packet_nonce(keys.iv, packet_number)
  @aead.open(@aead.Aes128Gcm, keys.key, nonce, header, sealed_pkt) catch {
    e => raise Aead(e)
  }
}

///|
/// Header-protection mask for the AES suites (RFC 9001 §5.4.3): the first 5
/// bytes of AES-ECB(hp_key, sample). `sample` is 16 bytes taken from the packet
/// ciphertext. The caller XORs mask[0] into the header's protected bits and
/// mask[1..5] into the (1–4 byte) packet-number field.
pub fn header_protection_mask(
  hp_key : Bytes,
  sample : Bytes,
) -> Bytes raise QuicError {
  if sample.length() != 16 {
    raise BadLength("sample must be 16 bytes")
  }
  let block = @aead.aes_block_encrypt(hp_key, sample) catch {
    e => raise Aead(e)
  }
  Bytes::makei(5, fn(i) { block[i] })
}
