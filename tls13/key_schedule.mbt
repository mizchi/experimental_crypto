// TLS 1.3 key schedule (RFC 8446 §7.1) and the HKDF building blocks it needs
// (RFC 5869 + the TLS-specific HKDF-Expand-Label / Derive-Secret).
//
// This is the pure-crypto core of a TLS 1.3 client: it turns the (EC)DHE shared
// secret and the handshake transcript hashes into the traffic secrets, write
// keys/IVs, and Finished keys. Record framing, handshake message parsing, and
// socket I/O live elsewhere / are the caller's responsibility.
//
// Both SHA-256 (TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256) and
// SHA-384 (TLS_AES_256_GCM_SHA384) cipher-suite hashes are supported.

///|
/// Hash used by a TLS 1.3 cipher suite's key schedule.
pub(all) enum Hash {
  Sha256
  Sha384
} derive(Eq, Debug)

///|
/// Output length of the hash, in bytes (32 for SHA-256, 48 for SHA-384).
pub fn Hash::hash_len(self : Hash) -> Int {
  match self {
    Sha256 => 32
    Sha384 => 48
  }
}

///|
fn zeros(n : Int) -> Bytes {
  Bytes::makei(n, fn(_) { b'\x00' })
}

///|
fn ascii_bytes(s : String) -> Bytes {
  // TLS label strings are ASCII; map each code unit to one byte.
  let buf = Buffer()
  for c in s {
    buf.write_byte((c.to_int() & 0xff).to_byte())
  }
  buf.to_bytes()
}

///|
/// Transcript hash (or any plain hash) of `data` under the suite hash.
pub fn Hash::transcript_hash(self : Hash, data : Bytes) -> Bytes {
  match self {
    Sha256 => @hash.sha256(data)
    Sha384 => @hash.sha384(data)
  }
}

///|
fn Hash::hmac(self : Hash, key : Bytes, msg : Bytes) -> Bytes {
  match self {
    Sha256 => @hash.hmac_sha256(key, msg)
    Sha384 => @hash.hmac_sha384(key, msg)
  }
}

///|
/// HKDF-Extract (RFC 5869 §2.2). An empty `salt` is treated as `hash_len`
/// zero bytes, matching TLS 1.3's `0` salt inputs.
pub fn Hash::hkdf_extract(self : Hash, salt : Bytes, ikm : Bytes) -> Bytes {
  let effective_salt = if salt.length() == 0 {
    zeros(self.hash_len())
  } else {
    salt
  }
  self.hmac(effective_salt, ikm)
}

///|
/// HKDF-Expand (RFC 5869 §2.3). `length` must satisfy `0 <= length <= 255 * HashLen`.
pub fn Hash::hkdf_expand(
  self : Hash,
  prk : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes {
  if length == 0 {
    return b""
  }
  let hlen = self.hash_len()
  if length < 0 || length > 255 * hlen {
    abort("hkdf_expand: invalid length " + length.to_string())
  }
  let n = (length + hlen - 1) / hlen
  let out = Buffer()
  let mut prev = b""
  for i = 1; i <= n; i = i + 1 {
    let msg = Buffer()
    msg.write_bytes(prev)
    msg.write_bytes(info)
    msg.write_byte(i.to_byte())
    prev = self.hmac(prk, msg.to_bytes())
    out.write_bytes(prev)
  }
  let full = out.to_bytes()
  Bytes::makei(length, fn(j) { full[j] })
}

///|
/// HKDF-Expand-Label (RFC 8446 §7.1):
///
/// ```text
/// struct {
///   uint16 length = Length;
///   opaque label<7..255> = "tls13 " + Label;
///   opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
pub fn Hash::hkdf_expand_label(
  self : Hash,
  secret : Bytes,
  label : String,
  context : Bytes,
  length : Int,
) -> Bytes {
  let full_label = ascii_bytes("tls13 " + label)
  if full_label.length() > 255 || context.length() > 255 {
    abort("hkdf_expand_label: label/context too long")
  }
  let hl = Buffer()
  hl.write_byte(((length >> 8) & 0xff).to_byte())
  hl.write_byte((length & 0xff).to_byte())
  hl.write_byte(full_label.length().to_byte())
  hl.write_bytes(full_label)
  hl.write_byte(context.length().to_byte())
  hl.write_bytes(context)
  self.hkdf_expand(secret, hl.to_bytes(), length)
}

///|
/// Derive-Secret (RFC 8446 §7.1). `transcript` is the already-computed
/// Transcript-Hash of the relevant handshake messages (use `b""`'s hash, i.e.
/// `transcript_hash(h, b"")`, for the empty-context derivations).
pub fn Hash::derive_secret(
  self : Hash,
  secret : Bytes,
  label : String,
  transcript : Bytes,
) -> Bytes {
  self.hkdf_expand_label(secret, label, transcript, self.hash_len())
}

// ─── key schedule chain (RFC 8446 §7.1) ──────────────────────────────────

///|
/// Early Secret = HKDF-Extract(0, PSK). Pass `hash_len` zero bytes (or
/// `b""`-derived zeros) as `psk` when no PSK is used.
pub fn Hash::early_secret(self : Hash, psk : Bytes) -> Bytes {
  let ikm = if psk.length() == 0 { zeros(self.hash_len()) } else { psk }
  self.hkdf_extract(b"", ikm)
}

///|
// The "derived" transition between schedule stages:
// Derive-Secret(Secret, "derived", "").
fn Hash::derived(self : Hash, secret : Bytes) -> Bytes {
  self.derive_secret(secret, "derived", self.transcript_hash(b""))
}

///|
/// Handshake Secret = HKDF-Extract(Derive-Secret(Early, "derived", ""), (EC)DHE).
pub fn Hash::handshake_secret(
  self : Hash,
  early : Bytes,
  ecdhe : Bytes,
) -> Bytes {
  self.hkdf_extract(self.derived(early), ecdhe)
}

///|
/// Master Secret = HKDF-Extract(Derive-Secret(Handshake, "derived", ""), 0).
pub fn Hash::master_secret(self : Hash, handshake : Bytes) -> Bytes {
  self.hkdf_extract(self.derived(handshake), zeros(self.hash_len()))
}

///|
/// client_handshake_traffic_secret: Derive-Secret(Handshake, "c hs traffic",
/// ClientHello..ServerHello). `transcript` is that transcript hash.
pub fn Hash::client_handshake_traffic_secret(
  self : Hash,
  handshake : Bytes,
  transcript : Bytes,
) -> Bytes {
  self.derive_secret(handshake, "c hs traffic", transcript)
}

///|
/// server_handshake_traffic_secret: Derive-Secret(Handshake, "s hs traffic",
/// ClientHello..ServerHello).
pub fn Hash::server_handshake_traffic_secret(
  self : Hash,
  handshake : Bytes,
  transcript : Bytes,
) -> Bytes {
  self.derive_secret(handshake, "s hs traffic", transcript)
}

///|
/// client_application_traffic_secret_0: Derive-Secret(Master, "c ap traffic",
/// ClientHello..server Finished).
pub fn Hash::client_application_traffic_secret(
  self : Hash,
  master : Bytes,
  transcript : Bytes,
) -> Bytes {
  self.derive_secret(master, "c ap traffic", transcript)
}

///|
/// server_application_traffic_secret_0: Derive-Secret(Master, "s ap traffic",
/// ClientHello..server Finished).
pub fn Hash::server_application_traffic_secret(
  self : Hash,
  master : Bytes,
  transcript : Bytes,
) -> Bytes {
  self.derive_secret(master, "s ap traffic", transcript)
}

///|
/// exporter_master_secret: Derive-Secret(Master, "exp master",
/// ClientHello..server Finished).
pub fn Hash::exporter_master_secret(
  self : Hash,
  master : Bytes,
  transcript : Bytes,
) -> Bytes {
  self.derive_secret(master, "exp master", transcript)
}

///|
/// resumption_master_secret: Derive-Secret(Master, "res master",
/// ClientHello..client Finished).
pub fn Hash::resumption_master_secret(
  self : Hash,
  master : Bytes,
  transcript : Bytes,
) -> Bytes {
  self.derive_secret(master, "res master", transcript)
}

///|
/// Per-record AEAD write key: HKDF-Expand-Label(Secret, "key", "", key_len).
pub fn Hash::write_key(self : Hash, secret : Bytes, key_len : Int) -> Bytes {
  self.hkdf_expand_label(secret, "key", b"", key_len)
}

///|
/// Per-record AEAD write IV: HKDF-Expand-Label(Secret, "iv", "", 12).
pub fn Hash::write_iv(self : Hash, secret : Bytes) -> Bytes {
  self.hkdf_expand_label(secret, "iv", b"", 12)
}

///|
/// Finished key: HKDF-Expand-Label(BaseKey, "finished", "", Hash.length).
/// The Finished MAC is HMAC(finished_key, Transcript-Hash(...)).
pub fn Hash::finished_key(self : Hash, base_key : Bytes) -> Bytes {
  self.hkdf_expand_label(base_key, "finished", b"", self.hash_len())
}
