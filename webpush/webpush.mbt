// Web Push message decryption: RFC 8291 (Message Encryption for Web Push) over
// the RFC 8188 `aes128gcm` Encrypted Content-Encoding.
//
// A subscriber (user agent) receives a push body encrypted by an application
// server to the subscriber's P-256 key pair + shared auth secret. The body
// carries the server's ephemeral public key (as the RFC 8188 `keyid`) and the
// random salt; the subscriber's private key + auth secret recover the content.
//
// Body layout (RFC 8188 §2.1):
//   salt(16) || rs(uint32) || idlen(1) || keyid(idlen) || record(s)
// For Web Push, `keyid` is the server's 65-byte uncompressed P-256 public key
// and there is normally a single record.

///|
pub suberror WebPushError {
  Truncated(String)
  BadServerKey
  DecryptFailed
  Malformed(String)
} derive(Debug)

///|
fn be_u32(b : Bytes, off : Int) -> Int {
  (b[off].to_int() << 24) |
  (b[off + 1].to_int() << 16) |
  (b[off + 2].to_int() << 8) |
  b[off + 3].to_int()
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
// RFC 8291 §3.4: derive the RFC 8188 input keying material from the ECDH
// shared secret, the auth secret, and the two public keys.
//   ikm = HKDF(auth_secret, ecdh_secret, "WebPush: info"||0x00||ua||as, 32)
fn derive_ikm(
  ecdh_secret : Bytes,
  auth_secret : Bytes,
  ua_public : Bytes,
  as_public : Bytes,
) -> Bytes {
  let key_info = concat([ascii("WebPush: info"), b"\x00", ua_public, as_public])
  let prk = @hkdf.extract(@hkdf.Sha256, auth_secret, ecdh_secret)
  @hkdf.expand(@hkdf.Sha256, prk, key_info, 32) catch {
    _ => abort("WebPush IKM expand")
  }
}

///|
// Per-record nonce: nonce_base XOR I2OSP(seq, 12) over the trailing bytes
// (RFC 8188 §2.3).
fn record_nonce(nonce_base : Bytes, seq : Int) -> Bytes {
  Bytes::makei(12, fn(i) {
    // seq occupies the low 6 bytes; XOR the big-endian counter into the tail.
    let shift = (11 - i) * 8
    let seq_byte = if shift < 48 { (seq >> shift) & 0xff } else { 0 }
    (nonce_base[i].to_int() ^ seq_byte).to_byte()
  })
}

///|
// Strip RFC 8188 padding: trailing 0x00 bytes then a single delimiter byte
// (0x02 on the final record, 0x01 otherwise).
fn unpad(record_pt : Bytes, is_last : Bool) -> Bytes raise WebPushError {
  let mut i = record_pt.length() - 1
  while i >= 0 && record_pt[i] == b'\x00' {
    i = i - 1
  }
  if i < 0 {
    raise Malformed("record has no delimiter")
  }
  let delim = record_pt[i].to_int()
  let want = if is_last { 0x02 } else { 0x01 }
  if delim != want {
    raise Malformed("bad RFC 8188 padding delimiter")
  }
  Bytes::makei(i, fn(j) { record_pt[j] })
}

///|
/// Decrypt a Web Push `aes128gcm` body addressed to the subscriber.
///
/// - `body`: the full RFC 8188 `aes128gcm` content-encoding body.
/// - `ua_private` / `ua_public`: the subscriber's P-256 key pair (32-byte
///   scalar / 65-byte uncompressed point).
/// - `auth_secret`: the 16-byte shared authentication secret.
///
/// Returns the decrypted plaintext (the concatenation of all record contents).
pub fn decrypt(
  body : Bytes,
  ua_private : Bytes,
  ua_public : Bytes,
  auth_secret : Bytes,
) -> Bytes raise WebPushError {
  if body.length() < 21 {
    raise Truncated("aes128gcm header")
  }
  let salt = Bytes::makei(16, fn(i) { body[i] })
  let rs = be_u32(body, 16)
  let idlen = body[20].to_int()
  if rs < 18 {
    raise Malformed("record size too small")
  }
  if body.length() < 21 + idlen {
    raise Truncated("keyid")
  }
  let as_public = Bytes::makei(idlen, fn(i) { body[21 + i] })
  // ECDH(ua_private, as_public) → 32-byte X coordinate.
  let sk = @p256.PrivateKey::from_bytes(ua_private) catch {
    _ => raise BadServerKey
  }
  let pk = @p256.PublicKey::from_uncompressed(as_public) catch {
    _ => raise BadServerKey
  }
  let ecdh_secret = sk.ecdh(pk)
  // RFC 8291 IKM, then RFC 8188 PRK / CEK / nonce.
  let ikm = derive_ikm(ecdh_secret, auth_secret, ua_public, as_public)
  let prk = @hkdf.extract(@hkdf.Sha256, salt, ikm)
  let cek = @hkdf.expand(
    @hkdf.Sha256,
    prk,
    concat([ascii("Content-Encoding: aes128gcm"), b"\x00"]),
    16,
  ) catch {
    _ => raise DecryptFailed
  }
  let nonce_base = @hkdf.expand(
    @hkdf.Sha256,
    prk,
    concat([ascii("Content-Encoding: nonce"), b"\x00"]),
    12,
  ) catch {
    _ => raise DecryptFailed
  }
  // Split the remaining body into `rs`-sized records and decrypt each.
  let header_len = 21 + idlen
  let total = body.length() - header_len
  if total <= 0 {
    raise Truncated("no records")
  }
  let out : Array[Bytes] = []
  let mut off = header_len
  let mut seq = 0
  while off < body.length() {
    let take = if body.length() - off < rs { body.length() - off } else { rs }
    let record = Bytes::makei(take, fn(i) { body[off + i] })
    let nonce = record_nonce(nonce_base, seq)
    let pt = @aead.open(@aead.Aes128Gcm, cek, nonce, b"", record) catch {
      _ => raise DecryptFailed
    }
    off = off + take
    let is_last = off >= body.length()
    out.push(unpad(pt, is_last))
    seq = seq + 1
  }
  concat(out)
}
