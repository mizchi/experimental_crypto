// TLS 1.2 AEAD (AES-GCM) record protection (RFC 5246 §6.2.3.3, RFC 5288).
//
// For the GCM cipher suites the record layer differs from TLS 1.3:
//
//   * The AEAD nonce is `salt (4-byte fixed IV from the key_block) ||
//     nonce_explicit (8 bytes)`. The 8-byte nonce_explicit is transmitted in
//     the clear at the front of the record fragment. We use the 64-bit record
//     sequence number as the explicit nonce (the common choice, e.g. OpenSSL);
//     it only has to be unique per key, which the monotonic seq guarantees.
//
//   * additional_data = seq_num(8) || type(1) || version(2) || length(2),
//     where `length` is the length of the *plaintext* fragment
//     (TLSCompressed.length), NOT the ciphertext.
//
//   * On the wire: type(1) || version(2) || length(2) || nonce_explicit(8) ||
//     ciphertext || tag(16), where the record `length` field counts
//     `8 + ciphertext + 16`.

///|
/// TLS 1.2 content types (RFC 5246 §6.2.1).
pub(all) enum ContentType {
  ChangeCipherSpec
  Alert
  Handshake
  ApplicationData
} derive(Eq, Debug)

///|
pub fn ContentType::to_int(self : ContentType) -> Int {
  match self {
    ChangeCipherSpec => 20
    Alert => 21
    Handshake => 22
    ApplicationData => 23
  }
}

///|
pub fn ContentType::from_int(v : Int) -> ContentType? {
  match v {
    20 => Some(ChangeCipherSpec)
    21 => Some(Alert)
    22 => Some(Handshake)
    23 => Some(ApplicationData)
    _ => None
  }
}

///|
pub suberror RecordError {
  ShortRecord
  UnexpectedContentType(Int)
  VersionMismatch(Int)
  LengthMismatch
  BadNonceCipher
  Aead(@aead.AeadError)
} derive(Debug)

///|
/// Directional GCM record keys: the AEAD algorithm, the 16/32-byte encryption
/// key, and the 4-byte fixed IV (salt) — all sliced out of the `key_block`.
pub struct GcmKeys {
  alg : @aead.Algorithm
  key : Bytes
  fixed_iv : Bytes
}

///|
/// Build directional GCM keys, validating the key / IV lengths against `alg`.
pub fn GcmKeys::new(
  alg : @aead.Algorithm,
  key : Bytes,
  fixed_iv : Bytes,
) -> GcmKeys raise RecordError {
  if key.length() != alg.key_size() || fixed_iv.length() != 4 {
    raise BadNonceCipher
  }
  { alg, key, fixed_iv }
}

///|
/// The AEAD encryption key.
pub fn GcmKeys::key_bytes(self : GcmKeys) -> Bytes {
  self.key
}

///|
/// The 4-byte fixed IV (salt) prefixed to every record nonce.
pub fn GcmKeys::iv_bytes(self : GcmKeys) -> Bytes {
  self.fixed_iv
}

///|
fn seq_bytes(seq : UInt64) -> Bytes {
  Bytes::makei(8, fn(i) { ((seq >> ((7 - i) * 8)) & 0xffUL).to_int().to_byte() })
}

///|
// additional_data = seq(8) || type(1) || 0x03 0x03 || plaintext_len(2).
fn gcm_aad(seq : UInt64, ct : ContentType, plaintext_len : Int) -> Bytes {
  let s = seq_bytes(seq)
  Bytes::makei(13, fn(i) {
    if i < 8 {
      s[i]
    } else if i == 8 {
      ct.to_int().to_byte()
    } else if i == 9 {
      b'\x03'
    } else if i == 10 {
      b'\x03'
    } else if i == 11 {
      ((plaintext_len >> 8) & 0xff).to_byte()
    } else {
      (plaintext_len & 0xff).to_byte()
    }
  })
}

///|
fn gcm_nonce(fixed_iv : Bytes, seq : UInt64) -> Bytes {
  let s = seq_bytes(seq)
  Bytes::makei(12, fn(i) { if i < 4 { fixed_iv[i] } else { s[i - 4] } })
}

///|
/// Seal one TLS 1.2 GCM record and return the full on-wire record
/// (`type || version || length || nonce_explicit || ciphertext || tag`).
/// `seq` is both the AEAD sequence number for the AAD and the explicit nonce.
pub fn seal_gcm_record(
  keys : GcmKeys,
  seq : UInt64,
  content_type : ContentType,
  plaintext : Bytes,
) -> Bytes raise RecordError {
  let nonce = gcm_nonce(keys.fixed_iv, seq)
  let aad = gcm_aad(seq, content_type, plaintext.length())
  let enc = @aead.seal(keys.alg, keys.key, nonce, aad, plaintext) catch {
    e => raise Aead(e)
  }
  // fragment = nonce_explicit(8) || enc(ciphertext || tag)
  let explicit = seq_bytes(seq)
  let frag_len = 8 + enc.length()
  Bytes::makei(5 + frag_len, fn(i) {
    if i == 0 {
      content_type.to_int().to_byte()
    } else if i == 1 {
      b'\x03'
    } else if i == 2 {
      b'\x03'
    } else if i == 3 {
      ((frag_len >> 8) & 0xff).to_byte()
    } else if i == 4 {
      (frag_len & 0xff).to_byte()
    } else if i < 13 {
      explicit[i - 5]
    } else {
      enc[i - 13]
    }
  })
}

///|
/// Open one TLS 1.2 GCM record. Verifies the version and tag, and returns the
/// `(ContentType, plaintext)`. `seq` must match the sender's sequence number.
pub fn open_gcm_record(
  keys : GcmKeys,
  seq : UInt64,
  record : Bytes,
) -> (ContentType, Bytes) raise RecordError {
  if record.length() < 5 {
    raise ShortRecord
  }
  let ct = match ContentType::from_int(record[0].to_int()) {
    Some(t) => t
    None => raise UnexpectedContentType(record[0].to_int())
  }
  if record[1] != b'\x03' || record[2] != b'\x03' {
    raise VersionMismatch((record[1].to_int() << 8) | record[2].to_int())
  }
  let frag_len = (record[3].to_int() << 8) | record[4].to_int()
  if record.length() != 5 + frag_len {
    raise LengthMismatch
  }
  // fragment = nonce_explicit(8) || ciphertext || tag(16)
  let tag_len = keys.alg.tag_size()
  if frag_len < 8 + tag_len {
    raise ShortRecord
  }
  // The peer chooses the 8-byte explicit nonce; read it off the wire rather
  // than assuming it equals `seq` (it usually does, but the spec doesn't
  // require it). The AAD, however, always uses our tracked `seq`.
  let nonce = Bytes::makei(12, fn(i) {
    if i < 4 {
      keys.fixed_iv[i]
    } else {
      record[5 + (i - 4)]
    }
  })
  let ct_tag_len = frag_len - 8
  let ct_tag = Bytes::makei(ct_tag_len, fn(i) { record[5 + 8 + i] })
  let plaintext_len = ct_tag_len - tag_len
  let aad = gcm_aad(seq, ct, plaintext_len)
  let pt = @aead.open(keys.alg, keys.key, nonce, aad, ct_tag) catch {
    e => raise Aead(e)
  }
  (ct, pt)
}
