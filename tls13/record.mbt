// TLS 1.3 record layer (RFC 8446 §5).
//
// Encrypted records carry a TLSInnerPlaintext (content || real ContentType ||
// zero padding) sealed with the suite AEAD. The 5-byte record header is both
// emitted on the wire and used as the AEAD additional data. The per-record
// nonce is the record sequence number, left-padded to the IV length and XORed
// with the static write IV (§5.3). Sequence numbers start at 0 and increment
// per record under a given key; they reset on each key change. This module is
// pure: the caller owns the sequence counter and the socket.

///|
/// TLS record ContentType (RFC 8446 §5.1).
pub(all) enum ContentType {
  ChangeCipherSpec
  Alert
  Handshake
  ApplicationData
} derive(Eq, Debug)

///|
pub fn ContentType::to_byte(self : ContentType) -> Byte {
  match self {
    ChangeCipherSpec => b'\x14' // 20
    Alert => b'\x15' // 21
    Handshake => b'\x16' // 22
    ApplicationData => b'\x17' // 23
  }
}

///|
fn ContentType::from_int(v : Int) -> ContentType? {
  match v {
    20 => Some(ChangeCipherSpec)
    21 => Some(Alert)
    22 => Some(Handshake)
    23 => Some(ApplicationData)
    _ => None
  }
}

///|
/// TLS 1.3 cipher suite: bundles the AEAD, the key-schedule hash, and the key
/// length. (RFC 8446 §B.4; the suite hash also fixes the HKDF used elsewhere.)
pub(all) enum CipherSuite {
  Aes128GcmSha256
  Aes256GcmSha384
  ChaCha20Poly1305Sha256
} derive(Eq, Debug)

///|
pub fn CipherSuite::hash(self : CipherSuite) -> Hash {
  match self {
    Aes128GcmSha256 => Sha256
    Aes256GcmSha384 => Sha384
    ChaCha20Poly1305Sha256 => Sha256
  }
}

///|
pub fn CipherSuite::aead(self : CipherSuite) -> @aead.Algorithm {
  match self {
    Aes128GcmSha256 => Aes128Gcm
    Aes256GcmSha384 => Aes256Gcm
    ChaCha20Poly1305Sha256 => ChaCha20Poly1305
  }
}

///|
/// AEAD key length in bytes (16 for AES-128, 32 for AES-256 / ChaCha20).
pub fn CipherSuite::key_len(self : CipherSuite) -> Int {
  match self {
    Aes128GcmSha256 => 16
    Aes256GcmSha384 => 32
    ChaCha20Poly1305Sha256 => 32
  }
}

///|
pub suberror RecordError {
  ShortRecord
  // Encrypted records use outer opaque_type = application_data(23); anything
  // else is rejected before AEAD.
  UnexpectedOuterType(Int)
  // The decrypted TLSInnerPlaintext was all-zero, so it has no ContentType.
  MissingContentType
  // The recovered real ContentType byte is not a known value.
  BadContentType(Int)
  // AEAD open failed (tag mismatch) or seal/length error.
  Aead(@aead.AeadError)
} derive(Debug)

///|
/// Per-record nonce (RFC 8446 §5.3): the 64-bit sequence number, left-padded
/// with zeros to the IV length, XORed with the static `write_iv`.
pub fn record_nonce(write_iv : Bytes, seq : UInt64) -> Bytes {
  let n = write_iv.length()
  Bytes::makei(n, fn(i) {
    // Sequence number occupies the trailing 8 bytes, big-endian.
    let from_end = n - 1 - i
    let seq_byte = if from_end < 8 {
      ((seq >> (from_end * 8)) & 0xffUL).to_int()
    } else {
      0
    }
    (seq_byte ^ write_iv[i].to_int()).to_byte()
  })
}

///|
// 5-byte record header / AEAD additional_data:
//   opaque_type(application_data=23) || legacy_record_version(0x0303) || u16(len)
// where `len` is the length of the encrypted_record (ciphertext + tag).
fn record_header(ciphertext_len : Int) -> Bytes {
  Bytes::makei(5, fn(i) {
    match i {
      0 => b'\x17'
      1 => b'\x03'
      2 => b'\x03'
      3 => ((ciphertext_len >> 8) & 0xff).to_byte()
      _ => (ciphertext_len & 0xff).to_byte()
    }
  })
}

///|
/// Seal one TLS 1.3 record. Builds TLSInnerPlaintext = `content` || the real
/// `content_type` byte || `padding` zero bytes, AEAD-seals it under the
/// per-record nonce with the record header as additional data, and returns the
/// full on-wire TLSCiphertext record (header || ciphertext || tag).
pub fn seal_record(
  suite : CipherSuite,
  write_key : Bytes,
  write_iv : Bytes,
  seq : UInt64,
  content_type : ContentType,
  content : Bytes,
  padding? : Int = 0,
) -> Bytes raise RecordError {
  let pad = if padding < 0 { 0 } else { padding }
  let inner_len = content.length() + 1 + pad
  let inner = Bytes::makei(inner_len, fn(i) {
    if i < content.length() {
      content[i]
    } else if i == content.length() {
      content_type.to_byte()
    } else {
      b'\x00'
    }
  })
  let tag_len = suite.aead().tag_size()
  let ciphertext_len = inner_len + tag_len
  let nonce = record_nonce(write_iv, seq)
  let header = record_header(ciphertext_len)
  let enc = @aead.seal(suite.aead(), write_key, nonce, header, inner) catch {
    e => raise Aead(e)
  }
  Bytes::makei(header.length() + enc.length(), fn(i) {
    if i < header.length() {
      header[i]
    } else {
      enc[i - header.length()]
    }
  })
}

///|
/// Open one TLS 1.3 record. Verifies the AEAD tag, strips the zero padding,
/// and returns the real `ContentType` plus the decrypted content. Raises on a
/// short/ill-typed record, a tag mismatch, or all-zero / unknown inner type.
pub fn open_record(
  suite : CipherSuite,
  write_key : Bytes,
  write_iv : Bytes,
  seq : UInt64,
  record : Bytes,
) -> (ContentType, Bytes) raise RecordError {
  if record.length() < 5 {
    raise ShortRecord
  }
  if record[0] != b'\x17' {
    raise UnexpectedOuterType(record[0].to_int())
  }
  let declared = (record[3].to_int() << 8) | record[4].to_int()
  if record.length() != 5 + declared {
    raise ShortRecord
  }
  let header = Bytes::makei(5, fn(i) { record[i] })
  let ciphertext = Bytes::makei(declared, fn(i) { record[5 + i] })
  let nonce = record_nonce(write_iv, seq)
  let inner = @aead.open(suite.aead(), write_key, nonce, header, ciphertext) catch {
    e => raise Aead(e)
  }
  // Strip trailing zero padding; the last non-zero byte is the real ContentType.
  let mut idx = inner.length() - 1
  while idx >= 0 && inner[idx] == b'\x00' {
    idx = idx - 1
  }
  if idx < 0 {
    raise MissingContentType
  }
  let real_type = match ContentType::from_int(inner[idx].to_int()) {
    Some(t) => t
    None => raise BadContentType(inner[idx].to_int())
  }
  let content = Bytes::makei(idx, fn(i) { inner[i] })
  (real_type, content)
}
