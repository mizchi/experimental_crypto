// Certificate Transparency — Signed Certificate Timestamp (SCT) verification
// (RFC 6962). Parses a SignedCertificateTimestampList (as carried in the X.509
// extension 1.3.6.1.4.1.11129.2.4.2, in a TLS extension, or via OCSP) and
// verifies each SCT's signature against a CT log's public key.
//
// The signed structure (RFC 6962 §3.2) is:
//   digitally-signed struct {
//     Version    sct_version = v1(0);
//     SignatureType signature_type = certificate_timestamp(0);
//     uint64     timestamp;
//     LogEntryType entry_type;          // x509_entry(0) | precert_entry(1)
//     select(entry_type) signed_entry;  // x509: ASN.1Cert; precert: PreCert
//     CtExtensions extensions;
//   }
// The caller supplies the `signed_entry` (built with `x509_entry` /
// `precert_entry`) since reconstructing the precertificate TBS (stripping the
// SCT-list + poison extensions) is a certificate-shape concern, not a crypto
// one.

///|
pub suberror CtError {
  Truncated(String)
  Malformed(String)
  Pkix(@pkix.PkixError)
  PkixVerify(@pkix_verify.PkixVerifyError)
} derive(Debug)

///|
/// A parsed Signed Certificate Timestamp (RFC 6962 §3.2).
pub struct Sct {
  version : Int
  log_id : Bytes // 32-byte SHA-256 of the log's SubjectPublicKeyInfo
  timestamp : UInt64
  extensions : Bytes
  sig_scheme : Int // SignatureAndHashAlgorithm (hash<<8 | sig)
  signature : Bytes
}

///|
pub fn Sct::version(self : Sct) -> Int {
  self.version
}

///|
pub fn Sct::log_id(self : Sct) -> Bytes {
  self.log_id
}

///|
pub fn Sct::timestamp(self : Sct) -> UInt64 {
  self.timestamp
}

///|
pub fn Sct::sig_scheme(self : Sct) -> Int {
  self.sig_scheme
}

///|
priv struct Reader {
  data : Bytes
  mut pos : Int
}

///|
fn Reader::u8(self : Reader, what : String) -> Int raise CtError {
  if self.pos + 1 > self.data.length() {
    raise Truncated(what)
  }
  let v = self.data[self.pos].to_int()
  self.pos += 1
  v
}

///|
fn Reader::u16(self : Reader, what : String) -> Int raise CtError {
  (self.u8(what) << 8) | self.u8(what)
}

///|
fn Reader::u64(self : Reader, what : String) -> UInt64 raise CtError {
  let mut v = 0UL
  for _i in 0..<8 {
    v = (v << 8) | self.u8(what).to_uint64()
  }
  v
}

///|
fn Reader::take(self : Reader, n : Int, what : String) -> Bytes raise CtError {
  if n < 0 || self.pos + n > self.data.length() {
    raise Truncated(what)
  }
  let start = self.pos
  self.pos += n
  Bytes::makei(n, fn(i) { self.data[start + i] })
}

///|
fn Reader::remaining(self : Reader) -> Int {
  self.data.length() - self.pos
}

///|
// Unwrap a DER OCTET STRING (tag 0x04) to its contents. X.509 extnValue is an
// OCTET STRING wrapping the TLS-encoded SignedCertificateTimestampList.
fn unwrap_octet_string(data : Bytes) -> Bytes raise CtError {
  let r = Reader::{ data, pos: 0 }
  if r.u8("octet-string tag") != 0x04 {
    raise Malformed("expected DER OCTET STRING")
  }
  let first = r.u8("length")
  let length = if first < 0x80 {
    first
  } else {
    let n = first - 0x80
    if n == 0 || n > 3 {
      raise Malformed("unsupported DER length")
    }
    let mut acc = 0
    for _i in 0..<n {
      acc = (acc << 8) | r.u8("length byte")
    }
    acc
  }
  r.take(length, "octet-string contents")
}

///|
fn parse_one_sct(bytes : Bytes) -> Sct raise CtError {
  let r = Reader::{ data: bytes, pos: 0 }
  let version = r.u8("sct_version")
  let log_id = r.take(32, "log_id")
  let timestamp = r.u64("timestamp")
  let ext_len = r.u16("extensions length")
  let extensions = r.take(ext_len, "extensions")
  let hash_alg = r.u8("hash_alg")
  let sig_alg = r.u8("sig_alg")
  let sig_len = r.u16("signature length")
  let signature = r.take(sig_len, "signature")
  {
    version,
    log_id,
    timestamp,
    extensions,
    sig_scheme: (hash_alg << 8) | sig_alg,
    signature,
  }
}

///|
/// Parse the X.509 SCT-list extension value (a DER OCTET STRING wrapping a
/// `SignedCertificateTimestampList`) into its SCTs.
pub fn parse_sct_list(extn_value : Bytes) -> Array[Sct] raise CtError {
  let list = unwrap_octet_string(extn_value)
  let r = Reader::{ data: list, pos: 0 }
  let total = r.u16("SCT list length")
  if r.remaining() != total {
    raise Malformed("SCT list length mismatch")
  }
  let scts : Array[Sct] = []
  while r.remaining() > 0 {
    let sct_len = r.u16("SerializedSCT length")
    scts.push(parse_one_sct(r.take(sct_len, "SerializedSCT")))
  }
  scts
}

///|
fn u24(n : Int) -> Bytes {
  Bytes::makei(3, fn(i) {
    match i {
      0 => ((n >> 16) & 0xff).to_byte()
      1 => ((n >> 8) & 0xff).to_byte()
      _ => (n & 0xff).to_byte()
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
/// Build the `signed_entry` for an `x509_entry` (entry_type 0): the leaf
/// certificate DER as `ASN.1Cert opaque<1..2^24-1>` (3-byte length + DER).
pub fn x509_entry(cert_der : Bytes) -> Bytes {
  concat([u24(cert_der.length()), cert_der])
}

///|
/// Build the `signed_entry` for a `precert_entry` (entry_type 1):
/// `issuer_key_hash[32] || TBSCertificate opaque<1..2^24-1>`. `tbs` is the
/// precertificate TBS with the SCT-list and poison extensions removed (the
/// caller reconstructs it); `issuer_key_hash` is SHA-256 of the issuer SPKI.
pub fn precert_entry(issuer_key_hash : Bytes, tbs : Bytes) -> Bytes {
  concat([issuer_key_hash, u24(tbs.length()), tbs])
}

///|
/// The SHA-256 log id of a CT log, given its DER SubjectPublicKeyInfo
/// (RFC 6962 §3.2: `LogID = SHA-256(SubjectPublicKeyInfo)`).
pub fn log_id_for_spki(log_spki_der : Bytes) -> Bytes {
  @hash.sha256(log_spki_der)
}

///|
// The TLS-serialized signed data the SCT signature covers.
fn sct_signed_data(sct : Sct, entry_type : Int, signed_entry : Bytes) -> Bytes {
  concat([
    Bytes::makei(1, fn(_i) { sct.version.to_byte() }), // sct_version
    b"\x00", // signature_type = certificate_timestamp
    Bytes::makei(8, fn(i) {
      ((sct.timestamp >> ((7 - i) * 8)) & 0xffUL).to_int().to_byte()
    }),
    Bytes::makei(2, fn(i) {
      if i == 0 {
        ((entry_type >> 8) & 0xff).to_byte()
      } else {
        (entry_type & 0xff).to_byte()
      }
    }),
    signed_entry,
    Bytes::makei(2, fn(i) {
      if i == 0 {
        ((sct.extensions.length() >> 8) & 0xff).to_byte()
      } else {
        (sct.extensions.length() & 0xff).to_byte()
      }
    }),
    sct.extensions,
  ])
}

///|
/// Verify an SCT against a CT log identified by its DER SubjectPublicKeyInfo.
///
/// Checks (a) the SCT's `log_id` equals `SHA-256(log_spki_der)` (binding the
/// key to the claimed log), and (b) the signature over the reconstructed signed
/// data verifies. `entry_type` is 0 (x509) or 1 (precert); `signed_entry` is
/// the matching entry from `x509_entry` / `precert_entry`.
///
/// Returns `true` only on a full match. Unsupported scheme / key-type
/// combinations raise; a signature mismatch is `false`.
pub fn verify_sct(
  sct : Sct,
  log_spki_der : Bytes,
  entry_type : Int,
  signed_entry : Bytes,
) -> Bool raise CtError {
  if sct.version != 0 {
    return false
  }
  let expected_id = @hash.sha256(log_spki_der)
  if expected_id.length() != sct.log_id.length() {
    return false
  }
  let mut id_diff = 0
  for i in 0..<expected_id.length() {
    id_diff = id_diff | (expected_id[i].to_int() ^ sct.log_id[i].to_int())
  }
  if id_diff != 0 {
    return false
  }
  let spki = @pkix.parse_subject_public_key_info(log_spki_der) catch {
    e => raise Pkix(e)
  }
  let pubkey = @pkix_verify.extract_public_key(spki) catch {
    e => raise PkixVerify(e)
  }
  let signed = sct_signed_data(sct, entry_type, signed_entry)
  match (sct.sig_scheme, pubkey) {
    (0x0403, P256(pk)) =>
      (try? @p256.verify(pk, signed, sct.signature, @p256.SignatureFormat::Der)).unwrap_or(
        false,
      )
    (0x0503, P384(pk)) =>
      (try? @p384.verify(pk, signed, sct.signature, @p384.SignatureFormat::Der)).unwrap_or(
        false,
      )
    (0x0401, Rsa(pk)) =>
      (try? pk.verify(signed, sct.signature, @rsa.HashAlg::Sha256)).unwrap_or(
        false,
      )
    (0x0501, Rsa(pk)) =>
      (try? pk.verify(signed, sct.signature, @rsa.HashAlg::Sha384)).unwrap_or(
        false,
      )
    _ => raise Malformed("unsupported SCT signature scheme / key type")
  }
}
