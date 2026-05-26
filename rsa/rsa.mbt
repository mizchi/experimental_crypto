// RSA PKCS#1 v1.5 signature verification (RFC 8017).
//
// Verify-only: there is no sign / decrypt / key generation path because
// this module exists to unlock RS256 in `mizchi/jwt` and OAuth / OIDC
// JWKS-style verification flows. Adding sign requires a CRT private-key
// path and side-channel discipline that is intentionally deferred.

///|
// Hash algorithm tag carried in the public API. Only Sha256 is wired
// today; Sha384 / Sha512 surface as `UnsupportedHash` so that callers
// can detect the gap explicitly instead of getting a verification
// false-negative.
pub(all) enum HashAlg {
  Sha256
  Sha384
  Sha512
} derive(Eq, Show)

///|
pub suberror RsaError {
  // ASN.1 / DER parse failure (PKCS#1 RSAPublicKey or SPKI wrapper).
  InvalidEncoding(String)
  // SPKI algorithm OID was not rsaEncryption (1.2.840.113549.1.1.1).
  UnsupportedAlgorithm(String)
  // Signature byte length did not equal the modulus byte length, which
  // RFC 8017 §8.2.2 step 1 demands. Returned before any modular math
  // happens. A mismatched modulus / signature size almost always means
  // the caller wired the wrong key, so we surface it as a typed error
  // rather than rolling it into the boolean return.
  InvalidSignatureLength
  // Hash variant is recognized in `HashAlg` but not implemented here.
  UnsupportedHash(HashAlg)
  // Modulus too small to fit the PKCS#1 v1.5 padding for the chosen
  // hash. RFC 8017 §9.2 step 3: emLen must be ≥ tLen + 11.
  ModulusTooSmall
  // Underlying ASN.1 decoder rejected the bytes (truncated, bad tag, …).
  Asn1(@asn1.Asn1Error)
} derive(Show)

///|
// RSA public key (modulus + public exponent). `n_bytes_len` is cached
// because RFC 8017's I2OSP / EMSA-PKCS1-v1_5 steps all operate on the
// modulus's fixed byte length, and recomputing `(n.bit_length() + 7) / 8`
// per verify is wasteful when callers verify many tokens against the
// same key.
pub(all) struct RsaPublicKey {
  n : BigInt
  e : BigInt
  n_bytes_len : Int
}

// ─── decoders ────────────────────────────────────────────────────────────

///|
fn expect_sequence(elem : @asn1.Element) -> Array[@asn1.Element] raise RsaError {
  match elem.value {
    Sequence(items) =>
      if elem.tag == @asn1.tag_sequence {
        items
      } else {
        raise InvalidEncoding("expected universal SEQUENCE tag")
      }
    _ => raise InvalidEncoding("expected SEQUENCE")
  }
}

///|
fn expect_integer_bytes(elem : @asn1.Element) -> Bytes raise RsaError {
  match elem.value {
    Integer(b) => b
    _ => raise InvalidEncoding("expected INTEGER")
  }
}

///|
// Decode a DER INTEGER (which may have a leading 0x00 sign byte) into a
// non-negative BigInt. RSA n and e are always non-negative, so we just
// strip a single 0x00 sign byte if present.
fn integer_to_bigint(bytes : Bytes) -> BigInt raise RsaError {
  if bytes.length() == 0 {
    raise InvalidEncoding("empty INTEGER")
  }
  // Negative DER INTEGERs would have the MSB of the first byte set without
  // a 0x00 prefix — never legal for RSA public-key fields.
  if (bytes[0].to_int() & 0x80) != 0 {
    raise InvalidEncoding("negative INTEGER not permitted")
  }
  // BigInt::from_octets defaults to positive (signum=1) and takes a
  // BytesView. Strip an optional 0x00 leading byte (DER's sign byte) so
  // that the BigInt does not unnecessarily widen.
  let start = if bytes.length() > 1 && bytes[0] == b'\x00' { 1 } else { 0 }
  BigInt::from_octets(bytes[start:])
}

///|
fn decode_one(der : Bytes) -> @asn1.Element raise RsaError {
  @asn1.decode_der(der) catch {
    e => raise Asn1(e)
  }
}

///|
// Parse a single RSAPublicKey SEQUENCE { n, e } element (without the
// SPKI wrapper). Used by both `from_pkcs1_der` and `from_spki_der`.
fn parse_rsa_public_key_elem(
  elem : @asn1.Element,
) -> RsaPublicKey raise RsaError {
  let items = expect_sequence(elem)
  if items.length() != 2 {
    raise InvalidEncoding("RSAPublicKey must have 2 entries")
  }
  let n_bytes = expect_integer_bytes(items[0])
  let e_bytes = expect_integer_bytes(items[1])
  let n = integer_to_bigint(n_bytes)
  let e = integer_to_bigint(e_bytes)
  if n.compare_int(0) <= 0 {
    raise InvalidEncoding("modulus must be positive")
  }
  if e.compare_int(0) <= 0 {
    raise InvalidEncoding("public exponent must be positive")
  }
  let n_bytes_len = (n.bit_length() + 7) / 8
  { n, e, n_bytes_len }
}

///|
/// Decode a PKCS#1 RSAPublicKey DER blob (RFC 8017 §A.1.1):
///   RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
pub fn RsaPublicKey::from_pkcs1_der(der : Bytes) -> RsaPublicKey raise RsaError {
  parse_rsa_public_key_elem(decode_one(der))
}

///|
// rsaEncryption OID — 1.2.840.113549.1.1.1 (RFC 8017 §A.1).
let rsa_encryption_oid_str : String = "1.2.840.113549.1.1.1"

///|
/// Decode a SubjectPublicKeyInfo DER blob (RFC 5280 §4.1.2.7):
///   SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm        AlgorithmIdentifier,
///     subjectPublicKey BIT STRING        -- contains PKCS#1 RSAPublicKey
///   }
/// The algorithm OID must be rsaEncryption (1.2.840.113549.1.1.1).
pub fn RsaPublicKey::from_spki_der(der : Bytes) -> RsaPublicKey raise RsaError {
  let elem = decode_one(der)
  let items = expect_sequence(elem)
  if items.length() != 2 {
    raise InvalidEncoding("SubjectPublicKeyInfo must have 2 entries")
  }
  // AlgorithmIdentifier
  let alg_items = expect_sequence(items[0])
  if alg_items.length() < 1 || alg_items.length() > 2 {
    raise InvalidEncoding("AlgorithmIdentifier arity")
  }
  let oid = match alg_items[0].value {
    Oid(o) => o
    _ => raise InvalidEncoding("expected OID")
  }
  if oid.to_string() != rsa_encryption_oid_str {
    raise UnsupportedAlgorithm(oid.to_string())
  }
  // subjectPublicKey is a BIT STRING wrapping a DER RSAPublicKey.
  let bs = match items[1].value {
    BitString(bs) => bs
    _ => raise InvalidEncoding("expected BIT STRING")
  }
  if bs.unused_bits != 0 {
    raise InvalidEncoding("SPKI BIT STRING must have 0 unused bits")
  }
  parse_rsa_public_key_elem(decode_one(bs.bytes))
}

// ─── EMSA-PKCS1-v1_5 ─────────────────────────────────────────────────────

///|
// DigestInfo DER prefixes from RFC 8017 §9.2 note 1. These are pre-encoded
// so the verify path never has to construct an ASN.1 SEQUENCE — we just
// concat with the raw hash. Each prefix includes the leading SEQUENCE tag
// and the DigestInfo header that immediately precedes the H bytes.
let digest_info_prefix_sha256 : Bytes = b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"

///|
// RFC 8017 §9.2 note 1: sha384WithRSAEncryption / sha512WithRSAEncryption
// DigestInfo prefixes. Each is the ASN.1 SEQUENCE { algorithm, OCTET STRING
// header } that precedes the raw digest in the encoded EM.
let digest_info_prefix_sha384 : Bytes = b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30"

///|
let digest_info_prefix_sha512 : Bytes = b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"

///|
fn digest_info_prefix(hash : HashAlg) -> Bytes raise RsaError {
  match hash {
    Sha256 => digest_info_prefix_sha256
    Sha384 => digest_info_prefix_sha384
    Sha512 => digest_info_prefix_sha512
  }
}

///|
fn digest_length(hash : HashAlg) -> Int raise RsaError {
  match hash {
    Sha256 => 32
    Sha384 => 48
    Sha512 => 64
  }
}

///|
fn hash_message(hash : HashAlg, msg : Bytes) -> Bytes raise RsaError {
  match hash {
    Sha256 => @hash.sha256(msg)
    Sha384 => @hash.sha384(msg)
    Sha512 => @hash.sha512(msg)
  }
}

///|
// EMSA-PKCS1-v1_5 encode (RFC 8017 §9.2). Build an `em_len`-byte block:
//   0x00 || 0x01 || PS || 0x00 || T
// where T = DigestInfo prefix || H(M) and PS is `em_len − tLen − 3` 0xFF
// bytes (must be ≥ 8, so `em_len ≥ tLen + 11`).
fn emsa_pkcs1_v1_5_encode(
  hash : HashAlg,
  msg : Bytes,
  em_len : Int,
) -> Bytes raise RsaError {
  let prefix = digest_info_prefix(hash)
  let h_len = digest_length(hash)
  let t_len = prefix.length() + h_len
  // RFC 8017 §9.2 step 3.
  if em_len < t_len + 11 {
    raise ModulusTooSmall
  }
  let h = hash_message(hash, msg)
  let ps_len = em_len - t_len - 3
  let out = FixedArray::make(em_len, b'\x00')
  out.unsafe_set(0, b'\x00')
  out.unsafe_set(1, b'\x01')
  for i = 0; i < ps_len; i = i + 1 {
    out.unsafe_set(2 + i, b'\xff')
  }
  out.unsafe_set(2 + ps_len, b'\x00')
  for i = 0; i < prefix.length(); i = i + 1 {
    out.unsafe_set(3 + ps_len + i, prefix[i])
  }
  for i = 0; i < h_len; i = i + 1 {
    out.unsafe_set(3 + ps_len + prefix.length() + i, h[i])
  }
  Bytes::makei(em_len, fn(j) { out.unsafe_get(j) })
}

///|
// Constant-time byte-sequence equality (OR-of-XORs over the full length).
// We compare two same-length blocks (em_len bytes), so the length-mismatch
// early return below is just a defensive guard.
fn ct_eq(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0
  for i = 0; i < a.length(); i = i + 1 {
    diff = diff | (a[i].to_int() ^ b[i].to_int())
  }
  diff == 0
}

// ─── verify ──────────────────────────────────────────────────────────────

///|
/// RSASSA-PKCS1-v1_5 verification (RFC 8017 §8.2.2).
///
/// Returns `true` iff the signature is valid for `message` under `pubkey`
/// with the given `hash`. Returns `false` on any of:
/// - signature integer ≥ modulus (RSAVP1),
/// - the recovered representative does not match the EMSA-PKCS1-v1_5
///   encoding of `H(message)`.
///
/// Raises:
/// - `InvalidSignatureLength` if `signature.length() ≠ modulus byte length`,
/// - `UnsupportedHash` if `hash` is Sha384 / Sha512 (not wired yet),
/// - `ModulusTooSmall` if the modulus is too short for the chosen hash's
///   DigestInfo + minimum padding.
pub fn RsaPublicKey::verify(
  self : RsaPublicKey,
  message : Bytes,
  signature : Bytes,
  hash : HashAlg,
) -> Bool raise RsaError {
  // Step 1: signature must be exactly `k` bytes where `k` is the modulus
  // byte length. RFC 8017 §8.2.2 step 1 says "if the length of the
  // signature S is not k octets, output 'invalid signature'". We surface
  // it as a typed error rather than `false` because it usually means the
  // caller wired the wrong key.
  if signature.length() != self.n_bytes_len {
    raise InvalidSignatureLength
  }
  // Step 2a: OS2IP — interpret signature bytes as a big-endian integer.
  let s = BigInt::from_octets(signature[:])
  // RSAVP1: 0 ≤ s < n. If s ≥ n, signature is invalid (don't raise, just
  // return false — could be attacker-supplied garbage).
  if s.compare(self.n) >= 0 {
    return false
  }
  // Step 2b: m = s^e mod n (modular exponentiation via BigInt::pow with
  // modulus parameter — single mod-exp, e is typically 65537 so cheap).
  let m = s.pow(self.e, modulus=self.n)
  // Step 2c: I2OSP — encode m as `k` big-endian bytes.
  let em = m.to_octets(length=self.n_bytes_len)
  // Step 3: compare against the expected EMSA-PKCS1-v1_5 encoding.
  let expected = emsa_pkcs1_v1_5_encode(hash, message, self.n_bytes_len)
  ct_eq(em, expected)
}

///|
/// Convenience wrapper kept for symmetry with other crypto modules
/// (sign / verify free functions in `ed25519`, etc).
pub fn verify(
  pubkey : RsaPublicKey,
  message : Bytes,
  signature : Bytes,
  hash : HashAlg,
) -> Bool raise RsaError {
  pubkey.verify(message, signature, hash)
}

// ─── private key + PKCS#1 v1.5 sign ──────────────────────────────────────

///|
/// RSA private key. The CRT parameters (p, q, dP, dQ, qInv) are recommended
/// for performance but optional — basic `(n, d)` is enough for sign.
pub(all) struct RsaPrivateKey {
  n : BigInt
  e : BigInt
  d : BigInt
  n_bytes_len : Int
}

///|
/// Parse a PKCS#1 v1.5 RSAPrivateKey DER blob (the inner form, without
/// the PKCS#8 envelope):
///   RSAPrivateKey ::= SEQUENCE {
///     version INTEGER,
///     modulus INTEGER,
///     publicExponent INTEGER,
///     privateExponent INTEGER,
///     prime1, prime2, exponent1, exponent2, coefficient INTEGER
///   }
///
/// Only the first four fields (version, n, e, d) are read; the CRT
/// parameters are skipped.
pub fn RsaPrivateKey::from_pkcs1_der(
  der : Bytes,
) -> RsaPrivateKey raise RsaError {
  let elem = decode_one(der)
  let items = expect_sequence(elem)
  if items.length() < 4 {
    raise InvalidEncoding("RSAPrivateKey arity < 4")
  }
  // version must be 0 (two-prime) per RFC 8017 §A.1.2.
  let v = integer_to_bigint(expect_integer_bytes(items[0]))
  if v.compare(BigInt::from_int(0)) != 0 {
    raise InvalidEncoding("RSAPrivateKey: version != 0 (multi-prime)")
  }
  let n_bytes = expect_integer_bytes(items[1])
  let e_bytes = expect_integer_bytes(items[2])
  let d_bytes = expect_integer_bytes(items[3])
  let n = integer_to_bigint(n_bytes)
  let e = integer_to_bigint(e_bytes)
  let d = integer_to_bigint(d_bytes)
  // n_bytes_len = ceil(bit_length(n) / 8). Deriving from the parsed BigInt
  // (rather than the raw DER bytes) makes the value robust against
  // non-canonical INTEGER encodings that happen to include extra leading
  // 0x00 bytes — the public-key constructor above does the same.
  let n_octets = n.to_octets()
  let mut start = 0
  while start < n_octets.length() - 1 && n_octets[start] == b'\x00' {
    start = start + 1
  }
  let n_bytes_len = n_octets.length() - start
  { n, e, d, n_bytes_len }
}

///|
/// Derive the public key from this private key. No private material leaks
/// across the boundary.
pub fn RsaPrivateKey::public_key(self : RsaPrivateKey) -> RsaPublicKey {
  { n: self.n, e: self.e, n_bytes_len: self.n_bytes_len }
}

///|
/// RSASSA-PKCS1-v1_5 sign (RFC 8017 §8.2.1).
///
///   s = (EM_to_integer(EMSA_PKCS1_v15(hash, message, k))) ^ d mod n
///
/// where k = n_bytes_len. Returns the k-byte signature.
///
/// Side-channel caveat: the modexp uses `@bigint.pow`, which is
/// variable-time on the secret `d`. We do NOT do CRT (so no
/// CRT-fault-injection vector either), but a timing attacker who can
/// trigger many sign operations may recover `d`. Treat this as a
/// sign-only-on-trusted-hosts primitive.
pub fn RsaPrivateKey::sign(
  self : RsaPrivateKey,
  message : Bytes,
  hash : HashAlg,
) -> Bytes raise RsaError {
  let em = emsa_pkcs1_v1_5_encode(hash, message, self.n_bytes_len)
  // OS2IP — interpret EM as a non-negative integer.
  let m = BigInt::from_octets(em[:])
  // s = m^d mod n.
  let s = m.pow(self.d, modulus=self.n)
  // I2OSP — encode as fixed-length big-endian.
  s.to_octets(length=self.n_bytes_len)
}

// ─── PKCS#8 / PEM loaders ────────────────────────────────────────────────

///|
fn rsa_encryption_oid_for_pkcs8() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 113549, 1, 1, 1])
}

///|
/// Load an RSA private key from a PKCS#8 PrivateKeyInfo DER blob (the
/// `BEGIN PRIVATE KEY` PEM body, post-base64-decode). Verifies the
/// algorithm OID is rsaEncryption (1.2.840.113549.1.1.1).
pub fn RsaPrivateKey::from_pkcs8_der(
  der : Bytes,
) -> RsaPrivateKey raise RsaError {
  let info = @pkcs8.parse_der(der) catch {
    e => raise InvalidEncoding("pkcs8: " + e.to_string())
  }
  if info.algorithm.algorithm != rsa_encryption_oid_for_pkcs8() {
    raise UnsupportedAlgorithm(info.algorithm.algorithm.to_string())
  }
  RsaPrivateKey::from_pkcs1_der(info.private_key)
}

///|
/// Convenience: parse a `-----BEGIN PRIVATE KEY-----` PEM (unencrypted)
/// and return the contained RSA private key.
pub fn RsaPrivateKey::from_pkcs8_pem(
  pem_str : String,
) -> RsaPrivateKey raise RsaError {
  let block = @pem.decode(pem_str) catch {
    e => raise InvalidEncoding("pem: " + e.to_string())
  }
  if block.label != "PRIVATE KEY" {
    raise InvalidEncoding(
      "expected -----BEGIN PRIVATE KEY----- label, got " + block.label,
    )
  }
  RsaPrivateKey::from_pkcs8_der(block.data)
}

// ─── RSASSA-PSS (RFC 8017 §8.1 / §9.1) ───────────────────────────────────
//
// PSS adds a randomised (or deterministic-with-empty-salt) variant of RSA
// signing, which TLS 1.3 and modern JWS (PS256/384/512) prefer over
// PKCS#1 v1.5. The encoding (EMSA-PSS) lives in §9.1; the signature scheme
// (RSASSA-PSS-SIGN / -VERIFY) in §8.1. We hardcode the same hash for the
// message hash (mHash) and the MGF1 hash, which is the common — and JWA
// §3.5-mandated — choice.

///|
// MGF1 (RFC 8017 §B.2.1). Generates `mask_len` bytes by hashing
// `seed || I2OSP(counter, 4)` for counter = 0, 1, 2, ... and concatenating
// the results until `mask_len` bytes have been produced.
//
// The "ceil(mask_len / hLen)" upper bound is enforced implicitly via the
// loop termination check `out.length() >= mask_len`.
fn mgf1(hash : HashAlg, seed : Bytes, mask_len : Int) -> Bytes raise RsaError {
  let h_len = digest_length(hash)
  let out = FixedArray::make(mask_len, b'\x00')
  let mut written = 0
  let mut counter = 0
  while written < mask_len {
    // I2OSP(counter, 4) — 4-byte big-endian counter.
    let c0 = ((counter >> 24) & 0xff).to_byte()
    let c1 = ((counter >> 16) & 0xff).to_byte()
    let c2 = ((counter >> 8) & 0xff).to_byte()
    let c3 = (counter & 0xff).to_byte()
    // seed || counter (4 bytes) — assemble into a single Bytes for the hash.
    let input = Bytes::makei(seed.length() + 4, fn(i) {
      if i < seed.length() {
        seed[i]
      } else if i == seed.length() {
        c0
      } else if i == seed.length() + 1 {
        c1
      } else if i == seed.length() + 2 {
        c2
      } else {
        c3
      }
    })
    let block = hash_message(hash, input)
    // Append up to (mask_len - written) bytes of `block`.
    let need = mask_len - written
    let take = if need < h_len { need } else { h_len }
    for i = 0; i < take; i = i + 1 {
      out.unsafe_set(written + i, block[i])
    }
    written = written + take
    counter = counter + 1
    // I2OSP guard: counter would overflow at 2^32 — for h_len ≥ 32 we'd
    // need mask_len ≥ 2^37 bytes, which is far outside Bytes' capacity, so
    // we don't bother with an explicit ceiling check.
  }
  Bytes::makei(mask_len, fn(j) { out.unsafe_get(j) })
}

///|
// Compute `EM = EMSA-PSS-ENCODE(mHash, salt, emBits, hash)` per RFC 8017
// §9.1.1. The caller supplies the salt bytes (so the salt RNG dependency
// stays at the API edge — see the doc comment on `sign_pss`).
//
// Returns the `em_len`-byte encoded message. `em_len = ceil(emBits / 8)`.
fn emsa_pss_encode(
  hash : HashAlg,
  m_hash : Bytes,
  salt : Bytes,
  em_bits : Int,
) -> Bytes raise RsaError {
  let h_len = digest_length(hash)
  let s_len = salt.length()
  // (8*emLen - emBits) is the count of leftmost bits we have to mask off
  // in maskedDB[0]. For modBits = 2048 this is 1 (emBits = 2047, emLen = 256).
  let em_len = (em_bits + 7) / 8
  // §9.1.1 step 3: if emLen < hLen + sLen + 2, encoding error.
  if em_len < h_len + s_len + 2 {
    raise ModulusTooSmall
  }
  if m_hash.length() != h_len {
    raise InvalidEncoding("mHash length mismatch")
  }
  // §9.1.1 step 5: M' = (0x00 * 8) || mHash || salt; H = H(M').
  let m_prime = Bytes::makei(8 + h_len + s_len, fn(i) {
    if i < 8 {
      b'\x00'
    } else if i < 8 + h_len {
      m_hash[i - 8]
    } else {
      salt[i - 8 - h_len]
    }
  })
  let h = hash_message(hash, m_prime)
  // §9.1.1 step 7-8: DB = PS || 0x01 || salt, where PS is
  // (emLen - sLen - hLen - 2) zero bytes. DB length = emLen - hLen - 1.
  let db_len = em_len - h_len - 1
  let ps_len = em_len - s_len - h_len - 2
  let db = FixedArray::make(db_len, b'\x00')
  // PS is already zero-filled by FixedArray::make. Just write 0x01 then salt.
  db.unsafe_set(ps_len, b'\x01')
  for i = 0; i < s_len; i = i + 1 {
    db.unsafe_set(ps_len + 1 + i, salt[i])
  }
  // §9.1.1 step 9-10: dbMask = MGF(H, emLen - hLen - 1), maskedDB = DB XOR dbMask.
  let db_mask = mgf1(hash, h, db_len)
  let masked_db = FixedArray::make(db_len, b'\x00')
  for i = 0; i < db_len; i = i + 1 {
    masked_db.unsafe_set(
      i,
      (db.unsafe_get(i).to_int() ^ db_mask[i].to_int()).to_byte(),
    )
  }
  // §9.1.1 step 11: zero the leftmost (8*emLen - emBits) bits of maskedDB[0].
  let zero_bits = 8 * em_len - em_bits
  if zero_bits > 0 {
    let keep_mask = (0xff >> zero_bits).to_byte()
    masked_db.unsafe_set(
      0,
      (masked_db.unsafe_get(0).to_int() & keep_mask.to_int()).to_byte(),
    )
  }
  // §9.1.1 step 12: EM = maskedDB || H || 0xBC.
  Bytes::makei(em_len, fn(i) {
    if i < db_len {
      masked_db.unsafe_get(i)
    } else if i < db_len + h_len {
      h[i - db_len]
    } else {
      b'\xbc'
    }
  })
}

///|
// `EMSA-PSS-VERIFY(mHash, EM, sLen, emBits, hash)` per RFC 8017 §9.1.2.
// Returns `true` iff the decoding is consistent with `mHash` under salt
// length `s_len`.
fn emsa_pss_verify(
  hash : HashAlg,
  m_hash : Bytes,
  em : Bytes,
  s_len : Int,
  em_bits : Int,
) -> Bool raise RsaError {
  let h_len = digest_length(hash)
  let em_len = (em_bits + 7) / 8
  // §9.1.2 step 3: emLen < hLen + sLen + 2 → inconsistent.
  if em_len < h_len + s_len + 2 {
    return false
  }
  if em.length() != em_len {
    return false
  }
  // §9.1.2 step 4: last byte of EM must be 0xBC.
  if em[em_len - 1] != b'\xbc' {
    return false
  }
  // maskedDB = EM[0 .. emLen - hLen - 1], H = EM[emLen - hLen - 1 .. emLen - 1].
  let db_len = em_len - h_len - 1
  // §9.1.2 step 6: top (8*emLen - emBits) bits of maskedDB[0] must be zero.
  let zero_bits = 8 * em_len - em_bits
  if zero_bits > 0 {
    let high_mask = (0xff << (8 - zero_bits)) & 0xff
    if (em[0].to_int() & high_mask) != 0 {
      return false
    }
  }
  let h = Bytes::makei(h_len, fn(i) { em[db_len + i] })
  // §9.1.2 step 7-8: dbMask = MGF(H, db_len), DB = maskedDB XOR dbMask.
  let db_mask = mgf1(hash, h, db_len)
  let db = FixedArray::make(db_len, b'\x00')
  for i = 0; i < db_len; i = i + 1 {
    db.unsafe_set(i, (em[i].to_int() ^ db_mask[i].to_int()).to_byte())
  }
  // §9.1.2 step 9: zero the leftmost (8*emLen - emBits) bits of DB[0].
  if zero_bits > 0 {
    let keep_mask = (0xff >> zero_bits).to_byte()
    db.unsafe_set(0, (db.unsafe_get(0).to_int() & keep_mask.to_int()).to_byte())
  }
  // §9.1.2 step 10: DB = PS || 0x01 || salt where PS = (em_len - s_len - h_len - 2)
  // zero bytes. We expect the 0x01 marker at position (db_len - s_len - 1) — and
  // every preceding byte must be 0x00.
  let ps_len = em_len - s_len - h_len - 2
  for i = 0; i < ps_len; i = i + 1 {
    if db.unsafe_get(i) != b'\x00' {
      return false
    }
  }
  if db.unsafe_get(ps_len) != b'\x01' {
    return false
  }
  // §9.1.2 step 12: salt = DB[db_len - sLen .. db_len].
  let salt = Bytes::makei(s_len, fn(i) { db.unsafe_get(ps_len + 1 + i) })
  // §9.1.2 step 13: M' = (0x00 * 8) || mHash || salt, H' = H(M').
  let m_prime = Bytes::makei(8 + h_len + s_len, fn(i) {
    if i < 8 {
      b'\x00'
    } else if i < 8 + h_len {
      m_hash[i - 8]
    } else {
      salt[i - 8 - h_len]
    }
  })
  let h_prime = hash_message(hash, m_prime)
  // §9.1.2 step 14: H = H' ?
  ct_eq(h, h_prime)
}

///|
// Compute modBits = bit length of n. We need this both for sign and verify
// to derive emBits = modBits - 1.
fn mod_bits(n : BigInt) -> Int {
  n.bit_length()
}

///|
/// RSASSA-PSS sign (RFC 8017 §8.1.1).
///
/// `salt` is supplied by the caller — pass `b""` for deterministic /
/// no-salt PSS (RFC 8017 §A.2.3 permits sLen = 0, which yields a
/// PKCS#1-v1.5-like deterministic signature). For randomised PSS, pass a
/// freshly-sampled `salt_len`-byte string (typically `salt_len = hLen` per
/// FIPS 186-4 / JWA §3.5).
///
/// The hash is used both for the message hash and for MGF1, matching every
/// real-world deployment (TLS 1.3, JWA, PKCS#1 v2.2 default).
///
/// Side-channel caveat: the modexp uses `@bigint.pow`, which is
/// variable-time on the secret `d` (same as the PKCS#1 v1.5 sign path).
pub fn RsaPrivateKey::sign_pss(
  self : RsaPrivateKey,
  message : Bytes,
  hash : HashAlg,
  salt : Bytes,
) -> Bytes raise RsaError {
  // §8.1.1 step 1: EMSA-PSS-ENCODE.
  let em_bits = mod_bits(self.n) - 1
  let m_hash = hash_message(hash, message)
  let em = emsa_pss_encode(hash, m_hash, salt, em_bits)
  // §8.1.1 step 2: OS2IP(EM) → m; s = m^d mod n.
  let m = BigInt::from_octets(em[:])
  let s = m.pow(self.d, modulus=self.n)
  // §8.1.1 step 3: I2OSP(s, k) → k-byte signature.
  s.to_octets(length=self.n_bytes_len)
}

///|
/// RSASSA-PSS verify (RFC 8017 §8.1.2).
///
/// Returns `true` iff the signature is valid for `message` under `self`
/// with the given `hash` and salt length.
///
/// - `salt_len = -1` → use `hLen` (the digest length of `hash`) as the
///   expected salt length. This matches RFC 7518 §3.5 (JWS PS256/384/512)
///   and FIPS 186-4 §5.5.
/// - `salt_len ≥ 0` → require exactly that many salt bytes.
///
/// Raises `InvalidSignatureLength` if `signature.length() ≠ k`. Returns
/// `false` on any encoding inconsistency (last byte ≠ 0xBC, high-bit
/// nonzero, PS bytes nonzero, recomputed H mismatch).
///
/// Side-channel caveat: the verify path is variable-time on the candidate
/// signature contents (same as the PKCS#1 v1.5 verify path — public
/// operation, so timing leaks the signature but not the key).
pub fn RsaPublicKey::verify_pss(
  self : RsaPublicKey,
  message : Bytes,
  signature : Bytes,
  hash : HashAlg,
  salt_len? : Int = -1,
) -> Bool raise RsaError {
  // §8.1.2 step 1: signature length must equal k.
  if signature.length() != self.n_bytes_len {
    raise InvalidSignatureLength
  }
  let h_len = digest_length(hash)
  let s_len = if salt_len < 0 { h_len } else { salt_len }
  let em_bits = mod_bits(self.n) - 1
  let em_len = (em_bits + 7) / 8
  // §8.1.2 step 2a: OS2IP(signature) → s; check 0 ≤ s < n.
  let s = BigInt::from_octets(signature[:])
  if s.compare(self.n) >= 0 {
    return false
  }
  // §8.1.2 step 2b: m = s^e mod n.
  let m = s.pow(self.e, modulus=self.n)
  // §8.1.2 step 2c: EM = I2OSP(m, emLen). If m doesn't fit in emLen bytes,
  // I2OSP fails. We get this for free from `to_octets(length=)` since it
  // pads / fails consistently — but in the emLen < k case we must encode
  // to emLen, not k. Same emBits ≡ 8*emLen − 0..7 bits invariant holds.
  let em = m.to_octets(length=em_len)
  // §8.1.2 step 3: EMSA-PSS-VERIFY(mHash, EM, sLen, emBits).
  let m_hash = hash_message(hash, message)
  emsa_pss_verify(hash, m_hash, em, s_len, em_bits)
}
