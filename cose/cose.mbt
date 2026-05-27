// COSE — CBOR Object Signing and Encryption (RFC 9052).
//
// This is a minimum-viable verifier:
//   - parse a COSE_Sign1 structure (with or without the outer tag 18)
//   - parse a COSE_Key into one of the supported public-key variants
//   - verify the signature against a payload (embedded or detached)
//
// Algorithms covered:
//   - ES256 (-7)   ECDSA over P-256 with SHA-256
//   - ES384 (-35)  ECDSA over P-384 with SHA-384
//   - EdDSA (-8)   Ed25519 (RFC 8032)
//   - RS256 (-257) RSASSA-PKCS1-v1_5 with SHA-256
//
// Out of scope:
//   - COSE_Encrypt / COSE_Mac / COSE_Sign (multi-signer)
//   - COSE_Key derivation / key wrap
//   - PSS, deterministic ECDSA, raw RSA signing
//   - canonical encoding validation of the incoming COSE_Sign1
//     (we only re-encode the Sig_structure for hashing; we trust the
//     `protected` bstr exactly as it was provided on the wire, which is
//     what RFC 9052 §4.4 step 4 actually requires)

// --- Algorithms ----------------------------------------------------------

///|
pub(all) enum CoseAlg {
  ES256
  ES384
  EdDSA
  RS256
} derive(Eq, Debug)

///|
fn alg_from_id(id : Int64) -> CoseAlg raise CoseError {
  match id {
    -7L => ES256
    -35L => ES384
    -8L => EdDSA
    -257L => RS256
    other => raise UnsupportedAlgorithm(other)
  }
}

// --- COSE_Key ------------------------------------------------------------

///|
pub(all) enum CoseKey {
  Ec2P256(pubkey~ : @p256.PublicKey)
  Ec2P384(pubkey~ : @p384.PublicKey)
  OkpEd25519(pubkey~ : @ed25519.PublicKey)
  Rsa(pubkey~ : @rsa.RsaPublicKey)
}

// --- Errors --------------------------------------------------------------

///|
pub suberror CoseError {
  // Underlying CBOR decode error.
  CborDecode(@cbor.CborError)
  // The COSE_Sign1 array did not match `[protected, unprotected, payload,
  // signature]`.
  InvalidStructure(String)
  // The `alg` header was missing, mis-typed, or specified an algorithm we
  // do not support yet.
  UnsupportedAlgorithm(Int64)
  // The key passed in didn't match the algorithm declared in the protected
  // header (e.g. ES256 sig + Ed25519 key).
  AlgorithmKeyMismatch
  // COSE_Key was missing a required label or had an unsupported value
  // (unknown kty, unknown curve, wrong key length, etc).
  InvalidKey(String)
  // The signature was structurally invalid (e.g. wrong length for the alg).
  InvalidSignature(String)
} derive(Debug)

// --- Public API ----------------------------------------------------------

///|
// Parse a COSE_Key from its CBOR encoding.
//
// Accepts both the "alg" label and the per-kty curve / x / y / n / e
// labels. The `kid` label is ignored on purpose (it's caller-side
// metadata and bears no signature integrity).
pub fn parse_cose_key(cbor : Bytes) -> CoseKey raise CoseError {
  let v = @cbor.decode(cbor) catch { e => raise CborDecode(e) }
  parse_cose_key_value(v)
}

///|
pub fn parse_cose_key_value(v : @cbor.CborValue) -> CoseKey raise CoseError {
  require_unique_int_labels(v, "COSE_Key")
  let kty = require_int(v, 1L, "kty")
  match kty {
    // kty = 1 (OKP)
    1L => {
      let crv = require_int(v, -1L, "OKP crv")
      // crv = 6 (Ed25519)
      if crv != 6L {
        raise InvalidKey("OKP curve \{crv} not supported (only Ed25519=6)")
      }
      let x = require_bytes(v, -2L, "OKP x")
      let pk = @ed25519.PublicKey::from_bytes(x) catch {
        e => raise InvalidKey("Ed25519: " + @debug.to_string(e) + "")
      }
      OkpEd25519(pubkey=pk)
    }
    // kty = 2 (EC2)
    2L => {
      let crv = require_int(v, -1L, "EC2 crv")
      let x = require_bytes(v, -2L, "EC2 x")
      let y = require_bytes(v, -3L, "EC2 y")
      match crv {
        // crv = 1 (P-256)
        1L => {
          if x.length() != 32 || y.length() != 32 {
            raise InvalidKey("P-256 coords must be 32 bytes each")
          }
          let uncompressed = concat3(b"\x04", x, y)
          let pk = @p256.PublicKey::from_uncompressed(uncompressed) catch {
            e => raise InvalidKey("P-256: " + @debug.to_string(e) + "")
          }
          Ec2P256(pubkey=pk)
        }
        // crv = 2 (P-384)
        2L => {
          if x.length() != 48 || y.length() != 48 {
            raise InvalidKey("P-384 coords must be 48 bytes each")
          }
          let uncompressed = concat3(b"\x04", x, y)
          let pk = @p384.PublicKey::from_uncompressed(uncompressed) catch {
            e => raise InvalidKey("P-384: " + @debug.to_string(e) + "")
          }
          Ec2P384(pubkey=pk)
        }
        other => raise InvalidKey("EC2 curve " + repr(other) + " not supported")
      }
    }
    // kty = 3 (RSA, RFC 8230 §4)
    3L => {
      let n = require_bytes(v, -1L, "RSA n")
      let e = require_bytes(v, -2L, "RSA e")
      let der = encode_rsa_pkcs1_der(n, e)
      let pk = @rsa.RsaPublicKey::from_pkcs1_der(der) catch {
        e => raise InvalidKey("RSA: " + @debug.to_string(e) + "")
      }
      Rsa(pubkey=pk)
    }
    other => raise InvalidKey("kty " + repr(other) + " not supported")
  }
}

///|
// Verify a COSE_Sign1 structure.
//
// `cose_sign1_bytes` may be a CBOR tag 18 wrapping the array, or just the
// 4-element array directly — both forms are accepted (RFC 9052 lets a
// tag be omitted when the application already knows the message kind).
//
// `payload` is the payload to verify against. If the COSE_Sign1 embeds a
// payload (third element != nil), pass the same bytes for `payload`. If
// the payload is detached (third element = nil), pass the external
// payload here; the function does not enforce the equality (a strict
// caller should compare beforehand).
//
// `external_aad` is the application-supplied AAD bound into the
// Sig_structure (RFC 9052 §4.4). Defaults to the empty byte string,
// which is the common case for WebAuthn / FIDO2.
pub fn verify_sign1(
  cose_sign1_bytes : Bytes,
  payload : Bytes,
  key : CoseKey,
  external_aad? : Bytes = b"",
) -> Bool raise CoseError {
  let parsed = @cbor.decode(cose_sign1_bytes) catch { e => raise CborDecode(e) }
  // Unwrap the outer Tag(18) if present.
  let arr_val = match parsed {
    Tag(18UL, inner) => inner
    other => other
  }
  let items = match arr_val {
    Array(xs) => xs
    _ => raise InvalidStructure("COSE_Sign1 must be a 4-element array")
  }
  if items.length() != 4 {
    raise InvalidStructure("COSE_Sign1 must have exactly 4 elements")
  }
  // Element 0: protected header, a CBOR-encoded map wrapped in a bstr.
  let protected_bytes = match items[0] {
    Bytes(b) => b
    _ => raise InvalidStructure("protected must be a bstr")
  }
  // Empty protected header is encoded as a zero-length bstr (RFC 9052
  // §3 — "If the protected map is empty, it is encoded as a
  // zero-length bstr"). For deterministic Sig_structure construction
  // we must use the wire bytes exactly as received.
  //
  // Element 1: unprotected header (a map; we don't need its contents
  // for signature verification).
  let unprotected = match items[1] {
    Map(_) => items[1]
    _ => raise InvalidStructure("unprotected must be a map")
  }
  //
  // Element 2: payload (bstr or null).
  match items[2] {
    Bytes(b) =>
      if b != payload {
        raise InvalidStructure(
          "embedded payload does not match supplied payload",
        )
      }
    Null => ()
    _ => raise InvalidStructure("payload must be bstr or null")
  }
  // Element 3: signature (bstr).
  let signature = match items[3] {
    Bytes(b) => b
    _ => raise InvalidStructure("signature must be a bstr")
  }
  // Resolve the algorithm. We require alg in the protected header and
  // reject an unprotected alg header to avoid algorithm-confusion inputs.
  let alg = resolve_alg(protected_bytes, unprotected)
  // Build the Sig_structure for Signature1 and CBOR-encode it.
  //   Sig_structure = ["Signature1", body_protected, external_aad, payload]
  // body_protected is the *bstr* from element 0 — i.e. the wrapping
  // bytes, not the decoded map. RFC 9052 §4.4 step 2.
  let sig_struct : @cbor.CborValue = Array([
    Text("Signature1"),
    Bytes(protected_bytes),
    Bytes(external_aad),
    Bytes(payload),
  ])
  let tbs = @cbor.encode(sig_struct)
  // Verify against the matching primitive.
  match key {
    OkpEd25519(pubkey~) =>
      if alg != EdDSA {
        raise AlgorithmKeyMismatch
      } else {
        pubkey.verify(tbs, signature)
      }
    Ec2P256(pubkey~) =>
      if alg != ES256 {
        raise AlgorithmKeyMismatch
      } else {
        if signature.length() != 64 {
          raise InvalidSignature("ES256 signature must be 64 bytes")
        }
        @p256.verify(pubkey, tbs, signature, @p256.SignatureFormat::Raw) catch {
          _ => false
        }
      }
    Ec2P384(pubkey~) =>
      if alg != ES384 {
        raise AlgorithmKeyMismatch
      } else {
        if signature.length() != 96 {
          raise InvalidSignature("ES384 signature must be 96 bytes")
        }
        @p384.verify(pubkey, tbs, signature, @p384.SignatureFormat::Raw) catch {
          _ => false
        }
      }
    Rsa(pubkey~) =>
      if alg != RS256 {
        raise AlgorithmKeyMismatch
      } else {
        pubkey.verify(tbs, signature, @rsa.HashAlg::Sha256) catch {
          _ => false
        }
      }
  }
}

// --- Helpers -------------------------------------------------------------

///|
fn resolve_alg(
  protected_bytes : Bytes,
  unprotected : @cbor.CborValue,
) -> CoseAlg raise CoseError {
  if count_int_label(unprotected, 1L) > 0 {
    raise InvalidStructure("alg must be protected, not unprotected")
  }
  if protected_bytes.length() > 0 {
    let m = @cbor.decode(protected_bytes) catch { e => raise CborDecode(e) }
    if @cbor.encode(m) != protected_bytes {
      raise InvalidStructure(
        "protected header must use preferred CBOR encoding",
      )
    }
    alg_from_protected_map(m)
  } else {
    raise InvalidStructure("protected alg required")
  }
}

///|
fn alg_from_protected_map(m : @cbor.CborValue) -> CoseAlg raise CoseError {
  match m {
    Map(_) => {
      let count = count_int_label(m, 1L)
      if count == 0 {
        raise InvalidStructure("protected alg required")
      }
      if count > 1 {
        raise InvalidStructure("duplicate protected alg header")
      }
      let id = match @cbor.map_get_int(m, 1L) {
        Some(Uint(n)) =>
          if n <= 0x7FFFFFFFUL {
            n.reinterpret_as_int64()
          } else {
            raise InvalidStructure("alg integer out of range")
          }
        Some(Nint(n)) => -1L - n.reinterpret_as_int64()
        _ => raise InvalidStructure("alg must be integer")
      }
      alg_from_id(id)
    }
    _ => raise InvalidStructure("protected header must be a map")
  }
}

///|
fn count_int_label(m : @cbor.CborValue, key : Int64) -> Int {
  match m {
    Map(pairs) => {
      let mut count = 0
      for pair in pairs {
        let (k, _) = pair
        match k {
          Uint(n) =>
            if key >= 0L && n == key.reinterpret_as_uint64() {
              count = count + 1
            }
          Nint(n) =>
            if key < 0L {
              let expected = (-1L - key).reinterpret_as_uint64()
              if n == expected {
                count = count + 1
              }
            }
          _ => ()
        }
      }
      count
    }
    _ => 0
  }
}

///|
fn int_label_of_key(k : @cbor.CborValue) -> Int64? {
  match k {
    Uint(n) =>
      if n <= 0x7FFFFFFFFFFFFFFFUL {
        Some(n.reinterpret_as_int64())
      } else {
        None
      }
    Nint(n) => Some(-1L - n.reinterpret_as_int64())
    _ => None
  }
}

///|
fn require_unique_int_labels(
  m : @cbor.CborValue,
  context : String,
) -> Unit raise CoseError {
  match m {
    Map(pairs) =>
      for i in 0..<pairs.length() {
        let (ki, _) = pairs[i]
        match int_label_of_key(ki) {
          None => ()
          Some(label) => {
            let mut j = i + 1
            while j < pairs.length() {
              let (kj, _) = pairs[j]
              match int_label_of_key(kj) {
                Some(other) =>
                  if other == label {
                    raise InvalidKey(context + " duplicate integer label")
                  }
                None => ()
              }
              j = j + 1
            }
          }
        }
      }
    _ => raise InvalidKey(context + " must be a map")
  }
}

///|
fn text_label_of_key(k : @cbor.CborValue) -> String? {
  match k {
    Text(s) => Some(s)
    _ => None
  }
}

///|
fn require_unique_text_labels(
  m : @cbor.CborValue,
  context : String,
) -> Unit raise CoseError {
  match m {
    Map(pairs) =>
      for i in 0..<pairs.length() {
        let (ki, _) = pairs[i]
        match text_label_of_key(ki) {
          None => ()
          Some(label) => {
            let mut j = i + 1
            while j < pairs.length() {
              let (kj, _) = pairs[j]
              match text_label_of_key(kj) {
                Some(other) =>
                  if other == label {
                    raise InvalidStructure(context + " duplicate text label")
                  }
                None => ()
              }
              j = j + 1
            }
          }
        }
      }
    _ => raise InvalidStructure(context + " must be a map")
  }
}

///|
fn require_int(
  m : @cbor.CborValue,
  key : Int64,
  field : String,
) -> Int64 raise CoseError {
  match @cbor.map_get_int(m, key) {
    Some(Uint(n)) => {
      if n > 0x7FFFFFFFFFFFFFFFUL {
        raise InvalidKey("\{field} integer out of range")
      }
      n.reinterpret_as_int64()
    }
    Some(Nint(n)) => -1L - n.reinterpret_as_int64()
    Some(_) => raise InvalidKey("\{field} must be an integer")
    None => raise InvalidKey("missing \{field}")
  }
}

///|
fn require_bytes(
  m : @cbor.CborValue,
  key : Int64,
  field : String,
) -> Bytes raise CoseError {
  match @cbor.map_get_int(m, key) {
    Some(Bytes(b)) => b
    Some(_) => raise InvalidKey("\{field} must be a byte string")
    None => raise InvalidKey("missing \{field}")
  }
}

///|
fn concat3(a : Bytes, b : Bytes, c : Bytes) -> Bytes {
  let total = a.length() + b.length() + c.length()
  let out = FixedArray::make(total, b'\x00')
  let mut i = 0
  for j = 0; j < a.length(); j = j + 1 {
    out[i] = a[j]
    i = i + 1
  }
  for j = 0; j < b.length(); j = j + 1 {
    out[i] = b[j]
    i = i + 1
  }
  for j = 0; j < c.length(); j = j + 1 {
    out[i] = c[j]
    i = i + 1
  }
  Bytes::from_array(out)
}

///|
// Encode an RSA PKCS#1 RSAPublicKey DER from raw `n` and `e` bytes
// (RFC 8017 §A.1.1):
//   RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
//
// COSE delivers `n` and `e` as straight unsigned big-endian numbers
// (RFC 8230 §4). DER INTEGER requires a leading 0x00 if the MSB is set,
// so we insert one only in that case.
fn encode_rsa_pkcs1_der(n : Bytes, e : Bytes) -> Bytes {
  let n_padded = pad_integer_msb(n)
  let e_padded = pad_integer_msb(e)
  let elem = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(@asn1.tag_integer, Integer(n_padded)),
      @asn1.Element::new(@asn1.tag_integer, Integer(e_padded)),
    ]),
  )
  @asn1.encode_der(elem)
}

///|
fn pad_integer_msb(b : Bytes) -> Bytes {
  if b.length() == 0 {
    return b"\x00"
  }
  if (b[0].to_int() & 0x80) == 0 {
    return b
  }
  let out = FixedArray::make(b.length() + 1, b'\x00')
  for i = 0; i < b.length(); i = i + 1 {
    out[i + 1] = b[i]
  }
  Bytes::from_array(out)
}

// --- WebAuthn / FIDO2 convenience ---------------------------------------

///|
pub(all) struct AttestationObject {
  fmt : String
  auth_data : Bytes
  // Parsed but not interpreted — the format-specific schema (packed /
  // tpm / fido-u2f / android-key / ...) is not part of this minimum.
  att_stmt : @cbor.CborValue
}

///|
// Parse a WebAuthn `attestationObject` CBOR map. The output is the raw
// authData buffer plus the attStmt CBOR value; verifying authData
// against the relying-party ID and the COSE_Sign1 / packed attestation
// signature is the caller's job.
//
// This is provided because `parse_cose_key` consumers almost always
// arrive via WebAuthn registration, and pulling authData out of the
// CBOR map is the one preliminary step every consumer would otherwise
// reinvent.
pub fn parse_attestation_object(
  cbor : Bytes,
) -> AttestationObject raise CoseError {
  let v = @cbor.decode(cbor) catch { e => raise CborDecode(e) }
  require_unique_text_labels(v, "attestationObject")
  let fmt = match @cbor.map_get_str(v, "fmt") {
    Some(Text(s)) => s
    _ => raise InvalidStructure("attestationObject missing fmt")
  }
  let auth_data = match @cbor.map_get_str(v, "authData") {
    Some(Bytes(b)) => b
    _ => raise InvalidStructure("attestationObject missing authData")
  }
  let att_stmt = match @cbor.map_get_str(v, "attStmt") {
    Some(x) => x
    None => raise InvalidStructure("attestationObject missing attStmt")
  }
  { fmt, auth_data, att_stmt }
}
