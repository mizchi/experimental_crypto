// WebAuthn / FIDO2 verification (W3C WebAuthn Level 2, FIDO CTAP2). The
// verify-side composition of the workspace: CBOR (cose_cbor), the COSE key /
// authenticatorData formats, the EC/EdDSA/RSA verifiers, and pkix / pkix_verify
// for attestation certificate chains.
//
// Supported credential public keys: ES256 (P-256), ES384 (P-384), EdDSA
// (Ed25519). RS256 credential keys (e.g. Windows Hello) are not yet supported
// and raise UnsupportedAlgorithm. Attestation statement formats: packed (x5c
// and self), fido-u2f, none. Certificate-chain trust (x5c -> a trusted root /
// metadata) is the caller's job, as in TLS — verify_attestation returns the
// trust path.

///|
pub suberror WebAuthnError {
  Cbor(@cose_cbor.CborError)
  ParseError(String)
  UnsupportedAlgorithm(Int)
  UnsupportedKeyType(String)
  Pkix(@pkix.PkixError)
  PkixVerify(@pkix_verify.PkixVerifyError)
  // The cryptographic signature did not verify.
  SignatureInvalid
  // An attestation statement was structurally invalid.
  AttestationFailure(String)
  // A clientDataJSON field did not match what was expected.
  ClientDataInvalid(String)
} derive(Debug)

// ─── small byte/CBOR helpers ─────────────────────────────────────────────

///|
fn cat(a : Bytes, b : Bytes) -> Bytes {
  Bytes::makei(a.length() + b.length(), fn(i) {
    if i < a.length() {
      a[i]
    } else {
      b[i - a.length()]
    }
  })
}

///|
fn slice(b : Bytes, start : Int, len : Int) -> Bytes {
  Bytes::makei(len, fn(i) { b[start + i] })
}

///|
fn map_int(
  m : @cose_cbor.CborValue,
  key : Int64,
  what : String,
) -> @cose_cbor.CborValue raise WebAuthnError {
  match @cose_cbor.map_get_int(m, key) {
    Some(v) => v
    None => raise ParseError("missing CBOR key " + what)
  }
}

///|
fn cbor_int(
  v : @cose_cbor.CborValue,
  what : String,
) -> Int64 raise WebAuthnError {
  match v {
    Uint(n) => n.reinterpret_as_int64()
    Nint(n) => -1L - n.reinterpret_as_int64()
    _ => raise ParseError("expected CBOR int for " + what)
  }
}

///|
fn cbor_bytes(
  v : @cose_cbor.CborValue,
  what : String,
) -> Bytes raise WebAuthnError {
  match v {
    Bytes(b) => b
    _ => raise ParseError("expected CBOR bytes for " + what)
  }
}

// ─── COSE_Key (RFC 9052 §7 / RFC 8152) ───────────────────────────────────

///|
/// A credential public key parsed from a COSE_Key, ready to verify with.
pub(all) enum CredentialPublicKey {
  Es256(@p256.PublicKey)
  Es384(@p384.PublicKey)
  EdDSA(@ed25519.PublicKey)
}

///|
/// Parse a COSE_Key (CBOR) into a verifiable credential public key.
pub fn parse_cose_key(cose : Bytes) -> CredentialPublicKey raise WebAuthnError {
  let m = @cose_cbor.decode(cose) catch { e => raise Cbor(e) }
  let kty = cbor_int(map_int(m, 1L, "kty"), "kty")
  let alg = cbor_int(map_int(m, 3L, "alg"), "alg")
  match kty {
    // EC2
    2L => {
      let crv = cbor_int(map_int(m, -1L, "crv"), "crv")
      let x = cbor_bytes(map_int(m, -2L, "x"), "x")
      let y = cbor_bytes(map_int(m, -3L, "y"), "y")
      let point = cat(b"\x04", cat(x, y))
      match crv {
        1L => {
          if alg != -7L {
            raise UnsupportedAlgorithm(alg.to_int())
          }
          Es256(
            @p256.PublicKey::from_uncompressed(point) catch {
              e => raise ParseError(repr(e))
            },
          )
        }
        2L => {
          if alg != -35L {
            raise UnsupportedAlgorithm(alg.to_int())
          }
          Es384(
            @p384.PublicKey::from_uncompressed(point) catch {
              e => raise ParseError(repr(e))
            },
          )
        }
        _ => raise UnsupportedKeyType("EC2 crv " + crv.to_string())
      }
    }
    // OKP (Ed25519)
    1L => {
      let crv = cbor_int(map_int(m, -1L, "crv"), "crv")
      if crv != 6L {
        raise UnsupportedKeyType("OKP crv " + crv.to_string())
      }
      if alg != -8L {
        raise UnsupportedAlgorithm(alg.to_int())
      }
      let x = cbor_bytes(map_int(m, -2L, "x"), "x")
      EdDSA(
        @ed25519.PublicKey::from_bytes(x) catch {
          e => raise ParseError(repr(e))
        },
      )
    }
    // RSA (kty 3) — RS256 not yet supported.
    3L => raise UnsupportedAlgorithm(alg.to_int())
    _ => raise UnsupportedKeyType("kty " + kty.to_string())
  }
}

///|
/// Verify `signature` over `message` with a parsed credential public key.
/// ECDSA signatures are DER-encoded (the WebAuthn assertion encoding); Ed25519
/// is the raw 64-byte form.
pub fn CredentialPublicKey::verify(
  self : CredentialPublicKey,
  message : Bytes,
  signature : Bytes,
) -> Bool {
  match self {
    Es256(pk) =>
      (try? @p256.verify(pk, message, signature, @p256.SignatureFormat::Der)).unwrap_or(
        false,
      )
    Es384(pk) =>
      (try? @p384.verify(pk, message, signature, @p384.SignatureFormat::Der)).unwrap_or(
        false,
      )
    EdDSA(pk) => pk.verify(message, signature)
  }
}

// ─── authenticatorData (WebAuthn §6.1) ───────────────────────────────────

///|
/// Parsed authenticatorData.
pub(all) struct AuthenticatorData {
  rp_id_hash : Bytes
  flags : Int
  sign_count : UInt
  // Present iff the AT (attested credential data) flag is set:
  aaguid : Bytes?
  credential_id : Bytes?
  credential_public_key : Bytes? // raw COSE_Key bytes
  raw : Bytes
}

///|
pub fn AuthenticatorData::user_present(self : AuthenticatorData) -> Bool {
  (self.flags & 0x01) != 0
}

///|
pub fn AuthenticatorData::user_verified(self : AuthenticatorData) -> Bool {
  (self.flags & 0x04) != 0
}

///|
pub fn AuthenticatorData::attested_credential_data_present(
  self : AuthenticatorData,
) -> Bool {
  (self.flags & 0x40) != 0
}

///|
/// Parse authenticatorData: rpIdHash(32) || flags(1) || signCount(4) ||
/// [attestedCredentialData] || [extensions].
pub fn parse_authenticator_data(
  b : Bytes,
) -> AuthenticatorData raise WebAuthnError {
  if b.length() < 37 {
    raise ParseError("authenticatorData too short")
  }
  let rp_id_hash = slice(b, 0, 32)
  let flags = b[32].to_int()
  let sign_count = ((b[33].to_int() << 24) |
  (b[34].to_int() << 16) |
  (b[35].to_int() << 8) |
  b[36].to_int()).reinterpret_as_uint()
  let at = (flags & 0x40) != 0
  if !at {
    return {
      rp_id_hash,
      flags,
      sign_count,
      aaguid: None,
      credential_id: None,
      credential_public_key: None,
      raw: b,
    }
  }
  // attestedCredentialData: aaguid(16) || credIdLen(2) || credId || COSE key.
  if b.length() < 55 {
    raise ParseError("attestedCredentialData truncated")
  }
  let aaguid = slice(b, 37, 16)
  let cred_id_len = (b[53].to_int() << 8) | b[54].to_int()
  if b.length() < 55 + cred_id_len {
    raise ParseError("credentialId truncated")
  }
  let cred_id = slice(b, 55, cred_id_len)
  let key_start = 55 + cred_id_len
  // The COSE key is the first CBOR item; decode_first tells us its length so we
  // can isolate it (extensions, if any, follow).
  let rest = slice(b, key_start, b.length() - key_start)
  let (_, consumed) = @cose_cbor.decode_first(rest) catch { e => raise Cbor(e) }
  let cose_key = slice(rest, 0, consumed)
  {
    rp_id_hash,
    flags,
    sign_count,
    aaguid: Some(aaguid),
    credential_id: Some(cred_id),
    credential_public_key: Some(cose_key),
    raw: b,
  }
}

// ─── assertion (WebAuthn §6.3.3 / verify step) ───────────────────────────

///|
/// Verify a WebAuthn assertion signature: the credential signs
/// `authenticatorData || clientDataHash`. `credential_cose_key` is the COSE_Key
/// stored at registration. Returns whether the signature is valid.
pub fn verify_assertion(
  credential_cose_key : Bytes,
  authenticator_data : Bytes,
  client_data_hash : Bytes,
  signature : Bytes,
) -> Bool raise WebAuthnError {
  let key = parse_cose_key(credential_cose_key)
  key.verify(cat(authenticator_data, client_data_hash), signature)
}

// ─── attestation (WebAuthn §6.5) ─────────────────────────────────────────

///|
/// The result of a successful attestation verification.
pub(all) struct AttestationResult {
  fmt : String
  credential_id : Bytes
  credential_public_key : Bytes // COSE_Key bytes
  sign_count : UInt
  aaguid : Bytes
  // The attestation certificate chain (x5c), leaf first, for the caller to
  // validate to a trusted root / FIDO metadata. Empty for self / none.
  trust_path : Array[Bytes]
}

///|
// Verify `signature` (DER for ECDSA / RSA, raw for Ed25519) over `message`
// using the public key of an attestation certificate (x5c leaf).
fn verify_with_certificate(
  cert_der : Bytes,
  message : Bytes,
  signature : Bytes,
) -> Bool raise WebAuthnError {
  let cert = @pkix.parse_certificate(cert_der) catch { e => raise Pkix(e) }
  let pk = @pkix_verify.extract_public_key(cert.tbs.subject_public_key_info) catch {
    e => raise PkixVerify(e)
  }
  match pk {
    P256(k) =>
      (try? @p256.verify(k, message, signature, @p256.SignatureFormat::Der)).unwrap_or(
        false,
      )
    P384(k) =>
      (try? @p384.verify(k, message, signature, @p384.SignatureFormat::Der)).unwrap_or(
        false,
      )
    Ed25519(k) => k.verify(message, signature)
    Rsa(k) =>
      (try? k.verify(message, signature, @rsa.HashAlg::Sha256)).unwrap_or(false)
  }
}

///|
fn require_attested(
  ad : AuthenticatorData,
) -> (Bytes, Bytes, Bytes) raise WebAuthnError {
  match (ad.credential_id, ad.credential_public_key, ad.aaguid) {
    (Some(id), Some(key), Some(g)) => (id, key, g)
    _ => raise AttestationFailure("no attested credential data")
  }
}

///|
/// Verify a WebAuthn attestation object (CBOR { fmt, authData, attStmt }) given
/// the clientDataHash. Supports the `packed` (x5c and self), `fido-u2f`, and
/// `none` formats. On success returns the credential to register, including the
/// x5c trust path for the caller to validate to a trusted root.
pub fn verify_attestation(
  attestation_object : Bytes,
  client_data_hash : Bytes,
) -> AttestationResult raise WebAuthnError {
  let obj = @cose_cbor.decode(attestation_object) catch { e => raise Cbor(e) }
  let fmt = match @cose_cbor.map_get_str(obj, "fmt") {
    Some(Text(s)) => s
    _ => raise ParseError("attestationObject.fmt")
  }
  let auth_data_bytes = match @cose_cbor.map_get_str(obj, "authData") {
    Some(Bytes(b)) => b
    _ => raise ParseError("attestationObject.authData")
  }
  let att_stmt = match @cose_cbor.map_get_str(obj, "attStmt") {
    Some(v) => v
    None => raise ParseError("attestationObject.attStmt")
  }
  let ad = parse_authenticator_data(auth_data_bytes)
  let (cred_id, cred_key, aaguid) = require_attested(ad)
  let signed = cat(auth_data_bytes, client_data_hash)
  match fmt {
    "none" => ()
    "packed" => verify_packed(att_stmt, signed, cred_key, ad)
    "fido-u2f" =>
      verify_fido_u2f(att_stmt, ad, cred_id, cred_key, client_data_hash)
    _ => raise AttestationFailure("unsupported attestation format " + fmt)
  }
  {
    fmt,
    credential_id: cred_id,
    credential_public_key: cred_key,
    sign_count: ad.sign_count,
    aaguid,
    trust_path: x5c_of(att_stmt),
  }
}

///|
fn x5c_of(att_stmt : @cose_cbor.CborValue) -> Array[Bytes] {
  match @cose_cbor.map_get_str(att_stmt, "x5c") {
    Some(Array(certs)) => {
      let out : Array[Bytes] = []
      for c in certs {
        match c {
          Bytes(b) => out.push(b)
          _ => ()
        }
      }
      out
    }
    _ => []
  }
}

///|
// packed (WebAuthn §8.2): { alg, sig, [x5c] }. With x5c, the attestation cert
// signs authData||clientDataHash; without, the credential key self-signs it.
fn verify_packed(
  att_stmt : @cose_cbor.CborValue,
  signed : Bytes,
  cred_key : Bytes,
  _ad : AuthenticatorData,
) -> Unit raise WebAuthnError {
  let sig = match @cose_cbor.map_get_str(att_stmt, "sig") {
    Some(Bytes(b)) => b
    _ => raise AttestationFailure("packed.sig")
  }
  let x5c = x5c_of(att_stmt)
  let ok = if x5c.length() > 0 {
    verify_with_certificate(x5c[0], signed, sig)
  } else {
    parse_cose_key(cred_key).verify(signed, sig)
  }
  if !ok {
    raise SignatureInvalid
  }
}

///|
// fido-u2f (WebAuthn §8.6): the cert signs
//   0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F
// where publicKeyU2F = 0x04 || x || y from the credential's COSE EC2 key.
fn verify_fido_u2f(
  att_stmt : @cose_cbor.CborValue,
  ad : AuthenticatorData,
  cred_id : Bytes,
  cred_key : Bytes,
  client_data_hash : Bytes,
) -> Unit raise WebAuthnError {
  let sig = match @cose_cbor.map_get_str(att_stmt, "sig") {
    Some(Bytes(b)) => b
    _ => raise AttestationFailure("u2f.sig")
  }
  let x5c = x5c_of(att_stmt)
  if x5c.length() != 1 {
    raise AttestationFailure("fido-u2f requires exactly one x5c cert")
  }
  // publicKeyU2F from the COSE EC2 (P-256) credential key.
  let m = @cose_cbor.decode(cred_key) catch { e => raise Cbor(e) }
  let x = cbor_bytes(map_int(m, -2L, "x"), "x")
  let y = cbor_bytes(map_int(m, -3L, "y"), "y")
  if x.length() != 32 || y.length() != 32 {
    raise AttestationFailure("fido-u2f credential is not P-256")
  }
  let public_key_u2f = cat(b"\x04", cat(x, y))
  let verification_data = cat(
    cat(cat(b"\x00", ad.rp_id_hash), client_data_hash),
    cat(cred_id, public_key_u2f),
  )
  if !verify_with_certificate(x5c[0], verification_data, sig) {
    raise SignatureInvalid
  }
}

// ─── clientDataJSON (WebAuthn §5.8.1 / §7) ───────────────────────────────

///|
/// SHA-256 of the clientDataJSON bytes (the hash signed by the authenticator).
pub fn client_data_hash(client_data_json : Bytes) -> Bytes {
  @hash.sha256(client_data_json)
}

///|
/// Parse and validate clientDataJSON: the `type`, `challenge` (base64url, as
/// the relying party issued it), and `origin` MUST match. Pass the exact JSON
/// text the authenticator hashed.
pub fn verify_client_data(
  client_data_json : String,
  expected_type : String,
  expected_challenge_b64url : String,
  expected_origin : String,
) -> Unit raise WebAuthnError {
  let j = @json.parse(client_data_json[:]) catch {
    _ => raise ClientDataInvalid("not JSON")
  }
  let get = fn(k : String) -> String raise WebAuthnError {
    match j {
      Object(m) =>
        match m.get(k) {
          Some(String(s)) => s
          _ => raise ClientDataInvalid("missing/invalid " + k)
        }
      _ => raise ClientDataInvalid("not an object")
    }
  }
  if get("type") != expected_type {
    raise ClientDataInvalid("type")
  }
  if get("challenge") != expected_challenge_b64url {
    raise ClientDataInvalid("challenge")
  }
  if get("origin") != expected_origin {
    raise ClientDataInvalid("origin")
  }
}
