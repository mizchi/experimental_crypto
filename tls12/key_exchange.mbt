// TLS 1.2 ECDHE key exchange + ServerKeyExchange signature verification, and
// the derivation of the session's record keys. This wires the curve / RSA /
// EdDSA primitives into the PRF key schedule (RFC 5246 §7.4.3, §8.1; RFC 4492).
//
// ⚠️ SERVER AUTHENTICATION IS THE CALLER'S RESPONSIBILITY. This module
// authenticates the ServerKeyExchange *to the leaf certificate's key*, but it
// does NOT establish that the leaf is trusted. A complete, MITM-resistant
// handshake MUST also, before deriving/using the session keys:
//   1. chain-verify the server's Certificate message to a trust anchor and
//      check validity dates + serverAuth EKU (mizchi/pkix_verify), and
//   2. check the leaf's dNSName SANs against the expected hostname.
// Using `verify_server_key_exchange` alone is equivalent to accepting any
// self-signed certificate — an active attacker who presents their own cert and
// signs the SKE with the matching key will pass. (Issue #22 tracks wiring the
// chain/OCSP checks into a single verified TLS 1.2 entry point.)

///|
pub suberror KeyExchangeError {
  Pkix(@pkix.PkixError)
  PkixVerify(@pkix_verify.PkixVerifyError)
  UnsupportedSigScheme(Int)
  UnsupportedGroup(Int)
  KeyTypeMismatch(Int)
  CurveError(String)
} derive(Debug)

// ─── ServerKeyExchange signature verification ────────────────────────────────

///|
/// Verify the signature on an ECDHE `ServerKeyExchange` against the leaf
/// certificate's public key. The signed content is
/// `client_random || server_random || ServerECDHParams` (RFC 4492 §5.4).
///
/// Returns `true` only if the signature scheme matches the certificate key
/// type and the signature verifies. Primitive-level failures collapse to
/// `false`; an unsupported scheme / key mismatch raises so the caller can
/// distinguish "forged" from "can't evaluate".
///
/// ⚠️ This proves the SKE was signed by whoever holds `leaf_cert_der`'s key —
/// NOT that the leaf is trusted. You MUST separately chain-verify the leaf to a
/// trust anchor and check the hostname (see the module header), or an active
/// MITM with their own certificate passes.
pub fn verify_server_key_exchange(
  leaf_cert_der : Bytes,
  ske : ServerKeyExchange,
  client_random : Bytes,
  server_random : Bytes,
) -> Bool raise KeyExchangeError {
  let cert = @pkix.parse_certificate(leaf_cert_der) catch { e => raise Pkix(e) }
  let pubkey = @pkix_verify.extract_public_key(cert.tbs.subject_public_key_info) catch {
    e => raise PkixVerify(e)
  }
  let content = ske.signed_material(client_random, server_random)
  let sig = ske.signature()
  match (ske.sig_scheme(), pubkey) {
    (0x0403, P256(pk)) =>
      (try? @p256.verify(pk, content, sig, @p256.SignatureFormat::Der)).unwrap_or(
        false,
      )
    (0x0503, P384(pk)) =>
      (try? @p384.verify(pk, content, sig, @p384.SignatureFormat::Der)).unwrap_or(
        false,
      )
    (0x0401, Rsa(pk)) =>
      (try? pk.verify(content, sig, @rsa.HashAlg::Sha256)).unwrap_or(false)
    (0x0501, Rsa(pk)) =>
      (try? pk.verify(content, sig, @rsa.HashAlg::Sha384)).unwrap_or(false)
    (0x0601, Rsa(pk)) =>
      (try? pk.verify(content, sig, @rsa.HashAlg::Sha512)).unwrap_or(false)
    (0x0807, Ed25519(pk)) => pk.verify(content, sig)
    // A recognised scheme paired with the wrong key type.
    (0x0403, _)
    | (0x0503, _)
    | (0x0401, _)
    | (0x0501, _)
    | (0x0601, _)
    | (0x0807, _) => raise KeyTypeMismatch(ske.sig_scheme())
    (other, _) => raise UnsupportedSigScheme(other)
  }
}

// ─── ECDHE shared secret ──────────────────────────────────────────────────────

///|
/// Derive the client's ephemeral ECDHE public key for `named_group` from a
/// caller-supplied ephemeral private scalar (32 bytes for X25519 / P-256,
/// 48 bytes for P-384). The returned bytes go directly into the
/// ClientKeyExchange ECPoint.
pub fn ecdhe_client_public(
  named_group : Int,
  ephemeral_private : Bytes,
) -> Bytes raise KeyExchangeError {
  if named_group == group_x25519 {
    let sk = @x25519.PrivateKey::from_bytes(ephemeral_private) catch {
      _ =>
        raise CurveError("invalid ECDHE key material for the negotiated group")
    }
    sk.public_key().to_bytes()
  } else if named_group == group_secp256r1 {
    let sk = @p256.PrivateKey::from_bytes(ephemeral_private) catch {
      _ =>
        raise CurveError("invalid ECDHE key material for the negotiated group")
    }
    sk.public_key().to_uncompressed()
  } else if named_group == group_secp384r1 {
    let sk = @p384.PrivateKey::from_bytes(ephemeral_private) catch {
      _ =>
        raise CurveError("invalid ECDHE key material for the negotiated group")
    }
    sk.public_key().to_uncompressed()
  } else {
    raise UnsupportedGroup(named_group)
  }
}

///|
/// Compute the ECDHE pre_master_secret: the X-coordinate of
/// `ephemeral_private · server_public` (RFC 4492 §5.10 / RFC 7748). For
/// X25519 this is the 32-byte RFC 7748 output; for the NIST curves it is the
/// big-endian X coordinate (32 / 48 bytes).
pub fn ecdhe_pre_master_secret(
  named_group : Int,
  ephemeral_private : Bytes,
  server_public : Bytes,
) -> Bytes raise KeyExchangeError {
  if named_group == group_x25519 {
    let sk = @x25519.PrivateKey::from_bytes(ephemeral_private) catch {
      _ =>
        raise CurveError("invalid ECDHE key material for the negotiated group")
    }
    let pk = @x25519.PublicKey::from_bytes(server_public) catch {
      _ =>
        raise CurveError("invalid ECDHE key material for the negotiated group")
    }
    (@x25519.diffie_hellman(sk, pk) catch {
      _ => raise CurveError("X25519 shared secret is a low-order point")
    }).to_bytes()
  } else if named_group == group_secp256r1 {
    let sk = @p256.PrivateKey::from_bytes(ephemeral_private) catch {
      _ =>
        raise CurveError("invalid ECDHE key material for the negotiated group")
    }
    let pk = @p256.PublicKey::from_uncompressed(server_public) catch {
      _ =>
        raise CurveError("invalid ECDHE key material for the negotiated group")
    }
    sk.ecdh(pk)
  } else if named_group == group_secp384r1 {
    let sk = @p384.PrivateKey::from_bytes(ephemeral_private) catch {
      _ =>
        raise CurveError("invalid ECDHE key material for the negotiated group")
    }
    let pk = @p384.PublicKey::from_uncompressed(server_public) catch {
      _ =>
        raise CurveError("invalid ECDHE key material for the negotiated group")
    }
    sk.ecdh(pk)
  } else {
    raise UnsupportedGroup(named_group)
  }
}

// ─── session key derivation ───────────────────────────────────────────────────

///|
/// The record-protection keys for a session: the 48-byte master secret and a
/// directional `GcmKeys` for each side.
pub struct SessionKeys {
  master_secret : Bytes
  client : GcmKeys
  server : GcmKeys
}

///|
pub fn SessionKeys::master_secret(self : SessionKeys) -> Bytes {
  self.master_secret
}

///|
pub fn SessionKeys::client_keys(self : SessionKeys) -> GcmKeys {
  self.client
}

///|
pub fn SessionKeys::server_keys(self : SessionKeys) -> GcmKeys {
  self.server
}

///|
/// Derive the session keys for a GCM cipher suite from a master secret.
///
/// The AEAD key_block has no MAC keys; its layout is
/// `client_write_key || server_write_key || client_iv(4) || server_iv(4)`
/// (RFC 5246 §6.3, RFC 5288 §3 — the 4-byte salts are the implicit nonce part).
pub fn derive_session_keys(
  suite : CipherSuite,
  master_secret : Bytes,
  client_random : Bytes,
  server_random : Bytes,
) -> SessionKeys raise RecordError {
  let alg = suite.aead()
  let h = suite.prf_hash()
  let key_len = alg.key_size()
  let block = h.key_block(
    master_secret,
    client_random,
    server_random,
    2 * key_len + 8,
  )
  let client_key = Bytes::makei(key_len, fn(i) { block[i] })
  let server_key = Bytes::makei(key_len, fn(i) { block[key_len + i] })
  let client_iv = Bytes::makei(4, fn(i) { block[2 * key_len + i] })
  let server_iv = Bytes::makei(4, fn(i) { block[2 * key_len + 4 + i] })
  {
    master_secret,
    client: GcmKeys::new(alg, client_key, client_iv),
    server: GcmKeys::new(alg, server_key, server_iv),
  }
}
