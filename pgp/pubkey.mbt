// OpenPGP Public-Key Packet (RFC 9580 §5.5.2 / RFC 4880 §5.5.2).
//
// We only parse v4 keys (the dominant deployed format). v6 (RFC 9580 new
// keys) has a slightly different layout and is left as future work.
//
// Supported pubkey algorithms:
//   - 1   RSA (Encrypt or Sign)
//   - 19  ECDSA  (with curve OID)
//   - 22  EdDSA legacy / Ed25519
//
// Not supported: DSA (17), ECDH (18), ElGamal (16, 20), Ed448, X25519, X448.

///|
pub(all) enum PgpPublicKey {
  Ed25519(@ed25519.PublicKey)
  Rsa(@rsa.RsaPublicKey)
  EcdsaP256(@p256.PublicKey)
  EcdsaP384(@p384.PublicKey)
}

///|
pub(all) struct PgpPublicKeyPacket {
  version : Int // 4
  creation_time : UInt
  algo : Int
  key : PgpPublicKey
}

///|
// Algorithm IDs (RFC 4880 §9.1).
pub let algo_rsa_sign_or_encrypt : Int = 1

///|
pub let algo_ecdsa : Int = 19

///|
pub let algo_eddsa_legacy : Int = 22

///|
// Hash algorithm IDs (RFC 4880 §9.4).
pub let hash_sha256 : Int = 8

///|
pub let hash_sha384 : Int = 9

///|
pub let hash_sha512 : Int = 10

///|
/// Parse the body of a Public-Key Packet (tag 6).
pub fn parse_public_key_packet(
  body : Bytes,
) -> PgpPublicKeyPacket raise PgpError {
  if body.length() < 6 {
    raise PacketTooShort("public-key packet header")
  }
  let version = body[0].to_int()
  if version != 4 {
    raise UnsupportedPacketVersion(version)
  }
  let creation_time =
    (body[1].to_uint() << 24) |
    (body[2].to_uint() << 16) |
    (body[3].to_uint() << 8) |
    body[4].to_uint()
  let algo = body[5].to_int()
  let key = if algo == algo_rsa_sign_or_encrypt {
    let (n_bytes, n_consumed) = read_mpi(body, 6)
    let (e_bytes, _) = read_mpi(body, 6 + n_consumed)
    let n = BigInt::from_octets(n_bytes[:])
    let e = BigInt::from_octets(e_bytes[:])
    Rsa({ n, e, n_bytes_len: n_bytes.length() })
  } else if algo == algo_eddsa_legacy {
    // RFC 4880bis §13.3: 1-byte OID length || OID bytes || MPI (0x40 || raw_pubkey)
    let oid_len = body[6].to_int()
    if 7 + oid_len > body.length() {
      raise PacketTooShort("eddsa OID")
    }
    // We trust the OID is ed25519 (1.3.6.1.4.1.11591.15.1) — caller can
    // double-check via `creation_time` / fingerprint if needed.
    let (mpi_bytes, _) = read_mpi(body, 7 + oid_len)
    // MPI is 0x40 || raw 32-byte ed25519 pubkey (33 bytes total).
    if mpi_bytes.length() != 33 || mpi_bytes[0] != b'\x40' {
      raise InvalidMpi("eddsa point encoding")
    }
    let raw = Bytes::makei(32, fn(i) { mpi_bytes[i + 1] })
    let pk = @ed25519.PublicKey::from_bytes(raw) catch {
      _ => raise InvalidMpi("ed25519 pubkey")
    }
    Ed25519(pk)
  } else if algo == algo_ecdsa {
    // RFC 4880 §5.5.2: 1-byte OID length || OID bytes || MPI(SEC1 uncompressed point)
    let oid_len = body[6].to_int()
    if 7 + oid_len > body.length() {
      raise PacketTooShort("ecdsa OID")
    }
    let oid_bytes = bytes_slice(body, 7, 7 + oid_len)
    let (mpi_bytes, _) = read_mpi(body, 7 + oid_len)
    // MPI is the SEC1 uncompressed point: 0x04 || X || Y.
    if is_p256_oid(oid_bytes) {
      let pk = @p256.PublicKey::from_uncompressed(mpi_bytes) catch {
        _ => raise InvalidMpi("p256 ecdsa pubkey")
      }
      EcdsaP256(pk)
    } else if is_p384_oid(oid_bytes) {
      let pk = @p384.PublicKey::from_uncompressed(mpi_bytes) catch {
        _ => raise InvalidMpi("p384 ecdsa pubkey")
      }
      EcdsaP384(pk)
    } else {
      raise UnsupportedPubkeyAlgo(algo)
    }
  } else {
    raise UnsupportedPubkeyAlgo(algo)
  }
  { version, creation_time, algo, key }
}

///|
// secp256r1 OID 1.2.840.10045.3.1.7 encoded as 1-byte-length-prefix-free
// DER content: 2A 86 48 CE 3D 03 01 07 (8 bytes).
fn is_p256_oid(b : Bytes) -> Bool {
  if b.length() != 8 {
    return false
  }
  let expected : Bytes = b"\x2a\x86\x48\xce\x3d\x03\x01\x07"
  for i = 0; i < 8; i = i + 1 {
    if b[i] != expected[i] {
      return false
    }
  }
  true
}

///|
// secp384r1 OID 1.3.132.0.34 → 2B 81 04 00 22 (5 bytes).
fn is_p384_oid(b : Bytes) -> Bool {
  if b.length() != 5 {
    return false
  }
  let expected : Bytes = b"\x2b\x81\x04\x00\x22"
  for i = 0; i < 5; i = i + 1 {
    if b[i] != expected[i] {
      return false
    }
  }
  true
}

///|
/// Parse a `-----BEGIN PGP PUBLIC KEY BLOCK-----` armor and return the
/// first Public-Key Packet's parsed contents. Sub-keys (algorithm 14
/// packets) and user IDs are skipped.
pub fn parse_pubkey_armor(
  armor : String,
) -> PgpPublicKeyPacket raise PgpError {
  let a = decode_armor(armor)
  let packets = parse_packets(a.data)
  for p in packets {
    if p.tag == 6 {
      return parse_public_key_packet(p.body)
    }
  }
  raise ArmorMalformed("no Public-Key packet in PGP PUBLIC KEY BLOCK")
}
