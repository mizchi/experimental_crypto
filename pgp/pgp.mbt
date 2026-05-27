// mizchi/pgp — OpenPGP signature verification and detached signing.
//
// Scope:
//   - Verify a `-----BEGIN PGP SIGNATURE-----` armor against a message
//     and an OpenPGP public key.
//   - Supported pubkey/hash algo combos:
//       Ed25519 (EdDSA legacy, algo 22) + SHA-256/384/512
//       RSA (algo 1) + SHA-256/384/512
//       ECDSA P-256 (algo 19) + SHA-256
//       ECDSA P-384 (algo 19) + SHA-384
//
// Out of scope: key generation, partial-body streaming lengths, subkey
// selection, trust signatures, revocation.

///|
/// Verify a detached OpenPGP signature.
///   - `signature_armor`: a `-----BEGIN PGP SIGNATURE-----` block.
///   - `message`: the bytes that were signed.
///   - `pubkey`: the signer's public key (parsed from a PGP PUBLIC KEY BLOCK
///     via `parse_pubkey_armor` — we only check the primary key here, no
///     subkey traversal).
pub fn verify_armor(
  signature_armor : String,
  message : Bytes,
  pubkey : PgpPublicKey,
) -> Bool raise PgpError {
  let a = decode_armor(signature_armor)
  let packets = parse_packets(a.data)
  let sig = find_signature_packet(packets)
  if sig.sig_type != 0x00 && sig.sig_type != 0x01 {
    // 0x00 = signature of a binary document
    // 0x01 = signature of a canonical text document (caller's
    //        responsibility to feed CRLF-normalised bytes if so)
    raise UnsupportedSignatureType(sig.sig_type)
  }
  let digest = compute_signature_digest(sig, message)
  // Quick check: leftmost 16 bits of digest must match sig.left16.
  let left = (digest[0].to_uint() << 8) | digest[1].to_uint()
  if left != sig.left16 {
    return false
  }
  // Dispatch on (pubkey, pubkey_algo).
  match pubkey {
    Ed25519(pk) =>
      // v4 uses algo 22 (EdDSA legacy, MPI-wrapped r||s); v6 uses algo 27
      // (raw 64-byte signature, no MPI). Reject mismatched pairings to
      // keep representation strict.
      if sig.version == 6 {
        if sig.pubkey_algo != algo_ed25519 {
          raise UnsupportedPubkeyAlgo(sig.pubkey_algo)
        }
        // RFC 9580 §5.2.3.3.4: Ed25519 v6 signature is 64 raw bytes.
        if sig.signature_material.length() != 64 {
          raise InvalidMpi("v6 ed25519 signature must be 64 bytes")
        }
        pk.verify(digest, sig.signature_material)
      } else if sig.pubkey_algo != algo_eddsa_legacy {
        raise UnsupportedPubkeyAlgo(sig.pubkey_algo)
      } else {
        // Signature material: MPI r || MPI s, each 256 bits. Reject trailing
        // garbage so the signature representation is strict (otherwise an
        // attacker could create multiple armors that all verify against the
        // same key+message, breaking non-malleability).
        let (r_bytes, r_used) = read_mpi(sig.signature_material, 0)
        let (s_bytes, s_used) = read_mpi(sig.signature_material, r_used)
        if r_used + s_used != sig.signature_material.length() {
          raise InvalidMpi("trailing bytes after ed25519 (r, s)")
        }
        let raw_sig = build_ed25519_sig(r_bytes, s_bytes)
        pk.verify(digest, raw_sig)
      }
    Rsa(pk) => {
      if sig.pubkey_algo != algo_rsa_sign_or_encrypt {
        raise UnsupportedPubkeyAlgo(sig.pubkey_algo)
      }
      let (s_bytes, s_used) = read_mpi(sig.signature_material, 0)
      if s_used != sig.signature_material.length() {
        raise InvalidMpi("trailing bytes after RSA signature MPI")
      }
      // Left-pad to modulus length (RSA signatures are full-block).
      let padded = pad_left(s_bytes, pk.n_bytes_len)
      // Map OpenPGP hash algo → @rsa HashAlg.
      let hash_alg = if sig.hash_algo == hash_sha256 {
        @rsa.HashAlg::Sha256
      } else if sig.hash_algo == hash_sha384 {
        @rsa.HashAlg::Sha384
      } else if sig.hash_algo == hash_sha512 {
        @rsa.HashAlg::Sha512
      } else {
        raise UnsupportedHashAlgo(sig.hash_algo)
      }
      // @rsa.verify takes raw message and applies the hash internally.
      // The OpenPGP signed data is exactly what compute_signature_digest
      // would pre-hash; we need to give @rsa the pre-hash input.
      let pre_hash_input = build_pre_hash_input(sig, message)
      pk.verify(pre_hash_input, padded, hash_alg) catch {
        _ => false
      }
    }
    EcdsaP256(pk) => {
      if sig.pubkey_algo != algo_ecdsa {
        raise UnsupportedPubkeyAlgo(sig.pubkey_algo)
      }
      if sig.hash_algo != hash_sha256 {
        raise UnsupportedHashAlgo(sig.hash_algo)
      }
      let (r_bytes, r_used) = read_mpi(sig.signature_material, 0)
      let (s_bytes, s_used) = read_mpi(sig.signature_material, r_used)
      if r_used + s_used != sig.signature_material.length() {
        raise InvalidMpi("trailing bytes after p256 (r, s)")
      }
      let raw_sig = build_ecdsa_raw(r_bytes, s_bytes, 32)
      let pre = build_pre_hash_input(sig, message)
      @p256.verify(pk, pre, raw_sig, @p256.SignatureFormat::Raw) catch {
        _ => false
      }
    }
    EcdsaP384(pk) => {
      if sig.pubkey_algo != algo_ecdsa {
        raise UnsupportedPubkeyAlgo(sig.pubkey_algo)
      }
      if sig.hash_algo != hash_sha384 {
        raise UnsupportedHashAlgo(sig.hash_algo)
      }
      let (r_bytes, r_used) = read_mpi(sig.signature_material, 0)
      let (s_bytes, s_used) = read_mpi(sig.signature_material, r_used)
      if r_used + s_used != sig.signature_material.length() {
        raise InvalidMpi("trailing bytes after p384 (r, s)")
      }
      let raw_sig = build_ecdsa_raw(r_bytes, s_bytes, 48)
      let pre = build_pre_hash_input(sig, message)
      @p384.verify(pk, pre, raw_sig, @p384.SignatureFormat::Raw) catch {
        _ => false
      }
    }
  }
}

///|
fn find_signature_packet(
  packets : Array[PgpPacket],
) -> PgpSignature raise PgpError {
  for p in packets {
    if p.tag == 2 {
      return parse_signature_packet(p.body)
    }
  }
  raise ArmorMalformed("no Signature packet in PGP SIGNATURE armor")
}

///|
fn build_ed25519_sig(r : Bytes, s : Bytes) -> Bytes raise PgpError {
  if r.length() > 32 || s.length() > 32 {
    raise InvalidMpi("ed25519 r/s too long")
  }
  let r_pad = pad_left(r, 32)
  let s_pad = pad_left(s, 32)
  Bytes::makei(64, fn(i) { if i < 32 { r_pad[i] } else { s_pad[i - 32] } })
}

///|
fn build_ecdsa_raw(r : Bytes, s : Bytes, half : Int) -> Bytes raise PgpError {
  let r_pad = pad_left(r, half)
  let s_pad = pad_left(s, half)
  Bytes::makei(half * 2, fn(i) {
    if i < half {
      r_pad[i]
    } else {
      s_pad[i - half]
    }
  })
}

///|
fn pad_left(b : Bytes, target : Int) -> Bytes raise PgpError {
  if b.length() > target {
    raise InvalidMpi(
      "integer too wide: " + b.length().to_string() + " > " + target.to_string(),
    )
  }
  let pad = target - b.length()
  Bytes::makei(target, fn(i) { if i < pad { b'\x00' } else { b[i - pad] } })
}

///|
// The bytes that @rsa.verify / @p256.verify / @p384.verify will pre-hash
// internally to produce the digest. For v4 this is `message || prelude ||
// trailer`; for v6 it is `salt || message || prelude || trailer` with the
// trailer's version byte set to 0x06.
fn build_pre_hash_input(sig : PgpSignature, message : Bytes) -> Bytes {
  let prelude = sig.hashed_subpackets_raw
  let prelude_len = prelude.length()
  let salt_len = sig.salt.length()
  let total = salt_len + message.length() + prelude_len + 6
  let buf = FixedArray::make(total, b'\x00')
  let mut off = 0
  for i = 0; i < salt_len; i = i + 1 {
    buf[off + i] = sig.salt[i]
  }
  off = off + salt_len
  for i = 0; i < message.length(); i = i + 1 {
    buf[off + i] = message[i]
  }
  off = off + message.length()
  for i = 0; i < prelude_len; i = i + 1 {
    buf[off + i] = prelude[i]
  }
  off = off + prelude_len
  buf[off] = if sig.version == 6 { b'\x06' } else { b'\x04' }
  buf[off + 1] = b'\xff'
  buf[off + 2] = ((prelude_len.reinterpret_as_uint() >> 24) & 0xffU).to_byte()
  buf[off + 3] = ((prelude_len.reinterpret_as_uint() >> 16) & 0xffU).to_byte()
  buf[off + 4] = ((prelude_len.reinterpret_as_uint() >> 8) & 0xffU).to_byte()
  buf[off + 5] = (prelude_len.reinterpret_as_uint() & 0xffU).to_byte()
  Bytes::makei(total, fn(j) { buf[j] })
}

// ─── sign side ───────────────────────────────────────────────────────────
//
// Out of scope: building a key (with user IDs / self-cert) for export.
// We just emit a detached signature armor over `message`.

///|
pub(all) enum PgpPrivateKey {
  Ed25519(@ed25519.PrivateKey)
  Rsa(@rsa.RsaPrivateKey)
  EcdsaP256(@p256.PrivateKey)
  EcdsaP384(@p384.PrivateKey)
}

///|
/// Sign `message` and produce a detached `-----BEGIN PGP SIGNATURE-----`
/// armor. The signature type is 0x00 (binary document) and the algorithm
/// pairing is fixed:
///   Ed25519 + SHA-512
///   RSA + caller-specified hash (sha256/sha384/sha512)
///   P-256 + SHA-256
///   P-384 + SHA-384
///
/// `hash_algo`: 8=sha256, 9=sha384, 10=sha512 (OpenPGP IDs, RFC 4880 §9.4).
/// Ignored for Ed25519/ECDSA where the hash is dictated by the curve.
///
/// `creation_time`: signature-creation timestamp (UNIX seconds), emitted
/// as the first hashed subpacket. Defaults to a fixed reference value
/// (2023-11-14, 1700000000) for reproducibility; pass the current time
/// when producing real signatures so verifiers that enforce "signed
/// within the last N hours" policies don't reject them.
///
/// `version`: 4 (default) or 6. Selects the Signature Packet wire format.
/// When `version=6` we emit:
///   - the v6 packet layout with 4-byte hashed/unhashed length fields
///   - `salt` as the v6 salt field. The default is empty only for
///     reproducible tests; production callers should pass a random salt with
///     the algorithm-specific minimum from RFC 9580 §5.2.3.3.
///   - Ed25519 raises to algo 27 with raw 64-byte signature material (no MPI)
///   - v6 trailer byte 0x06
pub fn sign_armor(
  privkey : PgpPrivateKey,
  message : Bytes,
  hash_algo? : Int = 0,
  creation_time? : UInt = 1700000000U,
  version? : Int = 4,
  salt? : Bytes = b"",
) -> String raise PgpError {
  if version != 4 && version != 6 {
    raise UnsupportedPacketVersion(version)
  }
  if version != 6 && salt.length() != 0 {
    raise Crypto("OpenPGP signature salt is only valid for v6 signatures")
  }
  if salt.length() > 255 {
    raise Crypto("OpenPGP v6 signature salt must fit in one octet")
  }
  let chosen_hash = if hash_algo == 0 {
    match privkey {
      Ed25519(_) => hash_sha512
      Rsa(_) => hash_sha256
      EcdsaP256(_) => hash_sha256
      EcdsaP384(_) => hash_sha384
    }
  } else {
    hash_algo
  }
  let pubkey_algo = match privkey {
    // v4 EdDSA legacy is algo 22; v6 Ed25519 is algo 27.
    Ed25519(_) => if version == 6 { algo_ed25519 } else { algo_eddsa_legacy }
    Rsa(_) => algo_rsa_sign_or_encrypt
    EcdsaP256(_) => algo_ecdsa
    EcdsaP384(_) => algo_ecdsa
  }
  // Build hashed subpackets: just a creation_time (subpacket type 2) +
  // issuer_fingerprint omitted for simplicity. Even a near-empty hashed
  // area is RFC-valid.
  let hashed_sub = build_creation_time_subpacket(creation_time)
  let hashed_sub_len = hashed_sub.length()
  // Prelude length: v4 uses a 2-byte length field, v6 uses 4-byte.
  let len_field = if version == 6 { 4 } else { 2 }
  let prelude_len = 4 + len_field + hashed_sub_len
  let prelude = FixedArray::make(prelude_len, b'\x00')
  prelude[0] = if version == 6 { b'\x06' } else { b'\x04' }
  prelude[1] = b'\x00' // sig_type = binary doc
  prelude[2] = pubkey_algo.to_byte()
  prelude[3] = chosen_hash.to_byte()
  if version == 6 {
    prelude[4] = ((hashed_sub_len.reinterpret_as_uint() >> 24) & 0xffU).to_byte()
    prelude[5] = ((hashed_sub_len.reinterpret_as_uint() >> 16) & 0xffU).to_byte()
    prelude[6] = ((hashed_sub_len.reinterpret_as_uint() >> 8) & 0xffU).to_byte()
    prelude[7] = (hashed_sub_len.reinterpret_as_uint() & 0xffU).to_byte()
  } else {
    prelude[4] = ((hashed_sub_len >> 8) & 0xff).to_byte()
    prelude[5] = (hashed_sub_len & 0xff).to_byte()
  }
  for i = 0; i < hashed_sub_len; i = i + 1 {
    prelude[4 + len_field + i] = hashed_sub[i]
  }
  let prelude_bytes = Bytes::makei(prelude_len, fn(j) { prelude[j] })
  // Compute digest = H(salt || message || prelude || trailer); for v4 the
  // salt is b"" and the trailer's version byte is 0x04.
  let digest = digest_for_pgp_sign(
    chosen_hash, message, prelude_bytes, salt, version,
  )
  // Sign the digest with the algorithm-specific path.
  let sig_material = match privkey {
    Ed25519(sk) => {
      // Ed25519 .sign(M) does the internal SHA-512(R||A||M). For OpenPGP
      // we pass `digest` as the message so Ed25519 operates on the v4/v6
      // PGP digest.
      let raw = sk.sign(digest)
      if version == 6 {
        // RFC 9580 §5.2.3.3.4: raw 64-byte signature, no MPI wrapping.
        raw
      } else {
        let r = Bytes::makei(32, fn(i) { raw[i] })
        let s = Bytes::makei(32, fn(i) { raw[i + 32] })
        concat_bytes(encode_mpi(r), encode_mpi(s))
      }
    }
    Rsa(sk) => {
      // RSA-PKCS#1 v1.5 inside @rsa.sign re-hashes; we feed it the same
      // pre-hash input that the verifier will hash.
      let pre = build_pgp_pre_hash_input(message, prelude_bytes, salt, version)
      let raw = sk.sign(pre, hash_alg_for_pgp(chosen_hash)) catch {
        _ => raise Crypto("RSA sign failed")
      }
      encode_mpi(raw)
    }
    EcdsaP256(sk) => {
      let pre = build_pgp_pre_hash_input(message, prelude_bytes, salt, version)
      let raw = sk.sign(pre) // Raw r||s 64 bytes
      let r = Bytes::makei(32, fn(i) { raw[i] })
      let s = Bytes::makei(32, fn(i) { raw[i + 32] })
      concat_bytes(encode_mpi(r), encode_mpi(s))
    }
    EcdsaP384(sk) => {
      let pre = build_pgp_pre_hash_input(message, prelude_bytes, salt, version)
      let raw = sk.sign(pre) // Raw r||s 96 bytes
      let r = Bytes::makei(48, fn(i) { raw[i] })
      let s = Bytes::makei(48, fn(i) { raw[i + 48] })
      concat_bytes(encode_mpi(r), encode_mpi(s))
    }
  }
  // left16 = top 16 bits of digest.
  let left16 = (digest[0].to_uint() << 8) | digest[1].to_uint()
  // Build full Signature Packet body.
  // v4: prelude || unhashed_len(2)=0 || left16(2) || sig_material
  // v6: prelude || unhashed_len(4)=0 || left16(2) || salt_len(1) ||
  //     salt(0) || sig_material
  let salt_len = salt.length()
  let extra = if version == 6 { 1 + salt_len } else { 0 }
  let sig_pkt_len = prelude_len + len_field + 2 + extra + sig_material.length()
  let sig_pkt = FixedArray::make(sig_pkt_len, b'\x00')
  for i = 0; i < prelude_len; i = i + 1 {
    sig_pkt[i] = prelude_bytes[i]
  }
  // unhashed_len = 0, encoded as 2 or 4 bytes.
  for i = 0; i < len_field; i = i + 1 {
    sig_pkt[prelude_len + i] = b'\x00'
  }
  sig_pkt[prelude_len + len_field] = ((left16 >> 8) & 0xffU).to_byte()
  sig_pkt[prelude_len + len_field + 1] = (left16 & 0xffU).to_byte()
  let mut p = prelude_len + len_field + 2
  if version == 6 {
    sig_pkt[p] = salt_len.to_byte()
    p = p + 1
    for i = 0; i < salt_len; i = i + 1 {
      sig_pkt[p + i] = salt[i]
    }
    p = p + salt_len
  }
  for i = 0; i < sig_material.length(); i = i + 1 {
    sig_pkt[p + i] = sig_material[i]
  }
  let sig_pkt_bytes = Bytes::makei(sig_pkt_len, fn(j) { sig_pkt[j] })
  let pkt_blob = wrap_new_format_packet(2, sig_pkt_bytes)
  let armor = build_armor("SIGNATURE", pkt_blob)
  armor
}

///|
fn build_creation_time_subpacket(t : UInt) -> Bytes {
  // Subpacket: length=5 (type byte + 4 timestamp bytes) | length(1) | type
  // OpenPGP subpacket length encoding (RFC 4880 §5.2.3.1): same as
  // packet length variant — 1-byte (<192), 2-byte (192..8383), 5-byte.
  // For length 5 we use single byte.
  Bytes::makei(6, fn(i) {
    if i == 0 {
      b'\x05'
    } else if i == 1 {
      b'\x02' // type 2 = signature creation time
    } else if i == 2 {
      ((t >> 24) & 0xffU).to_byte()
    } else if i == 3 {
      ((t >> 16) & 0xffU).to_byte()
    } else if i == 4 {
      ((t >> 8) & 0xffU).to_byte()
    } else {
      (t & 0xffU).to_byte()
    }
  })
}

///|
fn digest_for_pgp_sign(
  hash_algo : Int,
  message : Bytes,
  prelude : Bytes,
  salt : Bytes,
  version : Int,
) -> Bytes raise PgpError {
  let input = build_pgp_pre_hash_input(message, prelude, salt, version)
  hash_with_algo(hash_algo, input)
}

///|
fn build_pgp_pre_hash_input(
  message : Bytes,
  prelude : Bytes,
  salt : Bytes,
  version : Int,
) -> Bytes {
  let prelude_len = prelude.length()
  let salt_len = salt.length()
  let total = salt_len + message.length() + prelude_len + 6
  let buf = FixedArray::make(total, b'\x00')
  let mut off = 0
  for i = 0; i < salt_len; i = i + 1 {
    buf[off + i] = salt[i]
  }
  off = off + salt_len
  for i = 0; i < message.length(); i = i + 1 {
    buf[off + i] = message[i]
  }
  off = off + message.length()
  for i = 0; i < prelude_len; i = i + 1 {
    buf[off + i] = prelude[i]
  }
  off = off + prelude_len
  buf[off] = if version == 6 { b'\x06' } else { b'\x04' }
  buf[off + 1] = b'\xff'
  buf[off + 2] = ((prelude_len.reinterpret_as_uint() >> 24) & 0xffU).to_byte()
  buf[off + 3] = ((prelude_len.reinterpret_as_uint() >> 16) & 0xffU).to_byte()
  buf[off + 4] = ((prelude_len.reinterpret_as_uint() >> 8) & 0xffU).to_byte()
  buf[off + 5] = (prelude_len.reinterpret_as_uint() & 0xffU).to_byte()
  Bytes::makei(total, fn(j) { buf[j] })
}

///|
fn hash_alg_for_pgp(pgp_hash_id : Int) -> @rsa.HashAlg raise PgpError {
  if pgp_hash_id == hash_sha256 {
    @rsa.HashAlg::Sha256
  } else if pgp_hash_id == hash_sha384 {
    @rsa.HashAlg::Sha384
  } else if pgp_hash_id == hash_sha512 {
    @rsa.HashAlg::Sha512
  } else {
    raise UnsupportedHashAlgo(pgp_hash_id)
  }
}

///|
fn encode_mpi(b : Bytes) -> Bytes {
  // Strip leading zero bytes; figure out bit length of the remainder.
  let mut start = 0
  while start < b.length() && b[start] == b'\x00' {
    start = start + 1
  }
  if start == b.length() {
    return Bytes::makei(2, fn(_) { b'\x00' })
  }
  let n_bytes = b.length() - start
  let leading = b[start].to_int()
  let mut bits = (n_bytes - 1) * 8
  let mut x = leading
  while x > 0 {
    bits = bits + 1
    x = x >> 1
  }
  let total = 2 + n_bytes
  Bytes::makei(total, fn(i) {
    if i == 0 {
      ((bits >> 8) & 0xff).to_byte()
    } else if i == 1 {
      (bits & 0xff).to_byte()
    } else {
      b[start + (i - 2)]
    }
  })
}

///|
fn wrap_new_format_packet(tag : Int, body : Bytes) -> Bytes {
  // Header byte: 11TTTTTT, T = tag (6 bits).
  let header = 0xC0 | (tag & 0x3F)
  let len = body.length()
  let (len_bytes_count, len_enc) = if len < 192 {
    (1, Bytes::makei(1, fn(_) { len.to_byte() }))
  } else if len < 8384 {
    let v = len - 192
    (
      2,
      Bytes::makei(2, fn(i) {
        if i == 0 {
          (((v >> 8) & 0xff) + 192).to_byte()
        } else {
          (v & 0xff).to_byte()
        }
      }),
    )
  } else {
    (
      5,
      Bytes::makei(5, fn(i) {
        if i == 0 {
          b'\xff'
        } else if i == 1 {
          ((len >> 24) & 0xff).to_byte()
        } else if i == 2 {
          ((len >> 16) & 0xff).to_byte()
        } else if i == 3 {
          ((len >> 8) & 0xff).to_byte()
        } else {
          (len & 0xff).to_byte()
        }
      }),
    )
  }
  let total = 1 + len_bytes_count + len
  Bytes::makei(total, fn(i) {
    if i == 0 {
      header.to_byte()
    } else if i <= len_bytes_count {
      len_enc[i - 1]
    } else {
      body[i - 1 - len_bytes_count]
    }
  })
}

///|
fn build_armor(label : String, body_bytes : Bytes) -> String {
  let b64 = @base64.encode(body_bytes[:])
  let sb = StringBuilder::new()
  sb.write_string("-----BEGIN PGP ")
  sb.write_string(label)
  sb.write_string("-----\n\n")
  // Wrap base64 at 64 chars per line.
  let line_len = 64
  let mut pos = 0
  while pos < b64.length() {
    let take = if pos + line_len <= b64.length() {
      line_len
    } else {
      b64.length() - pos
    }
    for j = 0; j < take; j = j + 1 {
      sb.write_char(b64.get_char(pos + j).unwrap())
    }
    sb.write_char('\n')
    pos = pos + take
  }
  // CRC line: "=BBBB"
  let crc = crc24(body_bytes)
  let crc_b3 = Bytes::makei(3, fn(i) {
    if i == 0 {
      ((crc >> 16) & 0xffU).to_byte()
    } else if i == 1 {
      ((crc >> 8) & 0xffU).to_byte()
    } else {
      (crc & 0xffU).to_byte()
    }
  })
  let crc_b64 = @base64.encode(crc_b3[:])
  sb.write_char('=')
  sb.write_string(crc_b64)
  sb.write_char('\n')
  sb.write_string("-----END PGP ")
  sb.write_string(label)
  sb.write_string("-----\n")
  sb.to_string()
}

///|
fn concat_bytes(a : Bytes, b : Bytes) -> Bytes {
  Bytes::makei(a.length() + b.length(), fn(i) {
    if i < a.length() {
      a[i]
    } else {
      b[i - a.length()]
    }
  })
}
