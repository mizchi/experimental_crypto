// mizchi/pgp — OpenPGP v4 signature verification.
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
// Out of scope: signing, key generation, v6 packets, partial-body
// streaming lengths, subkey selection, trust signatures, revocation.

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
  let left =
    (digest[0].to_uint() << 8) | digest[1].to_uint()
  if left != sig.left16 {
    return false
  }
  // Dispatch on (pubkey, pubkey_algo).
  match pubkey {
    Ed25519(pk) =>
      if sig.pubkey_algo != algo_eddsa_legacy {
        raise UnsupportedPubkeyAlgo(sig.pubkey_algo)
      } else {
        // Signature material: MPI r || MPI s, each 256 bits.
        let (r_bytes, r_used) = read_mpi(sig.signature_material, 0)
        let (s_bytes, _) = read_mpi(sig.signature_material, r_used)
        let raw_sig = build_ed25519_sig(r_bytes, s_bytes)
        pk.verify(digest, raw_sig)
      }
    Rsa(pk) => {
      if sig.pubkey_algo != algo_rsa_sign_or_encrypt {
        raise UnsupportedPubkeyAlgo(sig.pubkey_algo)
      }
      let (s_bytes, _) = read_mpi(sig.signature_material, 0)
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
      let (s_bytes, _) = read_mpi(sig.signature_material, r_used)
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
      let (s_bytes, _) = read_mpi(sig.signature_material, r_used)
      let raw_sig = build_ecdsa_raw(r_bytes, s_bytes, 48)
      let pre = build_pre_hash_input(sig, message)
      @p384.verify(pk, pre, raw_sig, @p384.SignatureFormat::Raw) catch {
        _ => false
      }
    }
  }
}

///|
fn find_signature_packet(packets : Array[PgpPacket]) -> PgpSignature raise PgpError {
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
  Bytes::makei(64, fn(i) {
    if i < 32 {
      r_pad[i]
    } else {
      s_pad[i - 32]
    }
  })
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
      "integer too wide: " +
      b.length().to_string() +
      " > " +
      target.to_string(),
    )
  }
  let pad = target - b.length()
  Bytes::makei(target, fn(i) {
    if i < pad {
      b'\x00'
    } else {
      b[i - pad]
    }
  })
}

///|
// The bytes that @rsa.verify / @p256.verify / @p384.verify will pre-hash
// internally to produce the digest. This is `message || hashed_subpackets_raw
// || trailer`.
fn build_pre_hash_input(sig : PgpSignature, message : Bytes) -> Bytes {
  let prelude = sig.hashed_subpackets_raw
  let prelude_len = prelude.length()
  let total = message.length() + prelude_len + 6
  let buf = FixedArray::make(total, b'\x00')
  for i = 0; i < message.length(); i = i + 1 {
    buf[i] = message[i]
  }
  for i = 0; i < prelude_len; i = i + 1 {
    buf[message.length() + i] = prelude[i]
  }
  let off = message.length() + prelude_len
  buf[off] = b'\x04'
  buf[off + 1] = b'\xff'
  buf[off + 2] = ((prelude_len.to_uint() >> 24) & 0xffU).to_byte()
  buf[off + 3] = ((prelude_len.to_uint() >> 16) & 0xffU).to_byte()
  buf[off + 4] = ((prelude_len.to_uint() >> 8) & 0xffU).to_byte()
  buf[off + 5] = (prelude_len.to_uint() & 0xffU).to_byte()
  Bytes::makei(total, fn(j) { buf[j] })
}
