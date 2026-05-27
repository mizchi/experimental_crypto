// Blackbox tests against real gpg-generated OpenPGP signatures.

///|
fn hex_to_bytes(s : String) -> Bytes {
  let n = s.length() / 2
  let arr = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = hex_nibble(s.code_unit_at(i * 2).to_int())
    let lo = hex_nibble(s.code_unit_at(i * 2 + 1).to_int())
    arr[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::makei(n, fn(i) { arr[i] })
}

///|
fn hex_nibble(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else if c >= 0x41 && c <= 0x46 {
    c - 0x41 + 10
  } else {
    abort("bad hex")
  }
}

///|
// PGP Ed25519 pubkey for mizchi-pgp-test@pgp.test. Generated locally with:
//   gpg --quick-generate-key 'mizchi-pgp-test <mizchi@pgp.test>' ed25519 sign 1y
//   gpg --export --armor <fingerprint>
let pubkey_armor : String =
  #|-----BEGIN PGP PUBLIC KEY BLOCK-----
  #|
  #|mDMEahVikBYJKwYBBAHaRw8BAQdAFcCGD4FWeFWaKP63iD2kaWB7PdCvi/qNbKdn
  #|+70X8FC0IW1pemNoaS1wZ3AtdGVzdCA8bWl6Y2hpQHBncC50ZXN0PoiWBBMWCgA+
  #|FiEEnw6WuikaohqHyZg0cghfOfzvGXwFAmoVYpACGwMFCQHhM4AFCwkIBwIGFQoJ
  #|CAsCBBYCAwECHgECF4AACgkQcghfOfzvGXw/MAEA0RIBVcaC7gDbfMxHEk2drqH1
  #|mr+rjnaWyQKuQR0bdasBAP2WT1Y/UmFzQ73PZ+F70U3Xj8zpjSdJ4pVDkGfc7q4H
  #|=WXNn
  #|-----END PGP PUBLIC KEY BLOCK-----

///|
// Detached signature over the ASCII string "hello pgp signing", produced
// with `gpg --detach-sign --armor` and the key above.
let detached_signature : String =
  #|-----BEGIN PGP SIGNATURE-----
  #|
  #|iHUEABYKAB0WIQSfDpa6KRqiGofJmDRyCF85/O8ZfAUCahVikQAKCRByCF85/O8Z
  #|fN3QAQDj1RLNT9SyabU1KvU4kaZAs0Ka44bversHDAgRXz78IAD/SeOuV4vuWMyh
  #|zPnq2Xp3evefYWxMMi30BVzsr6n43gU=
  #|=0DWT
  #|-----END PGP SIGNATURE-----

///|
fn message_bytes() -> Bytes {
  let s = "hello pgp signing"
  Bytes::makei(s.length(), fn(i) { s.get_char(i).unwrap().to_int().to_byte() })
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

///|
fn armor_signature_no_crc(data : Bytes) -> String {
  armor_block_no_crc("SIGNATURE", data)
}

///|
fn armor_block_no_crc(label : String, data : Bytes) -> String {
  let b64 = @base64.encode(data[:])
  "-----BEGIN PGP " +
  label +
  "-----\n\n" +
  b64 +
  "\n-----END PGP " +
  label +
  "-----\n"
}

///|
fn encode_mpi_for_test(b : Bytes) -> Bytes {
  let mut start = 0
  while start < b.length() && b[start] == b'\x00' {
    start = start + 1
  }
  if start == b.length() {
    return b"\x00\x00"
  }
  let n_bytes = b.length() - start
  let mut bits = (n_bytes - 1) * 8
  let mut x = b[start].to_int()
  while x > 0 {
    bits = bits + 1
    x = x >> 1
  }
  Bytes::makei(2 + n_bytes, fn(i) {
    if i == 0 {
      ((bits >> 8) & 0xff).to_byte()
    } else if i == 1 {
      (bits & 0xff).to_byte()
    } else {
      b[start + i - 2]
    }
  })
}

///|
fn wrap_new_format_packet_for_test(tag : Int, body : Bytes) -> Bytes {
  let header = (0xc0 | (tag & 0x3f)).to_byte()
  let len = body.length()
  if len >= 192 {
    abort("test helper only supports one-octet packet lengths")
  }
  Bytes::makei(2 + len, fn(i) {
    if i == 0 {
      header
    } else if i == 1 {
      len.to_byte()
    } else {
      body[i - 2]
    }
  })
}

///|
fn pgp_v4_pre_hash_input_for_test(message : Bytes, prelude : Bytes) -> Bytes {
  let prelude_len = prelude.length()
  let total = message.length() + prelude_len + 6
  let buf = FixedArray::make(total, b'\x00')
  let mut off = 0
  for i = 0; i < message.length(); i = i + 1 {
    buf[off + i] = message[i]
  }
  off = off + message.length()
  for i = 0; i < prelude_len; i = i + 1 {
    buf[off + i] = prelude[i]
  }
  off = off + prelude_len
  buf[off] = b'\x04'
  buf[off + 1] = b'\xff'
  let n = prelude_len.reinterpret_as_uint()
  buf[off + 2] = ((n >> 24) & 0xffU).to_byte()
  buf[off + 3] = ((n >> 16) & 0xffU).to_byte()
  buf[off + 4] = ((n >> 8) & 0xffU).to_byte()
  buf[off + 5] = (n & 0xffU).to_byte()
  Bytes::makei(total, fn(i) { buf[i] })
}

///|
fn detached_ed25519_with_unknown_critical_hashed_subpacket_for_test(
  sk : @ed25519.PrivateKey,
  message : Bytes,
) -> String {
  let creation : Bytes = b"\x05\x02\x65\x53\xf1\x00"
  // Subpacket length 1, critical unknown type 100 (0x80 | 0x64).
  let critical_unknown : Bytes = b"\x01\xe4"
  let hashed_sub = concat_bytes(creation, critical_unknown)
  let hashed_len = hashed_sub.length()
  let prelude_len = 6 + hashed_len
  let prelude = Bytes::makei(prelude_len, fn(i) {
    if i == 0 {
      b'\x04'
    } else if i == 1 {
      b'\x00'
    } else if i == 2 {
      @pgp.algo_eddsa_legacy.to_byte()
    } else if i == 3 {
      @pgp.hash_sha512.to_byte()
    } else if i == 4 {
      ((hashed_len >> 8) & 0xff).to_byte()
    } else if i == 5 {
      (hashed_len & 0xff).to_byte()
    } else {
      hashed_sub[i - 6]
    }
  })
  let digest = @hash.sha512(pgp_v4_pre_hash_input_for_test(message, prelude))
  let raw = sk.sign(digest)
  let r = Bytes::makei(32, fn(i) { raw[i] })
  let s = Bytes::makei(32, fn(i) { raw[i + 32] })
  let sig_material = concat_bytes(
    encode_mpi_for_test(r),
    encode_mpi_for_test(s),
  )
  let body_len = prelude_len + 2 + 2 + sig_material.length()
  let left16 = (digest[0].to_uint() << 8) | digest[1].to_uint()
  let body = Bytes::makei(body_len, fn(i) {
    if i < prelude_len {
      prelude[i]
    } else if i < prelude_len + 2 {
      b'\x00'
    } else if i == prelude_len + 2 {
      ((left16 >> 8) & 0xffU).to_byte()
    } else if i == prelude_len + 3 {
      (left16 & 0xffU).to_byte()
    } else {
      sig_material[i - prelude_len - 4]
    }
  })
  armor_block_no_crc("SIGNATURE", wrap_new_format_packet_for_test(2, body))
}

///|
test "pgp: armor decode roundtrips through CRC24" {
  let a = @pgp.decode_armor(pubkey_armor)
  @debug.assert_eq(a.label, "PUBLIC KEY BLOCK")
  assert_true(a.data.length() > 0)
}

///|
test "pgp: parse Public-Key Packet from armor (Ed25519)" {
  let pk = @pgp.parse_pubkey_armor(pubkey_armor)
  @debug.assert_eq(pk.version, 4)
  @debug.assert_eq(pk.algo, @pgp.algo_eddsa_legacy)
  match pk.key {
    Ed25519(_) => ()
    _ => abort("expected Ed25519 key")
  }
}

///|
test "pgp: verify_armor against real gpg signature" {
  let pkpkt = @pgp.parse_pubkey_armor(pubkey_armor)
  assert_true(@pgp.verify_armor(detached_signature, message_bytes(), pkpkt.key))
}

///|
test "pgp: tampered message fails verify" {
  let pkpkt = @pgp.parse_pubkey_armor(pubkey_armor)
  let bad : Bytes = b"hello pgp signinG"
  assert_false(@pgp.verify_armor(detached_signature, bad, pkpkt.key))
}

///|
test "pgp: tampered signature fails verify" {
  // Flip a char in the body of the armor.
  let bad_sig =
    #|-----BEGIN PGP SIGNATURE-----
    #|
    #|jHUEABYKAB0WIQSfDpa6KRqiGofJmDRyCF85/O8ZfAUCahVikQAKCRByCF85/O8Z
    #|fN3QAQDj1RLNT9SyabU1KvU4kaZAs0Ka44bversHDAgRXz78IAD/SeOuV4vuWMyh
    #|zPnq2Xp3evefYWxMMi30BVzsr6n43gU=
    #|=0DWT
    #|-----END PGP SIGNATURE-----
  let pkpkt = @pgp.parse_pubkey_armor(pubkey_armor)
  try @pgp.verify_armor(bad_sig, message_bytes(), pkpkt.key) catch {
    ArmorCrcMismatch => () // CRC24 catches the byte flip first
    _ => () // or parser rejects
  } noraise {
    false => () // or signature verify rejects
    true => abort("tampered signature accepted!")
  }
}

///|
test "pgp: armor CRC mismatch is detected" {
  let bad_crc =
    #|-----BEGIN PGP PUBLIC KEY BLOCK-----
    #|
    #|mDMEahVikBYJKwYBBAHaRw8BAQdAFcCGD4FWeFWaKP63iD2kaWB7PdCvi/qNbKdn
    #|=AAAA
    #|-----END PGP PUBLIC KEY BLOCK-----
  try @pgp.decode_armor(bad_crc) catch {
    ArmorCrcMismatch => ()
    other => abort("expected ArmorCrcMismatch, got " + repr(other) + "")
  } noraise {
    _ => abort("expected ArmorCrcMismatch, got Ok")
  }
}

// -----------------------------------------------------------------------------
// Sign roundtrips (verify with our own verifier — gpg-binary
// interoperability is left as a follow-up since we don't emit a UserID
// packet, only the detached Signature packet).
// -----------------------------------------------------------------------------

///|
test "pgp: sign Ed25519 + verify roundtrip" {
  let seed = Bytes::makei(32, fn(i) { (i + 3).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk_pgp = @pgp.PgpPublicKey::Ed25519(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"hello pgp ed25519",
  )
  assert_true(@pgp.verify_armor(armor, b"hello pgp ed25519", pk_pgp))
}

///|
test "ATTACK pgp: detached signature armor rejects extra packets" {
  let seed = Bytes::makei(32, fn(i) { (i + 3).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk_pgp = @pgp.PgpPublicKey::Ed25519(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"hello pgp ed25519",
  )
  let decoded = @pgp.decode_armor(armor)
  // New-format User ID packet (tag 13) with body "bad" appended after the
  // valid signature packet. A detached-signature armor must not ignore it.
  let extra_user_id_packet : Bytes = b"\xcd\x03bad"
  let with_extra = armor_signature_no_crc(
    concat_bytes(decoded.data, extra_user_id_packet),
  )
  try @pgp.verify_armor(with_extra, b"hello pgp ed25519", pk_pgp) catch {
    ArmorMalformed(_) => ()
    other => abort("expected ArmorMalformed, got " + repr(other) + "")
  } noraise {
    true => abort("accepted detached signature armor with extra packet")
    false => ()
  }
}

///|
test "ATTACK pgp: verify_armor rejects non-signature armor label" {
  let seed = Bytes::makei(32, fn(i) { (i + 43).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk_pgp = @pgp.PgpPublicKey::Ed25519(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"pgp armor label confusion",
  )
  let decoded = @pgp.decode_armor(armor)
  let mislabeled = armor_block_no_crc("PUBLIC KEY BLOCK", decoded.data)
  try
    @pgp.verify_armor(mislabeled, b"pgp armor label confusion", pk_pgp)
  catch {
    ArmorMalformed(_) => ()
    other => abort("expected ArmorMalformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted detached signature packet under non-signature armor")
  }
}

///|
test "ATTACK pgp: parse_pubkey_armor rejects non-public-key armor label" {
  let decoded = @pgp.decode_armor(pubkey_armor)
  let mislabeled = armor_block_no_crc("SIGNATURE", decoded.data)
  try @pgp.parse_pubkey_armor(mislabeled) catch {
    ArmorMalformed(_) => ()
    other => abort("expected ArmorMalformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted public-key packet under non-public-key armor")
  }
}

///|
test "ATTACK pgp: unknown critical hashed signature subpacket is rejected" {
  let seed = Bytes::makei(32, fn(i) { (i + 47).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk_pgp = @pgp.PgpPublicKey::Ed25519(sk.public_key())
  let msg : Bytes = b"pgp critical subpacket"
  let armor = detached_ed25519_with_unknown_critical_hashed_subpacket_for_test(
    sk, msg,
  )
  try @pgp.verify_armor(armor, msg, pk_pgp) catch {
    ArmorMalformed(_) => ()
    other => abort("expected ArmorMalformed, got " + repr(other) + "")
  } noraise {
    true => abort("accepted unknown critical signature subpacket")
    false => abort("signature construction failed before critical check")
  }
}

///|
test "pgp: sign ECDSA P-256 + verify roundtrip" {
  let scalar = Bytes::makei(32, fn(i) { (i + 7).to_byte() })
  let sk = @p256.PrivateKey::from_bytes(scalar)
  let pk_pgp = @pgp.PgpPublicKey::EcdsaP256(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::EcdsaP256(sk),
    b"hello pgp p256",
  )
  assert_true(@pgp.verify_armor(armor, b"hello pgp p256", pk_pgp))
}

///|
test "pgp: sign ECDSA P-384 + verify roundtrip" {
  let scalar = Bytes::makei(48, fn(i) { (i + 11).to_byte() })
  let sk = @p384.PrivateKey::from_bytes(scalar)
  let pk_pgp = @pgp.PgpPublicKey::EcdsaP384(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::EcdsaP384(sk),
    b"hello pgp p384",
  )
  assert_true(@pgp.verify_armor(armor, b"hello pgp p384", pk_pgp))
}

// -----------------------------------------------------------------------------
// v6 (RFC 9580) roundtrips.
//
// We could not produce a real v6 fixture from this host: gpg 2.4.9 is
// installed but its build advertises only EDDSA (algo 22) in
// `gpg --version`, and emits v4 signatures even with `future-default` /
// `--default-new-key-algo ed25519/cert,sign+cv25519/encr`. The
// supported-algorithms list does not include Ed25519 (algo 27, RFC 9580
// id-Ed25519). So we only exercise sign-then-verify against our own impl.
// -----------------------------------------------------------------------------

///|
test "pgp v6: sign Ed25519 + verify roundtrip" {
  let seed = Bytes::makei(32, fn(i) { (i + 13).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk_pgp = @pgp.PgpPublicKey::Ed25519(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"hello pgp v6 ed25519",
    version=6,
  )
  assert_true(@pgp.verify_armor(armor, b"hello pgp v6 ed25519", pk_pgp))
}

///|
test "pgp v6: sign ECDSA P-256 + verify roundtrip" {
  let scalar = Bytes::makei(32, fn(i) { (i + 17).to_byte() })
  let sk = @p256.PrivateKey::from_bytes(scalar)
  let pk_pgp = @pgp.PgpPublicKey::EcdsaP256(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::EcdsaP256(sk),
    b"hello pgp v6 p256",
    version=6,
  )
  assert_true(@pgp.verify_armor(armor, b"hello pgp v6 p256", pk_pgp))
}

///|
test "pgp v6: tampered message fails" {
  let seed = Bytes::makei(32, fn(i) { (i + 19).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk_pgp = @pgp.PgpPublicKey::Ed25519(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"hello pgp v6 ed25519",
    version=6,
  )
  assert_false(@pgp.verify_armor(armor, b"hello pgp v6 ed25519!", pk_pgp))
}

///|
test "pgp v6: tampered version byte rejected" {
  // Sign with v6 then mangle the packet body's first byte to 0x05 (an
  // unused/reserved version). The parser should raise UnsupportedPacketVersion.
  let seed = Bytes::makei(32, fn(i) { (i + 23).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk_pgp = @pgp.PgpPublicKey::Ed25519(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"hello v6 vbyte",
    version=6,
  )
  let decoded = @pgp.decode_armor(armor)
  let pkts = @pgp.parse_packets(decoded.data)
  let mut sig_body : Bytes = b""
  for p in pkts {
    if p.tag == 2 {
      sig_body = p.body
    }
  }
  let bad_body = Bytes::makei(sig_body.length(), fn(i) {
    if i == 0 {
      b'\x05'
    } else {
      sig_body[i]
    }
  })
  try @pgp.parse_signature_packet(bad_body) catch {
    UnsupportedPacketVersion(5) => ()
    other =>
      abort("expected UnsupportedPacketVersion(5), got " + repr(other) + "")
  } noraise {
    _ => abort("expected rejection")
  }
  assert_true(@pgp.verify_armor(armor, b"hello v6 vbyte", pk_pgp))
}

///|
test "pgp v6: v4 and v6 produce different armors" {
  // Signature material differs between v4 (MPI-wrapped r||s, 70 bytes) and
  // v6 (raw 64 bytes); trailer byte differs (0x04 vs 0x06); algo ID differs.
  let seed = Bytes::makei(32, fn(i) { (i + 29).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let armor_v4 = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"compare v4 v6",
  )
  let armor_v6 = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"compare v4 v6",
    version=6,
  )
  assert_not_eq(armor_v4, armor_v6)
}

///|
test "pgp v6: wire format checks (algo 27, salt=0, raw 64-byte sig)" {
  let seed = Bytes::makei(32, fn(i) { (i + 31).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let armor_v4 = @pgp.sign_armor(@pgp.PgpPrivateKey::Ed25519(sk), b"algo-check")
  let armor_v6 = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"algo-check",
    version=6,
  )
  let pkts_v4 = @pgp.parse_packets(@pgp.decode_armor(armor_v4).data)
  let pkts_v6 = @pgp.parse_packets(@pgp.decode_armor(armor_v6).data)
  let mut sig4 = @pgp.parse_signature_packet(pkts_v4[0].body)
  for p in pkts_v4 {
    if p.tag == 2 {
      sig4 = @pgp.parse_signature_packet(p.body)
    }
  }
  let mut sig6 = @pgp.parse_signature_packet(pkts_v6[0].body)
  for p in pkts_v6 {
    if p.tag == 2 {
      sig6 = @pgp.parse_signature_packet(p.body)
    }
  }
  @debug.assert_eq(sig4.version, 4)
  @debug.assert_eq(sig4.pubkey_algo, @pgp.algo_eddsa_legacy)
  @debug.assert_eq(sig4.salt.length(), 0)
  @debug.assert_eq(sig6.version, 6)
  @debug.assert_eq(sig6.pubkey_algo, @pgp.algo_ed25519)
  @debug.assert_eq(sig6.salt.length(), 0)
  @debug.assert_eq(sig6.signature_material.length(), 64) // raw Ed25519 sig
}

///|
test "pgp v6: caller-supplied salt is encoded and verified" {
  let seed = Bytes::makei(32, fn(i) { (i + 37).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk_pgp = @pgp.PgpPublicKey::Ed25519(sk.public_key())
  let salt : Bytes = b"1234567890123456"
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"salted v6 signature",
    version=6,
    salt~,
  )
  let pkts = @pgp.parse_packets(@pgp.decode_armor(armor).data)
  let mut sig = @pgp.parse_signature_packet(pkts[0].body)
  for p in pkts {
    if p.tag == 2 {
      sig = @pgp.parse_signature_packet(p.body)
    }
  }
  @debug.assert_eq(sig.version, 6)
  @debug.assert_eq(sig.salt, salt)
  assert_true(@pgp.verify_armor(armor, b"salted v6 signature", pk_pgp))
  assert_false(@pgp.verify_armor(armor, b"salted v6 signature!", pk_pgp))
}

///|
test "ATTACK pgp: v4 signatures reject caller-supplied v6 salt" {
  let seed = Bytes::makei(32, fn(i) { (i + 39).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  try
    @pgp.sign_armor(
      @pgp.PgpPrivateKey::Ed25519(sk),
      b"salt on v4",
      salt=b"1234567890123456",
    )
  catch {
    Crypto(_) => ()
    other => abort("expected Crypto, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted salt on v4 signature")
  }
}

///|
test "ATTACK pgp: truncated packet headers raise PgpError instead of aborting" {
  let cases : Array[Bytes] = [
    b"\xc0", // new-format packet without length octet
     b"\x84", // old-format one-octet length without length octet
     b"\x85\x01", // old-format two-octet length missing second octet
     b"\x86\x00\x00", // old-format four-octet length too short
     b"\xc0\xc0", // new-format two-octet length missing second octet
     b"\xc0\xff\x00", // new-format five-octet length too short
  ]
  for input in cases {
    try @pgp.parse_packets(input) catch {
      PacketTooShort(_) => ()
      ArmorMalformed(_) => ()
      other => abort("expected packet framing error, got " + repr(other) + "")
    } noraise {
      _ => abort("accepted truncated packet header")
    }
  }
}

///|
test "ATTACK pgp: MPI bit length must be minimal and exact" {
  let cases : Array[Bytes] = [
    hex_to_bytes("00090080"), // value 0x80 encoded with a leading zero
    hex_to_bytes("000780"), // bit length says 7, but unused high bit is set
    hex_to_bytes("000800"), // zero must be encoded with bit length 0
  ]
  for input in cases {
    try @pgp.read_mpi(input, 0) catch {
      InvalidMpi(_) => ()
      other => abort("expected InvalidMpi, got " + repr(other) + "")
    } noraise {
      _ => abort("accepted non-minimal MPI")
    }
  }
}

///|
test "ATTACK pgp: v6 public-key length prefix must cover exact key material" {
  let seed = Bytes::makei(32, fn(i) { (i + 41).to_byte() })
  let raw = @ed25519.PrivateKey::from_seed(seed).public_key().to_bytes()
  let body = Bytes::makei(43, fn(i) {
    if i == 0 {
      b'\x06'
    } else if i >= 1 && i <= 4 {
      b'\x00'
    } else if i == 5 {
      @pgp.algo_ed25519.to_byte()
    } else if i >= 6 && i <= 8 {
      b'\x00'
    } else if i == 9 {
      b'\x20'
    } else if i < 42 {
      raw[i - 10]
    } else {
      b'\x00'
    }
  })
  try @pgp.parse_public_key_packet(body) catch {
    InvalidMpi(_) => ()
    other => abort("expected InvalidMpi, got " + repr(other))
  } noraise {
    _ => abort("accepted trailing bytes after v6 public key")
  }
}

///|
test "ATTACK pgp: v6 signature oversized length fields reject without aborting" {
  let body = hex_to_bytes("06001b0affffffff")
  try @pgp.parse_signature_packet(body) catch {
    PacketTooShort(_) => ()
    other => abort("expected PacketTooShort, got " + repr(other))
  } noraise {
    _ => abort("accepted impossible v6 hashed-subpacket length")
  }
}
