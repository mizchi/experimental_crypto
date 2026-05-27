// Property-based fuzz tests for AEAD constructions. For each supported
// algorithm (ChaCha20Poly1305, XChaCha20Poly1305, Aes128Gcm, Aes256Gcm) we check four
// invariants on random inputs drawn from core/quickcheck:
//   (1) seal/open is a roundtrip: open(seal(p)) == p
//   (2) flipping any single bit in the sealed_bytes output causes open to fail
//       authentication (a tag-bit flip will always reject; a ciphertext-
//       bit flip can in principle still authenticate with vanishing
//       probability ≈ 2^-128, so we accept that astronomical fluke).
//   (3) opening with the wrong AAD must reject.
//   (4) open() on arbitrary random bytes must not crash.

///|
/// Coerce arbitrary bytes to exact target length. Repeats input cyclically
/// when too short, truncates when too long, and falls back to a zero buffer
/// when the input is empty.
fn ensure_length(b : Bytes, target : Int) -> Bytes {
  if b.length() == target {
    b
  } else if b.length() == 0 {
    Bytes::makei(target, fn(_) { b'\x00' })
  } else if b.length() > target {
    Bytes::makei(target, fn(i) { b[i] })
  } else {
    let n = b.length()
    Bytes::makei(target, fn(i) { b[i % n] })
  }
}

///|
fn flip_bit(b : Bytes, bit_index : Int) -> Bytes {
  let byte_idx = bit_index / 8
  let bit_in_byte = bit_index % 8
  Bytes::makei(b.length(), fn(i) {
    if i == byte_idx {
      (b[i].to_int() ^ (1 << bit_in_byte)).to_byte()
    } else {
      b[i]
    }
  })
}

///|
fn algs() -> Array[@aead.Algorithm] {
  [
    @aead.ChaCha20Poly1305,
    @aead.XChaCha20Poly1305,
    @aead.Aes128Gcm,
    @aead.Aes256Gcm,
  ]
}

///|
test "fuzz aead: seal/open roundtrip (ChaCha20Poly1305)" {
  fuzz_roundtrip(@aead.ChaCha20Poly1305)
}

///|
test "fuzz aead: seal/open roundtrip (XChaCha20Poly1305)" {
  fuzz_roundtrip(@aead.XChaCha20Poly1305)
}

///|
test "fuzz aead: seal/open roundtrip (Aes128Gcm)" {
  fuzz_roundtrip(@aead.Aes128Gcm)
}

///|
test "fuzz aead: seal/open roundtrip (Aes256Gcm)" {
  fuzz_roundtrip(@aead.Aes256Gcm)
}

///|
fn fuzz_roundtrip(alg : @aead.Algorithm) -> Unit raise {
  let n = 50
  let plaintexts : Array[Bytes] = @quickcheck.samples(n)
  let aads : Array[Bytes] = @quickcheck.samples(n)
  let keys : Array[Bytes] = @quickcheck.samples(n)
  let nonces : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let key = ensure_length(keys[i], alg.key_size())
    let nonce = ensure_length(nonces[i], alg.nonce_size())
    let aad = aads[i]
    let p = plaintexts[i]
    let sealed_bytes = @aead.seal(alg, key, nonce, aad, p)
    let opened = @aead.open(alg, key, nonce, aad, sealed_bytes)
    @debug.assert_eq(opened, p)
  }
}

///|
test "fuzz aead: tampered ciphertext rejects (ChaCha20Poly1305)" {
  fuzz_tamper(@aead.ChaCha20Poly1305)
}

///|
test "fuzz aead: tampered ciphertext rejects (XChaCha20Poly1305)" {
  fuzz_tamper(@aead.XChaCha20Poly1305)
}

///|
test "fuzz aead: tampered ciphertext rejects (Aes128Gcm)" {
  fuzz_tamper(@aead.Aes128Gcm)
}

///|
test "fuzz aead: tampered ciphertext rejects (Aes256Gcm)" {
  fuzz_tamper(@aead.Aes256Gcm)
}

///|
fn fuzz_tamper(alg : @aead.Algorithm) -> Unit raise {
  let n = 50
  let plaintexts : Array[Bytes] = @quickcheck.samples(n)
  let aads : Array[Bytes] = @quickcheck.samples(n)
  let keys : Array[Bytes] = @quickcheck.samples(n)
  let nonces : Array[Bytes] = @quickcheck.samples(n)
  let bit_indices : Array[Int] = @quickcheck.samples(n)
  for i in 0..<n {
    let key = ensure_length(keys[i], alg.key_size())
    let nonce = ensure_length(nonces[i], alg.nonce_size())
    let aad = aads[i]
    let p = plaintexts[i]
    let sealed_bytes = @aead.seal(alg, key, nonce, aad, p)
    if sealed_bytes.length() == 0 {
      continue
    }
    let total_bits = sealed_bytes.length() * 8
    let raw = bit_indices[i]
    let positive = if raw < 0 { -raw } else { raw }
    let bit = positive % total_bits
    let tampered = flip_bit(sealed_bytes, bit)
    if tampered == sealed_bytes {
      continue
    }
    try @aead.open(alg, key, nonce, aad, tampered) catch {
      _ => () // expected
    } noraise {
      _ => fail("tampered ciphertext must reject")
    }
  }
}

///|
test "fuzz aead: wrong AAD rejects (ChaCha20Poly1305)" {
  fuzz_wrong_aad(@aead.ChaCha20Poly1305)
}

///|
test "fuzz aead: wrong AAD rejects (XChaCha20Poly1305)" {
  fuzz_wrong_aad(@aead.XChaCha20Poly1305)
}

///|
test "fuzz aead: wrong AAD rejects (Aes128Gcm)" {
  fuzz_wrong_aad(@aead.Aes128Gcm)
}

///|
test "fuzz aead: wrong AAD rejects (Aes256Gcm)" {
  fuzz_wrong_aad(@aead.Aes256Gcm)
}

///|
fn fuzz_wrong_aad(alg : @aead.Algorithm) -> Unit raise {
  let n = 50
  let plaintexts : Array[Bytes] = @quickcheck.samples(n)
  let aads : Array[Bytes] = @quickcheck.samples(n)
  let keys : Array[Bytes] = @quickcheck.samples(n)
  let nonces : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let key = ensure_length(keys[i], alg.key_size())
    let nonce = ensure_length(nonces[i], alg.nonce_size())
    let aad = aads[i]
    let p = plaintexts[i]
    let sealed_bytes = @aead.seal(alg, key, nonce, aad, p)
    let wrong_aad : Bytes = if aad == b"" { b"\xff" } else { b"" }
    try @aead.open(alg, key, nonce, wrong_aad, sealed_bytes) catch {
      _ => () // expected
    } noraise {
      _ => fail("open with wrong aad must reject")
    }
  }
}

///|
test "fuzz aead: open of random bytes does not crash (ChaCha20Poly1305)" {
  fuzz_random_open(@aead.ChaCha20Poly1305)
}

///|
test "fuzz aead: open of random bytes does not crash (XChaCha20Poly1305)" {
  fuzz_random_open(@aead.XChaCha20Poly1305)
}

///|
test "fuzz aead: open of random bytes does not crash (Aes128Gcm)" {
  fuzz_random_open(@aead.Aes128Gcm)
}

///|
test "fuzz aead: open of random bytes does not crash (Aes256Gcm)" {
  fuzz_random_open(@aead.Aes256Gcm)
}

///|
fn fuzz_random_open(alg : @aead.Algorithm) -> Unit {
  let n = 50
  let inputs : Array[Bytes] = @quickcheck.samples(n)
  let aads : Array[Bytes] = @quickcheck.samples(n)
  let keys : Array[Bytes] = @quickcheck.samples(n)
  let nonces : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let key = ensure_length(keys[i], alg.key_size())
    let nonce = ensure_length(nonces[i], alg.nonce_size())
    let aad = aads[i]
    let input = inputs[i]
    let _ = try? @aead.open(alg, key, nonce, aad, input)
  }
}

///|
fn algs_used() -> Int {
  // Touch algs() so the helper is not dead code; also acts as a small
  // sanity check that all three algorithm names compile in this file.
  algs().length()
}

///|
test "fuzz aead: algorithm list sanity" {
  @debug.assert_eq(algs_used(), 4)
}
