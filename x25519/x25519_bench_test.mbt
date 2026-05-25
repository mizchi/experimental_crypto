// Benchmarks for X25519. The current implementation goes through @bigint
// (variable-time) so this measures the BigInt Montgomery ladder as a
// baseline; a future limb-level rewrite should beat these numbers by 1-2
// orders of magnitude.

///|
test "bench x25519 diffie_hellman (Alice key on Bob pubkey)" (it : @bench.T) {
  let sk = @x25519.PrivateKey::from_bytes(
    b"\x77\x07\x6d\x0a\x73\x18\xa5\x7d\x3c\x16\xc1\x72\x51\xb2\x66\x45\xdf\x4c\x2f\x87\xeb\xc0\x99\x2a\xb1\x77\xfb\xa5\x1d\xb9\x2c\x2a",
  ) catch {
    _ => abort("unreachable")
  }
  let pk = @x25519.PublicKey::from_bytes(
    b"\xde\x9e\xdb\x7d\x7b\x7d\xc1\xb4\xd3\x5b\x61\xc2\xec\xe4\x35\x37\x3f\x83\x43\xc8\x5b\x78\x67\x4d\xad\xfc\x7e\x14\x6f\x88\x2b\x4f",
  ) catch {
    _ => abort("unreachable")
  }
  it.bench(name="x25519 ECDH", count=200, () => {
    it.keep(@x25519.diffie_hellman(sk, pk) catch { _ => abort("unreachable") })
  })
}

///|
test "bench x25519 PrivateKey::public_key (base point scalar mult)" (
  it : @bench.T,
) {
  let sk = @x25519.PrivateKey::from_bytes(
    b"\x77\x07\x6d\x0a\x73\x18\xa5\x7d\x3c\x16\xc1\x72\x51\xb2\x66\x45\xdf\x4c\x2f\x87\xeb\xc0\x99\x2a\xb1\x77\xfb\xa5\x1d\xb9\x2c\x2a",
  ) catch {
    _ => abort("unreachable")
  }
  it.bench(name="x25519 derive public key", count=200, () => {
    it.keep(sk.public_key())
  })
}
