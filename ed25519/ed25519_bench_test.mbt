// Benchmarks for Ed25519. Measures derive-public-key, sign, and verify
// hot paths. The implementation uses a 10-limb radix-2^25.5 field
// representation over UInt64 with schoolbook multiplication and a
// 254-step Fermat inversion chain. Scalar arithmetic (mod L) still
// uses @bigint; it runs O(1) times per sign/verify so it is not on the
// hot path.

///|
let bench_seed : Bytes = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"

///|
let bench_msg : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

///|
test "bench ed25519 derive public key" (it : @bench.T) {
  let sk = @ed25519.PrivateKey::from_seed(bench_seed) catch {
    _ => abort("unreachable")
  }
  it.bench(name="ed25519 derive pk", count=200, () => it.keep(sk.public_key()))
}

///|
test "bench ed25519 sign 32 bytes" (it : @bench.T) {
  let sk = @ed25519.PrivateKey::from_seed(bench_seed) catch {
    _ => abort("unreachable")
  }
  it.bench(name="ed25519 sign", count=200, () => it.keep(sk.sign(bench_msg)))
}

///|
test "bench ed25519 verify" (it : @bench.T) {
  let sk = @ed25519.PrivateKey::from_seed(bench_seed) catch {
    _ => abort("unreachable")
  }
  let pk = sk.public_key()
  let sig = sk.sign(bench_msg)
  it.bench(name="ed25519 verify", count=200, () =>
    it.keep(pk.verify(bench_msg, sig))
  )
}
