// Benchmarks for P-384 ECDSA. Field arithmetic goes through @bigint affine
// point ops — baseline before a planned 14-limb radix-2^28 field rewrite.

///|
let bench_priv_scalar : Bytes = b"\x6b\x9d\x3d\xad\x2e\x1b\x8c\x1c\x05\xb1\x98\x75\xb6\x65\x9f\x4d\xe2\x3c\x3b\x66\x7b\xf2\x97\xba\x9a\xa4\x77\x40\x78\x71\x37\xd8\x96\xd5\x72\x4e\x4c\x70\xa8\x25\xf8\x72\xc9\xea\x60\xd2\xed\xf5"

///|
let bench_msg : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

///|
test "bench p384 derive public key" (it : @bench.T) {
  let sk = @p384.PrivateKey::from_bytes(bench_priv_scalar) catch {
    _ => abort("unreachable")
  }
  it.bench(name="p384 derive pk", count=20, () => it.keep(sk.public_key()))
}

///|
test "bench p384 sign" (it : @bench.T) {
  let sk = @p384.PrivateKey::from_bytes(bench_priv_scalar) catch {
    _ => abort("unreachable")
  }
  it.bench(name="p384 sign", count=20, () => it.keep(sk.sign(bench_msg)))
}

///|
test "bench p384 verify" (it : @bench.T) {
  let sk = @p384.PrivateKey::from_bytes(bench_priv_scalar) catch {
    _ => abort("unreachable")
  }
  let pk = sk.public_key()
  let sig = sk.sign(bench_msg)
  it.bench(name="p384 verify", count=20, () => {
    let ok = @p384.verify(pk, bench_msg, sig, Raw) catch { _ => false }
    it.keep(ok)
  })
}
