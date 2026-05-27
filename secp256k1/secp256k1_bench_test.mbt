// Benchmarks for secp256k1 ECDSA. Sign-side base-point multiplication and the
// final nonce inverse are routed through fixed-limb crypto_bigint paths;
// public verify remains affine @bigint.
// secp256k1 has an endomorphism (GLV decomposition) that could
// further halve scalar mult cost; out of scope for this baseline.

///|
let bench_priv_scalar : Bytes = b"\xc9\xaf\xa9\xd8\x45\xba\x75\x16\x6b\x5c\x21\x57\x67\xb1\xd6\x93\x4e\x50\xc3\xdb\x36\xe8\x9b\x12\x7b\x8a\x62\x2b\x12\x0f\x67\x21"

///|
let bench_sparse_priv_scalar : Bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"

///|
let bench_dense_priv_scalar : Bytes = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xba\xae\xdc\xe6\xaf\x48\xa0\x3b\xbf\xd2\x5e\x8c\xd0\x36\x41\x3f"

///|
let bench_msg : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

///|
test "bench secp256k1 derive public key" (it : @bench.T) {
  let sk = @secp256k1.PrivateKey::from_bytes(bench_priv_scalar) catch {
    _ => abort("unreachable")
  }
  it.bench(name="secp256k1 derive pk", count=50, () => it.keep(sk.public_key()))
}

///|
test "bench secp256k1 sign" (it : @bench.T) {
  let sk = @secp256k1.PrivateKey::from_bytes(bench_priv_scalar) catch {
    _ => abort("unreachable")
  }
  it.bench(name="secp256k1 sign", count=50, () => it.keep(sk.sign(bench_msg)))
}

///|
test "bench secp256k1 sign sparse scalar" (it : @bench.T) {
  let sk = @secp256k1.PrivateKey::from_bytes(bench_sparse_priv_scalar) catch {
    _ => abort("unreachable")
  }
  it.bench(name="secp256k1 sign sparse", count=50, () => {
    it.keep(sk.sign(bench_msg))
  })
}

///|
test "bench secp256k1 sign dense scalar" (it : @bench.T) {
  let sk = @secp256k1.PrivateKey::from_bytes(bench_dense_priv_scalar) catch {
    _ => abort("unreachable")
  }
  it.bench(name="secp256k1 sign dense", count=50, () => {
    it.keep(sk.sign(bench_msg))
  })
}

///|
test "bench secp256k1 verify" (it : @bench.T) {
  let sk = @secp256k1.PrivateKey::from_bytes(bench_priv_scalar) catch {
    _ => abort("unreachable")
  }
  let pk = sk.public_key()
  let sig = sk.sign(bench_msg)
  it.bench(name="secp256k1 verify", count=50, () => {
    let ok = @secp256k1.verify(pk, bench_msg, sig, Raw) catch { _ => false }
    it.keep(ok)
  })
}
