// Benchmarks for scrypt KDF hot path. Build with `moon bench --release`.

///|
test "bench scrypt N=16 r=1 p=1 dkLen=32" (it : @bench.T) {
  let params : @scrypt.Params = { log_n: 4, r: 1, p: 1, dk_len: 32 }
  it.bench(name="scrypt N=16", count=50, () => {
    it.keep(
      @scrypt.derive_key(params, b"password", b"salt") catch {
        _ => abort("unreachable")
      },
    )
  })
}

///|
test "bench scrypt N=1024 r=8 p=1 dkLen=32" (it : @bench.T) {
  let params : @scrypt.Params = { log_n: 10, r: 8, p: 1, dk_len: 32 }
  it.bench(name="scrypt N=1024", count=10, () => {
    it.keep(
      @scrypt.derive_key(params, b"password", b"salt") catch {
        _ => abort("unreachable")
      },
    )
  })
}

///|
test "bench scrypt N=16384 r=8 p=1 dkLen=32" (it : @bench.T) {
  let params : @scrypt.Params = { log_n: 14, r: 8, p: 1, dk_len: 32 }
  it.bench(name="scrypt N=16k", count=5, () => {
    it.keep(
      @scrypt.derive_key(params, b"password", b"salt") catch {
        _ => abort("unreachable")
      },
    )
  })
}
