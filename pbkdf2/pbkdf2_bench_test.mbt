// Benchmarks for PBKDF2-HMAC-SHA256. Iteration count dominates wall time.

///|
test "bench pbkdf2 c=1000 dkLen=32" (it : @bench.T) {
  it.bench(name="pbkdf2 c=1k", count=50, () => {
    it.keep(
      @pbkdf2.pbkdf2(Sha256, b"password", b"salt", 1000, 32) catch {
        _ => abort("unreachable")
      },
    )
  })
}

///|
test "bench pbkdf2 c=10000 dkLen=32" (it : @bench.T) {
  it.bench(name="pbkdf2 c=10k", count=10, () => {
    it.keep(
      @pbkdf2.pbkdf2(Sha256, b"password", b"salt", 10000, 32) catch {
        _ => abort("unreachable")
      },
    )
  })
}

///|
test "bench pbkdf2 c=1000 dkLen=64 (two HMAC blocks)" (it : @bench.T) {
  it.bench(name="pbkdf2 c=1k dk=64", count=50, () => {
    it.keep(
      @pbkdf2.pbkdf2(Sha256, b"password", b"salt", 1000, 64) catch {
        _ => abort("unreachable")
      },
    )
  })
}
