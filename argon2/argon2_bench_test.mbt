// Benchmarks for Argon2 hot path. Build with `moon bench --release`.

///|
test "bench argon2id interactive (m=19 t=2 p=1 out=32)" (it : @bench.T) {
  let params : @argon2.Params = @argon2.Params::recommended_interactive()
  it.bench(name="argon2id interactive", count=10, () => {
    it.keep(
      @argon2.hash_raw(params, b"password", b"saltsaltsaltsalt") catch {
        _ => abort("unreachable")
      },
    )
  })
}

///|
test "bench argon2id m=64 t=3 p=1 out=32" (it : @bench.T) {
  let params : @argon2.Params = {
    variant: Argon2id,
    m_cost: 65536,
    t_cost: 3,
    parallelism: 1,
    output_len: 32,
  }
  it.bench(name="argon2id m=64MiB", count=5, () => {
    it.keep(
      @argon2.hash_raw(params, b"password", b"saltsaltsaltsalt") catch {
        _ => abort("unreachable")
      },
    )
  })
}
