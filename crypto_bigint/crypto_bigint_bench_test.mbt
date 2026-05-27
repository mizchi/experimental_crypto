// Secret-class benchmark smoke tests for `crypto_bigint`.
//
// These benchmarks are not constant-time evidence. They just give us stable
// sparse-vs-dense inputs for `moon bench -p mizchi/crypto_bigint` before the
// external dudect / callgrind harness exists.

///|
fn bench_uint(limb_count : Int, limbs : Array[UInt64]) -> @crypto_bigint.Uint {
  let arr = FixedArray::make(limb_count, 0UL)
  for i in 0..<limbs.length() {
    if i < limb_count {
      arr[i] = limbs[i]
    }
  }
  { limbs: arr }
}

///|
fn bench_p256_order() -> @crypto_bigint.Uint {
  bench_uint(4, [
    0xf3b9_cac2_fc63_2551UL, 0xbce6_faad_a717_9e84UL, 0xffff_ffff_ffff_ffffUL, 0xffff_ffff_0000_0000UL,
  ])
}

///|
fn bench_base() -> @crypto_bigint.Uint {
  bench_uint(4, [
    0x0123_4567_89ab_cdefUL, 0xfedc_ba98_7654_3210UL, 0x0f0e_0d0c_0b0a_0908UL, 0x8070_6050_4030_2010UL,
  ])
}

///|
fn bench_sparse_secret() -> @crypto_bigint.Uint {
  bench_uint(4, [1UL, 0UL, 0UL, 0x8000_0000_0000_0000UL])
}

///|
fn bench_dense_secret() -> @crypto_bigint.Uint {
  bench_uint(4, [
    0xffff_ffff_ffff_fffeUL, 0xffff_ffff_ffff_ffffUL, 0xffff_ffff_ffff_ffffUL, 0x7fff_ffff_ffff_ffffUL,
  ])
}

///|
fn bench_inv(
  input : @crypto_bigint.Uint,
  modulus : @crypto_bigint.Uint,
) -> @crypto_bigint.Uint {
  input.inv_mod(modulus) catch {
    e => abort("benchmark inverse fixture must be invertible: " + repr(e))
  }
}

///|
test "bench crypto_bigint pow_mod sparse exponent" (it : @bench.T) {
  let base = bench_base()
  let exponent = bench_sparse_secret()
  let modulus = bench_p256_order()
  it.bench(name="crypto_bigint pow sparse", count=10, () => {
    it.keep(base.pow_mod(exponent, modulus))
  })
}

///|
test "bench crypto_bigint pow_mod dense exponent" (it : @bench.T) {
  let base = bench_base()
  let exponent = bench_dense_secret()
  let modulus = bench_p256_order()
  it.bench(name="crypto_bigint pow dense", count=10, () => {
    it.keep(base.pow_mod(exponent, modulus))
  })
}

///|
test "bench crypto_bigint inv_mod sparse input" (it : @bench.T) {
  let input = bench_sparse_secret()
  let modulus = bench_p256_order()
  it.bench(name="crypto_bigint inv sparse", count=20, () => {
    it.keep(bench_inv(input, modulus))
  })
}

///|
test "bench crypto_bigint inv_mod dense input" (it : @bench.T) {
  let input = bench_dense_secret()
  let modulus = bench_p256_order()
  it.bench(name="crypto_bigint inv dense", count=20, () => {
    it.keep(bench_inv(input, modulus))
  })
}
