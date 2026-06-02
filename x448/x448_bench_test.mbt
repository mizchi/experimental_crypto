// Benchmarks for X448. This is the @bigint Montgomery ladder (448 ladder steps,
// each a handful of modular mul/sq over p = 2^448 - 2^224 - 1), so it is far
// slower than the dedicated 10-limb X25519 path — included for completeness.

///|
let bench_x448_sk : Bytes = Bytes::makei(56, fn(i) {
  ((i * 7 + 3) & 0xff).to_byte()
})

///|
test "bench x448 public_key (base point scalar mult)" (it : @bench.T) {
  it.bench(name="x448 derive public key", count=20, () => {
    it.keep(@x448.public_key(bench_x448_sk) catch { _ => abort("unreachable") })
  })
}

///|
test "bench x448 ECDH" (it : @bench.T) {
  let peer = @x448.public_key(bench_x448_sk) catch { _ => abort("unreachable") }
  it.bench(name="x448 ECDH", count=20, () => {
    it.keep(@x448.x448(bench_x448_sk, peer) catch { _ => abort("unreachable") })
  })
}
