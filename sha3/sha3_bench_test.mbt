// Benchmarks for the Keccak-f[1600] sponge. The hot path is keccak_f (24 rounds
// of θρπχι over 25 UInt64 lanes); throughput is dominated by the number of
// permutation calls, i.e. ceil(len / rate) absorb blocks.

///|
let bench_1kib : Bytes = Bytes::makei(1024, fn(i) { (i & 0xff).to_byte() })

///|
test "bench sha3_256 (1 KiB)" (it : @bench.T) {
  it.bench(name="sha3_256 1KiB", count=200, () => {
    it.keep(@sha3.sha3_256(bench_1kib))
  })
}

///|
test "bench sha3_512 (1 KiB)" (it : @bench.T) {
  it.bench(name="sha3_512 1KiB", count=200, () => {
    it.keep(@sha3.sha3_512(bench_1kib))
  })
}

///|
test "bench shake128 (1 KiB in, 32 B out)" (it : @bench.T) {
  it.bench(name="shake128 1KiB->32", count=200, () => {
    it.keep(@sha3.shake128(bench_1kib, 32))
  })
}

///|
test "bench shake256 (1 KiB in, 32 B out)" (it : @bench.T) {
  it.bench(name="shake256 1KiB->32", count=200, () => {
    it.keep(@sha3.shake256(bench_1kib, 32))
  })
}
