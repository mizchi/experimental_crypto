// Benchmarks for ML-KEM-768. KeyGen / Encaps / Decaps are dominated by SHAKE
// (matrix expansion + CBD sampling) and the NTT base-multiplies; Decaps also
// re-encrypts for the implicit-reject check, so it is the heaviest of the three.

///|
let bench_d : Bytes = Bytes::makei(32, fn(_i) { b'\x2a' })

///|
let bench_z : Bytes = Bytes::makei(32, fn(_i) { b'\x55' })

///|
let bench_m : Bytes = Bytes::makei(32, fn(_i) { b'\x11' })

///|
test "bench ML-KEM-768 keygen" (it : @bench.T) {
  it.bench(name="mlkem768 keygen", count=50, () => {
    it.keep(@mlkem.keygen(bench_d, bench_z) catch { _ => abort("unreachable") })
  })
}

///|
test "bench ML-KEM-768 encaps" (it : @bench.T) {
  let (ek, _dk) = @mlkem.keygen(bench_d, bench_z) catch {
    _ => abort("unreachable")
  }
  it.bench(name="mlkem768 encaps", count=50, () => {
    it.keep(@mlkem.encaps(ek, bench_m) catch { _ => abort("unreachable") })
  })
}

///|
test "bench ML-KEM-768 decaps" (it : @bench.T) {
  let (ek, dk) = @mlkem.keygen(bench_d, bench_z) catch {
    _ => abort("unreachable")
  }
  let (_ss, ct) = @mlkem.encaps(ek, bench_m) catch { _ => abort("unreachable") }
  it.bench(name="mlkem768 decaps", count=50, () => {
    it.keep(@mlkem.decaps(dk, ct) catch { _ => abort("unreachable") })
  })
}
