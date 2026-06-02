// Benchmarks for QUIC v1 Initial-packet crypto (RFC 9001). `initial_keys` is a
// short HKDF chain (one extract + a few expand-labels); `seal_payload` is the
// AES-128-GCM cost over a near-MTU payload, which is the per-packet hot path.

///|
let bench_dcid : Bytes = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"

///|
let bench_qpayload : Bytes = Bytes::makei(1200, fn(i) { (i & 0xff).to_byte() })

///|
let bench_qheader : Bytes = b"\xc3\x00\x00\x00\x01\x08\x83\x94\xc8\xf0\x3e\x51\x57\x08\x00\x00\x44\x9e\x00\x00\x00\x02"

///|
test "bench quic initial_keys (HKDF key derivation)" (it : @bench.T) {
  it.bench(name="quic initial_keys", count=100, () => {
    it.keep(@quic.initial_keys(bench_dcid))
  })
}

///|
test "bench quic seal_payload (AES-128-GCM, 1200 B)" (it : @bench.T) {
  let (client, _server) = @quic.initial_keys(bench_dcid)
  it.bench(name="quic seal 1200B", count=100, () => {
    it.keep(
      @quic.seal_payload(client, 1, bench_qheader, bench_qpayload) catch {
        _ => abort("unreachable")
      },
    )
  })
}
