// Benchmarks for the X25519MLKEM768 hybrid. Each side combines an ML-KEM-768
// operation with an X25519 scalar mult: the server does encaps + DH, the client
// does decaps + DH. ML-KEM dominates over the (already cheap) X25519 part.

///|
let bench_hd : Bytes = Bytes::makei(32, fn(_i) { b'\x2a' })

///|
let bench_hz : Bytes = Bytes::makei(32, fn(_i) { b'\x55' })

///|
let bench_hm : Bytes = Bytes::makei(32, fn(_i) { b'\x11' })

///|
let bench_xsk_c : Bytes = Bytes::makei(32, fn(i) {
  ((i * 5 + 1) & 0xff).to_byte()
})

///|
let bench_xsk_s : Bytes = Bytes::makei(32, fn(i) {
  ((i * 3 + 7) & 0xff).to_byte()
})

///|
test "bench X25519MLKEM768 server_respond (encaps + X25519)" (it : @bench.T) {
  let (client_share, _dk) = @pqhybrid.client_offer(
    bench_hd, bench_hz, bench_xsk_c,
  ) catch {
    _ => abort("unreachable")
  }
  it.bench(name="hybrid server_respond", count=30, () => {
    it.keep(
      @pqhybrid.server_respond(client_share, bench_hm, bench_xsk_s) catch {
        _ => abort("unreachable")
      },
    )
  })
}

///|
test "bench X25519MLKEM768 client_finish (decaps + X25519)" (it : @bench.T) {
  let (client_share, dk) = @pqhybrid.client_offer(
    bench_hd, bench_hz, bench_xsk_c,
  ) catch {
    _ => abort("unreachable")
  }
  let (server_share, _ss) = @pqhybrid.server_respond(
    client_share, bench_hm, bench_xsk_s,
  ) catch {
    _ => abort("unreachable")
  }
  it.bench(name="hybrid client_finish", count=30, () => {
    it.keep(
      @pqhybrid.client_finish(dk, bench_xsk_c, server_share) catch {
        _ => abort("unreachable")
      },
    )
  })
}
