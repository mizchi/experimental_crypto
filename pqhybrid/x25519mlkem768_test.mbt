// X25519MLKEM768 hybrid round-trip: client_offer -> server_respond ->
// client_finish, asserting both sides derive the identical 64-byte secret
// (ML-KEM ss || X25519 ss). ML-KEM-768 and X25519 are each KAT-verified in
// their own modules; this pins the hybrid wiring + share/secret layout.

///|
fn rep(byte : Int, n : Int) -> Bytes {
  Bytes::makei(n, fn(_i) { (byte & 0xff).to_byte() })
}

///|
test "X25519MLKEM768 hybrid round trip" {
  let d = rep(0x11, 32)
  let z = rep(0x22, 32)
  let client_x = rep(0x33, 32)
  let server_x = rep(0x44, 32)
  let m = rep(0x55, 32)

  // Client offer
  let (client_share, dk) = @pqhybrid.client_offer(d, z, client_x)
  inspect(client_share.length(), content="1216")

  // Server response
  let (server_share, ss_server) = @pqhybrid.server_respond(
    client_share, m, server_x,
  )
  inspect(server_share.length(), content="1120")
  inspect(ss_server.length(), content="64")

  // Client finish
  let ss_client = @pqhybrid.client_finish(dk, client_x, server_share)
  inspect(ss_client.length(), content="64")

  // Both sides agree
  let mut eq = true
  for i in 0..<64 {
    if ss_client[i] != ss_server[i] {
      eq = false
    }
  }
  inspect(eq, content="true")
}

///|
test "X25519MLKEM768 rejects malformed share lengths" {
  let d = rep(1, 32)
  let z = rep(2, 32)
  let (_share, dk) = @pqhybrid.client_offer(d, z, rep(3, 32))
  // wrong client_share length on the server side
  inspect(
    (try? @pqhybrid.server_respond(rep(0, 100), rep(4, 32), rep(5, 32)))
    is Err(_),
    content="true",
  )
  // wrong server_share length on the client side
  inspect(
    (try? @pqhybrid.client_finish(dk, rep(3, 32), rep(0, 100))) is Err(_),
    content="true",
  )
}

///|
test "X25519MLKEM768 finish with wrong X25519 key yields a different secret" {
  let d = rep(0x11, 32)
  let z = rep(0x22, 32)
  let client_x = rep(0x33, 32)
  let server_x = rep(0x44, 32)
  let (client_share, dk) = @pqhybrid.client_offer(d, z, client_x)
  let (server_share, ss_server) = @pqhybrid.server_respond(
    client_share,
    rep(0x55, 32),
    server_x,
  )
  // A client using the wrong X25519 private key gets the right ML-KEM half but
  // a different X25519 half → overall secret differs.
  let ss_wrong = @pqhybrid.client_finish(dk, rep(0x99, 32), server_share)
  let mut differ = false
  for i in 0..<64 {
    if ss_wrong[i] != ss_server[i] {
      differ = true
      break
    }
  }
  inspect(differ, content="true")
}
