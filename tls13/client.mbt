// TLS 1.3 client handshake driver (RFC 8446 §4): a one-shot orchestration of
// the building blocks for a 1-RTT handshake. Given the ClientHello and
// ServerHello it sent/received, the negotiated (EC)DHE shared secret, and the
// decrypted server flight (EncryptedExtensions, Certificate, CertificateVerify,
// Finished), it runs the key schedule, authenticates the server (CertificateVerify
// signature + server Finished MAC), derives the application traffic keys, and
// produces the client Finished message.
//
// This deliberately stays pure: the caller owns the socket, the ECDHE keypair,
// and the record (de)framing (see seal_record / open_record). Certificate
// chain-of-trust validation (leaf -> anchor) is also the caller's job — the
// returned `server_certificates` chain is meant to be fed to
// `pkix_verify.verify_chain*`. This driver only proves the server holds the
// leaf key and agrees on the transcript.

///|
pub suberror ClientError {
  Handshake(HandshakeError)
  Message(MessageError)
  Auth(AuthError)
  // The server flight was not the expected EncryptedExtensions, Certificate,
  // CertificateVerify, Finished sequence.
  UnexpectedFlight(String)
  // The server's CertificateVerify signature did not validate.
  CertificateVerifyFailed
  // The server's Finished MAC did not validate.
  ServerFinishedFailed
} derive(Debug)

///|
/// The traffic secrets and AEAD key/IV pairs negotiated by the handshake.
pub(all) struct HandshakeKeys {
  suite : CipherSuite
  client_handshake_traffic_secret : Bytes
  server_handshake_traffic_secret : Bytes
  client_handshake_key : Bytes
  client_handshake_iv : Bytes
  server_handshake_key : Bytes
  server_handshake_iv : Bytes
  client_application_traffic_secret : Bytes
  server_application_traffic_secret : Bytes
  client_application_key : Bytes
  client_application_iv : Bytes
  server_application_key : Bytes
  server_application_iv : Bytes
}

///|
/// The outcome of driving the client side of a 1-RTT handshake.
pub(all) struct ClientHandshakeResult {
  keys : HandshakeKeys
  // The server's certificate chain (leaf first), for the caller to validate
  // against its trust store with `pkix_verify`.
  server_certificates : Array[Bytes]
  // The client Finished handshake message to send (encrypt under the client
  // handshake traffic key) to complete the handshake.
  client_finished : Bytes
}

///|
// Hash(client_hello || server_hello || server_flight[0:end]).
fn transcript_upto(
  suite : CipherSuite,
  client_hello : Bytes,
  server_hello : Bytes,
  flight : Bytes,
  end : Int,
) -> Bytes {
  let prefix = Bytes::makei(end, fn(i) { flight[i] })
  suite
  .hash()
  .transcript_hash(concat_bytes([client_hello, server_hello, prefix]))
}

///|
/// Drive the client side of a 1-RTT handshake. See the module comment for the
/// division of responsibilities. Raises if the flight shape is wrong or if
/// server authentication fails (CertificateVerify or Finished).
pub fn client_handshake_1rtt(
  suite : CipherSuite,
  client_hello : Bytes,
  server_hello : Bytes,
  ecdhe_shared_secret : Bytes,
  server_flight : Bytes,
) -> ClientHandshakeResult raise ClientError {
  let h = suite.hash()
  let key_len = suite.key_len()

  // Handshake-stage secrets and keys (transcript = ClientHello..ServerHello).
  let th_ch_sh = h.transcript_hash(concat_bytes([client_hello, server_hello]))
  let early = h.early_secret(b"")
  let handshake = h.handshake_secret(early, ecdhe_shared_secret)
  let c_hs = h.client_handshake_traffic_secret(handshake, th_ch_sh)
  let s_hs = h.server_handshake_traffic_secret(handshake, th_ch_sh)

  // Walk the decrypted server flight, recording framed offsets so transcript
  // hashes can be taken at each message boundary.
  let msgs = parse_handshake_flight(server_flight) catch {
    e => raise Handshake(e)
  }
  if msgs.length() != 4 {
    raise UnexpectedFlight(
      "expected EE, Certificate, CertificateVerify, Finished",
    )
  }
  let ends : Array[Int] = []
  let mut off = 0
  for m in msgs {
    let (_, body) = m
    off = off + 4 + body.length()
    ends.push(off)
  }
  let (t_ee, _) = msgs[0]
  let (t_cert, cert_body) = msgs[1]
  let (t_cv, cv_body) = msgs[2]
  let (t_fin, _) = msgs[3]
  if t_ee != EncryptedExtensions ||
    t_cert != Certificate ||
    t_cv != CertificateVerify ||
    t_fin != Finished {
    raise UnexpectedFlight("server flight messages out of order")
  }

  // Server authentication, part 1: CertificateVerify over Transcript-Hash up to
  // and including the Certificate message.
  let chain = parse_certificate(cert_body) catch { e => raise Message(e) }
  if chain.length() == 0 {
    raise UnexpectedFlight("empty certificate chain")
  }
  let cv = parse_certificate_verify(cv_body) catch { e => raise Message(e) }
  let th_through_cert = transcript_upto(
    suite,
    client_hello,
    server_hello,
    server_flight,
    ends[1],
  )
  let cv_ok = verify_server_certificate_verify(chain[0], cv, th_through_cert) catch {
    e => raise Auth(e)
  }
  if !cv_ok {
    raise CertificateVerifyFailed
  }

  // Server authentication, part 2: the server Finished MAC over Transcript-Hash
  // up to and including CertificateVerify.
  let server_finished_msg = Bytes::makei(ends[3] - ends[2], fn(i) {
    server_flight[ends[2] + i]
  })
  let th_through_cv = transcript_upto(
    suite,
    client_hello,
    server_hello,
    server_flight,
    ends[2],
  )
  let fin_ok = verify_finished(suite, s_hs, th_through_cv, server_finished_msg) catch {
    e => raise Handshake(e)
  }
  if !fin_ok {
    raise ServerFinishedFailed
  }

  // Application-stage secrets (transcript = ClientHello..server Finished).
  let th_ch_sf = transcript_upto(
    suite,
    client_hello,
    server_hello,
    server_flight,
    ends[3],
  )
  let master = h.master_secret(handshake)
  let c_ap = h.client_application_traffic_secret(master, th_ch_sf)
  let s_ap = h.server_application_traffic_secret(master, th_ch_sf)

  // Client Finished: HMAC over the same through-server-Finished transcript,
  // keyed by the client handshake traffic secret.
  let client_finished = build_finished(suite, c_hs, th_ch_sf)
  let keys : HandshakeKeys = {
    suite,
    client_handshake_traffic_secret: c_hs,
    server_handshake_traffic_secret: s_hs,
    client_handshake_key: h.write_key(c_hs, key_len),
    client_handshake_iv: h.write_iv(c_hs),
    server_handshake_key: h.write_key(s_hs, key_len),
    server_handshake_iv: h.write_iv(s_hs),
    client_application_traffic_secret: c_ap,
    server_application_traffic_secret: s_ap,
    client_application_key: h.write_key(c_ap, key_len),
    client_application_iv: h.write_iv(c_ap),
    server_application_key: h.write_key(s_ap, key_len),
    server_application_iv: h.write_iv(s_ap),
  }
  { keys, server_certificates: chain, client_finished }
}
