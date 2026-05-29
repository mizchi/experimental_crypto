// TLS 1.3 client handshake driver (RFC 8446 §4): a one-shot orchestration of
// the building blocks for a 1-RTT handshake. Given the ClientHello and
// ServerHello it sent/received, the negotiated (EC)DHE shared secret, and the
// decrypted server flight (EncryptedExtensions, Certificate, CertificateVerify,
// Finished), it runs the key schedule, authenticates the server (CertificateVerify
// signature + server Finished MAC), derives the application traffic keys, and
// produces the client Finished message.
//
// This deliberately stays pure: the caller owns the socket, the ECDHE keypair,
// and the record (de)framing (see seal_record / open_record).
//
// Two entry points, differing in how far they take server authentication:
//   - client_handshake_1rtt proves only that the server holds the leaf key and
//     agrees on the transcript (CertificateVerify + Finished). Chain-of-trust
//     and hostname validation are the caller's job; the returned
//     `server_certificates` chain is meant for `pkix_verify`.
//   - client_handshake_1rtt_verified additionally validates the chain to a
//     supplied trust anchor (via `pkix_verify`) and matches the leaf SAN
//     against an expected hostname (RFC 6125), so a non-raising return means
//     the server is fully authenticated for that name.

///|
pub suberror ClientError {
  Handshake(HandshakeError)
  Message(MessageError)
  Auth(AuthError)
  // The server flight was not the expected EncryptedExtensions, Certificate,
  // CertificateVerify, Finished sequence.
  UnexpectedFlight(String)
  // The second handshake message was not a ServerHello.
  NotServerHello
  // ServerHello was a HelloRetryRequest, which this one-shot driver does not
  // support (it would require a second ClientHello and the §4.4.1 transcript
  // synthesis).
  HelloRetryRequestUnsupported
  // The negotiated version is not TLS 1.3 (no supported_versions == 0x0304).
  NotTls13(Int?)
  // RFC 8446 §4.1.3 downgrade sentinel present in ServerHello.random: an active
  // attacker forced a fallback below TLS 1.3.
  DowngradeDetected
  // The server selected a cipher suite different from the one this driver was
  // told to use (and would key the handshake with).
  CipherSuiteMismatch(Int)
  // The ServerHello carried no key_share, so the ECDHE secret is unanchored.
  MissingKeyShare
  // The supplied (EC)DHE shared secret is empty or all-zero — the contributory-
  // behaviour / small-order-point abort condition (RFC 7748 §6.1).
  WeakSharedSecret
  // The server's CertificateVerify signature did not validate.
  CertificateVerifyFailed
  // The server's Finished MAC did not validate.
  ServerFinishedFailed
  // A certificate in the chain failed to parse as DER.
  CertParse(@pkix.PkixError)
  // The server certificate chain did not validate to the trust anchor.
  ChainUntrusted(@pkix_verify.PkixVerifyError)
  // No dNSName SAN on the leaf matched the expected hostname.
  HostnameMismatch(String)
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
// RFC 8446 §4.1.3: a genuine TLS 1.3 server MUST NOT set these in the last 8
// bytes of ServerHello.random; their presence means an active attacker forced a
// downgrade to TLS 1.2 ("DOWNGRD\x01") or below ("DOWNGRD\x00").
fn has_downgrade_sentinel(random : Bytes) -> Bool {
  if random.length() != 32 {
    return false
  }
  let s12 = b"DOWNGRD\x01"
  let s11 = b"DOWNGRD\x00"
  let mut m12 = true
  let mut m11 = true
  for i in 0..<8 {
    let b = random[24 + i]
    if b != s12[i] {
      m12 = false
    }
    if b != s11[i] {
      m11 = false
    }
  }
  m12 || m11
}

///|
// Validate the ServerHello before deriving any keys from it: reject HRR, a
// non-TLS-1.3 negotiation, a downgrade sentinel, a cipher suite other than the
// one we will key with, and a missing key_share. `sh_message` is the full
// ServerHello handshake message (with its 4-byte header).
fn validate_server_hello(
  suite : CipherSuite,
  sh_message : Bytes,
) -> Unit raise ClientError {
  let (t, body, _) = parse_handshake(sh_message) catch {
    e => raise Handshake(e)
  }
  if t != ServerHello {
    raise NotServerHello
  }
  let sh = parse_server_hello(body) catch { e => raise Message(e) }
  if sh.is_hello_retry_request {
    raise HelloRetryRequestUnsupported
  }
  if has_downgrade_sentinel(sh.random) {
    raise DowngradeDetected
  }
  match sh.selected_version {
    Some(0x0304) => ()
    other => raise NotTls13(other)
  }
  if sh.cipher_suite != suite.to_u16() {
    raise CipherSuiteMismatch(sh.cipher_suite)
  }
  match sh.key_share {
    Some(_) => ()
    None => raise MissingKeyShare
  }
}

///|
fn is_all_zero(b : Bytes) -> Bool {
  if b.length() == 0 {
    return true
  }
  for i in 0..<b.length() {
    if b[i] != b'\x00' {
      return false
    }
  }
  true
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

  // Reject downgrade / HRR / suite-confusion before deriving anything from the
  // ServerHello. (The transcript still uses the raw ServerHello bytes.)
  validate_server_hello(suite, server_hello)

  // Defence in depth (RFC 7748 §6.1): an empty or all-zero (EC)DHE secret means
  // the peer's key share was a small-order point / contributory failure.
  if is_all_zero(ecdhe_shared_secret) {
    raise WeakSharedSecret
  }

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

// ─── turnkey server authentication (chain trust + hostname) ──────────────

///|
fn ascii_lower(s : String) -> String {
  let buf = StringBuilder::new()
  for c in s {
    let n = c.to_int()
    if n >= 0x41 && n <= 0x5a {
      buf.write_char((n + 0x20).to_char().unwrap())
    } else {
      buf.write_char(c)
    }
  }
  buf.to_string()
}

///|
// Does `h` end with `s[s_start:]`?
fn ends_with_from(h : String, s : String, s_start : Int) -> Bool {
  let suffix_len = s.length() - s_start
  if suffix_len > h.length() {
    return false
  }
  let off = h.length() - suffix_len
  for i in 0..<suffix_len {
    if h.get_char(off + i).unwrap() != s.get_char(s_start + i).unwrap() {
      return false
    }
  }
  true
}

///|
// Is there a '.' in `s[start:]`?
fn has_dot_from(s : String, start : Int) -> Bool {
  for i in start..<s.length() {
    if s.get_char(i).unwrap() == '.' {
      return true
    }
  }
  false
}

///|
/// RFC 6125 §6.4.3 hostname matching of a DNS-ID against a certificate SAN
/// dNSName. Case-insensitive exact match, plus a single left-most-label
/// wildcard (`*.example.com` matches exactly one label — `a.example.com` but
/// not `example.com` or `a.b.example.com`). Partial-label wildcards
/// (`f*.example.com`), bare `*`, and wildcards covering a bare TLD (`*.com`)
/// are rejected.
pub fn hostname_matches_san(hostname : String, san : String) -> Bool {
  let h = ascii_lower(hostname)
  let s = ascii_lower(san)
  if h.length() == 0 || s.length() == 0 {
    return false
  }
  if h == s {
    return true
  }
  // Wildcard must be exactly the whole left-most label: a "*." prefix.
  if s.length() >= 2 &&
    s.get_char(0).unwrap() == '*' &&
    s.get_char(1).unwrap() == '.' {
    // Wildcard suffix is s[1:] (".example.com"); it must cover at least two
    // labels (a dot beyond the leading one) so "*.com" cannot match.
    if !has_dot_from(s, 2) {
      return false
    }
    if !ends_with_from(h, s, 1) {
      return false
    }
    // The matched left-most label is h up to the suffix; it must be exactly one
    // non-empty, dot-free label.
    let label_len = h.length() - (s.length() - 1)
    if label_len <= 0 {
      return false
    }
    for i in 0..<label_len {
      if h.get_char(i).unwrap() == '.' {
        return false
      }
    }
    return true
  }
  false
}

///|
/// Like `client_handshake_1rtt`, but additionally establishes server identity:
/// it validates the server certificate chain (leaf -> `trust_anchor`) with
/// `pkix_verify` and checks the leaf's dNSName SANs against `expected_hostname`
/// (RFC 6125). A non-raising return therefore means the server was both
/// cryptographically authenticated (CertificateVerify + Finished) AND its
/// certificate is trusted for the requested name.
///
/// `now` is the validation time as an RFC 5280 UTCTime/GeneralizedTime string
/// (e.g. "20240101000000Z").
pub fn client_handshake_1rtt_verified(
  suite : CipherSuite,
  client_hello : Bytes,
  server_hello : Bytes,
  ecdhe_shared_secret : Bytes,
  server_flight : Bytes,
  trust_anchor : @pkix.Certificate,
  now : String,
  expected_hostname : String,
) -> ClientHandshakeResult raise ClientError {
  let result = client_handshake_1rtt(
    suite, client_hello, server_hello, ecdhe_shared_secret, server_flight,
  )
  // Parse the chain and validate leaf -> trust_anchor (signatures, validity,
  // basicConstraints, pathLen, name constraints, leaf digitalSignature).
  let parsed : Array[@pkix.Certificate] = []
  for der in result.server_certificates {
    parsed.push(@pkix.parse_certificate(der) catch { e => raise CertParse(e) })
  }
  let leaf = parsed[0]
  let intermediates : Array[@pkix.Certificate] = []
  for i = 1; i < parsed.length(); i = i + 1 {
    intermediates.push(parsed[i])
  }
  @pkix_verify.verify_chain_for_signature_with_anchor_cert(
    leaf, intermediates, trust_anchor, now,
  ) catch {
    e => raise ChainUntrusted(e)
  }
  // RFC 6125 identity check against the leaf's dNSName SANs.
  let sans = @pkix_verify.extract_dns_san(leaf) catch {
    e => raise ChainUntrusted(e)
  }
  let mut matched = false
  for san in sans {
    if hostname_matches_san(expected_hostname, san) {
      matched = true
      break
    }
  }
  if !matched {
    raise HostnameMismatch(expected_hostname)
  }
  result
}
