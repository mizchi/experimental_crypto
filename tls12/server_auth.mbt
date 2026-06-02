// Verified TLS 1.2 server authentication — the MITM-resistant composition that
// `verify_server_key_exchange` alone is NOT (see key_exchange.mbt's warning).
//
// `verify_server_auth` ties together everything a client must check before it
// keys a session and sends application data:
//   1. chain-verify the server's Certificate message to a trust anchor, with
//      validity dates, basicConstraints/pathlen, name constraints, and the leaf
//      keyUsage=digitalSignature (mizchi/pkix_verify);
//   2. check the leaf's dNSName SANs against the expected hostname (RFC 6125);
//   3. verify the ECDHE ServerKeyExchange signature against the leaf key;
//   4. apply a revocation policy to an optional stapled OCSP response
//      (RFC 6066 status_request / RFC 6960), rejecting a revoked certificate.

///|
pub suberror ServerAuthError {
  ChainUntrusted(@pkix_verify.PkixVerifyError)
  CertParse(@pkix.PkixError)
  EmptyChain
  HostnameMismatch(String)
  BadServerKeyExchange
  /// The stapled OCSP response says the leaf is revoked.
  CertificateRevoked
  /// HardFail policy and the stapled OCSP status was absent or indeterminate.
  RevocationUnknown
  Ocsp(@ocsp.OcspError)
  KeyExchange(KeyExchangeError)
} derive(Debug)

///|
/// How to treat a missing or indeterminate stapled OCSP status.
pub(all) enum RevocationPolicy {
  /// Accept when no usable stapled status is available; reject only on an
  /// explicit `revoked`. (Browser default; stapling is best-effort over TLS.)
  SoftFail
  /// Require a fresh `good` stapled response; reject if absent / unknown / stale.
  HardFail
} derive(Eq, Debug)

///|
fn ascii_lower_char(c : Char) -> Char {
  let n = c.to_int()
  if n >= 0x41 && n <= 0x5a {
    (n + 0x20).to_char().unwrap()
  } else {
    c
  }
}

///|
// RFC 6125 hostname ↔ SAN match: exact (case-insensitive) or a single left-most
// `*.` wildcard label covering at least two further labels.
fn hostname_matches(hostname : String, san : String) -> Bool {
  let h = String::from_array(
    Array::makei(hostname.length(), fn(i) {
      ascii_lower_char(hostname.get_char(i).unwrap())
    }),
  )
  let s = String::from_array(
    Array::makei(san.length(), fn(i) {
      ascii_lower_char(san.get_char(i).unwrap())
    }),
  )
  if h.length() == 0 || s.length() == 0 {
    return false
  }
  if h == s {
    return true
  }
  if s.length() >= 2 &&
    s.get_char(0).unwrap() == '*' &&
    s.get_char(1).unwrap() == '.' {
    // suffix = s[1:] (".example.com"); require a dot beyond the leading one so
    // "*.com" is rejected.
    let mut suffix_has_dot = false
    for i = 2; i < s.length(); i = i + 1 {
      if s.get_char(i).unwrap() == '.' {
        suffix_has_dot = true
        break
      }
    }
    if !suffix_has_dot {
      return false
    }
    let label_len = h.length() - (s.length() - 1)
    if label_len <= 0 {
      return false
    }
    // h must end with s[1:].
    for i = 0; i < s.length() - 1; i = i + 1 {
      if h.get_char(label_len + i).unwrap() != s.get_char(1 + i).unwrap() {
        return false
      }
    }
    // The left-most matched label must be a single non-empty dot-free label.
    for i = 0; i < label_len; i = i + 1 {
      if h.get_char(i).unwrap() == '.' {
        return false
      }
    }
    return true
  }
  false
}

///|
/// Fully verify the server's authentication for a TLS 1.2 ECDHE handshake.
/// Raises on any failure; returns normally only when the server is trusted,
/// the hostname matches, the ServerKeyExchange signature is valid, and the
/// revocation policy is satisfied.
///
/// - `chain`: the Certificate message certificates (leaf first), e.g. from
///   `parse_certificate`.
/// - `trust_anchor`: the trusted root/CA certificate.
/// - `now`: current time as GeneralizedTime `YYYYMMDDHHMMSSZ`.
/// - `expected_hostname`: the SNI / URL host to match against the leaf SANs.
/// - `ske` + randoms: the parsed ServerKeyExchange and the two Hello randoms.
/// - `stapled_ocsp`: the DER OCSP response from a CertificateStatus message, or
///   `None` if the server did not staple one.
/// - `revocation`: policy for a missing / indeterminate stapled status.
pub fn verify_server_auth(
  chain : Array[Bytes],
  trust_anchor : @pkix.Certificate,
  now : String,
  expected_hostname : String,
  ske : ServerKeyExchange,
  client_random : Bytes,
  server_random : Bytes,
  stapled_ocsp? : Bytes? = None,
  revocation? : RevocationPolicy = SoftFail,
) -> Unit raise ServerAuthError {
  if chain.length() == 0 {
    raise EmptyChain
  }
  let parsed : Array[@pkix.Certificate] = []
  for der in chain {
    parsed.push(@pkix.parse_certificate(der) catch { e => raise CertParse(e) })
  }
  let leaf = parsed[0]
  let intermediates : Array[@pkix.Certificate] = []
  for i = 1; i < parsed.length(); i = i + 1 {
    intermediates.push(parsed[i])
  }

  // 1. Chain to the trust anchor (signatures, validity, constraints, leaf
  //    digitalSignature keyUsage).
  @pkix_verify.verify_chain_for_signature_with_anchor_cert(
    leaf, intermediates, trust_anchor, now,
  ) catch {
    e => raise ChainUntrusted(e)
  }

  // 2. Hostname identity (RFC 6125, dNSName SANs only).
  let sans = @pkix_verify.extract_dns_san(leaf) catch {
    e => raise ChainUntrusted(e)
  }
  let mut matched = false
  for san in sans {
    if hostname_matches(expected_hostname, san) {
      matched = true
      break
    }
  }
  if !matched {
    raise HostnameMismatch(expected_hostname)
  }

  // 3. ServerKeyExchange signature against the (now-trusted) leaf key.
  let der0 = chain[0]
  let ok = verify_server_key_exchange(der0, ske, client_random, server_random) catch {
    e => raise KeyExchange(e)
  }
  if !ok {
    raise BadServerKeyExchange
  }

  // 4. Revocation via the optional stapled OCSP response. The leaf's issuer is
  //    the first intermediate, or the anchor for a single-cert chain.
  let issuer = if intermediates.length() > 0 {
    intermediates[0]
  } else {
    trust_anchor
  }
  match stapled_ocsp {
    Some(resp_der) => {
      let status = @ocsp.verify(resp_der, leaf, issuer, now) catch {
        e =>
          // A malformed / unverifiable stapled response is indeterminate.
          match revocation {
            HardFail => raise Ocsp(e)
            SoftFail => return
          }
      }
      match status {
        Good => ()
        Revoked(..) => raise CertificateRevoked
        Unknown =>
          match revocation {
            HardFail => raise RevocationUnknown
            SoftFail => ()
          }
      }
    }
    None =>
      match revocation {
        HardFail => raise RevocationUnknown
        SoftFail => ()
      }
  }
}
