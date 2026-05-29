// Black-box fuzzing of the TLS 1.3 client. Two invariants:
//   1. No single-byte tamper of the RFC 8448 §3 handshake (ServerHello or the
//      server flight) ever produces a successful authenticated handshake.
//   2. The parsers and the record-open path never panic on arbitrary input;
//      they either parse a value or fail closed with a typed error.
// Reuses hs_hex / the RFC constants from handshake_test.mbt (same package).

///|
// Small deterministic LCG so the sweep is reproducible.
fn fz_bytes(seed : UInt64, len : Int) -> Bytes {
  let mut s = seed
  Bytes::makei(len, fn(_) {
    s = s * 6364136223846793005UL + 1442695040888963407UL
    ((s >> 33) & 0xffUL).to_int().to_byte()
  })
}

///|
fn fz_flip(b : Bytes, off : Int) -> Bytes {
  Bytes::makei(b.length(), fn(i) {
    if i == off {
      (b[i].to_int() ^ 0xff).to_byte()
    } else {
      b[i]
    }
  })
}

///|
test "fuzz: no single-byte tamper of the RFC handshake authenticates" {
  let suite = @tls13.CipherSuite::Aes128GcmSha256
  let ch = hs_hex(hs_client_hello)
  let sh = hs_hex(hs_server_hello)
  let flight = hs_hex(hs_server_flight)
  let ecdhe = hs_hex(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d",
  )

  // The clean handshake must succeed (otherwise the test is vacuous).
  let _ = @tls13.client_handshake_1rtt(suite, ch, sh, ecdhe, flight)

  // Flip each byte of the server flight: every mutation must be rejected.
  for off = 0; off < flight.length(); off = off + 1 {
    let bad = fz_flip(flight, off)
    try
      @tls13.client_handshake_1rtt(suite, ch, sh, ecdhe, bad) |> ignore
    catch {
      _ => ()
    } noraise {
      _ =>
        abort(
          "FALSE ACCEPT: flipping server-flight byte " +
          off.to_string() +
          " still authenticated",
        )
    }
  }

  // Flip each byte of the ServerHello: every mutation must be rejected.
  for off = 0; off < sh.length(); off = off + 1 {
    let bad = fz_flip(sh, off)
    try
      @tls13.client_handshake_1rtt(suite, ch, bad, ecdhe, flight) |> ignore
    catch {
      _ => ()
    } noraise {
      _ =>
        abort(
          "FALSE ACCEPT: flipping ServerHello byte " +
          off.to_string() +
          " still authenticated",
        )
    }
  }

  // Flip each byte of the ECDHE secret: wrong shared secret must be rejected.
  for off = 0; off < ecdhe.length(); off = off + 1 {
    let bad = fz_flip(ecdhe, off)
    try
      @tls13.client_handshake_1rtt(suite, ch, sh, bad, flight) |> ignore
    catch {
      _ => ()
    } noraise {
      _ => abort("FALSE ACCEPT: wrong ECDHE secret still authenticated")
    }
  }
}

///|
test "fuzz: parsers and record-open fail closed on random input" {
  // Random byte blobs of varied lengths must never panic; parse-or-raise only.
  for trial = 0; trial < 400; trial = trial + 1 {
    let len = trial % 80
    let blob = fz_bytes(
      0x9e3779b97f4a7c15UL + trial.to_uint64() * 2654435761UL,
      len,
    )
    try @tls13.parse_handshake(blob) |> ignore catch {
      _ => ()
    }
    try @tls13.parse_server_hello(blob) |> ignore catch {
      _ => ()
    }
    try @tls13.parse_certificate(blob) |> ignore catch {
      _ => ()
    }
    try @tls13.parse_certificate_verify(blob) |> ignore catch {
      _ => ()
    }
    try @tls13.parse_client_hello(blob) |> ignore catch {
      _ => ()
    }
  }

  // open_record on random keys/records must fail closed (never return plaintext
  // for an unauthenticated record), and never panic.
  let suite = @tls13.CipherSuite::Aes128GcmSha256
  for trial = 0; trial < 200; trial = trial + 1 {
    let key = fz_bytes(0x1234UL + trial.to_uint64(), 16)
    let iv = fz_bytes(0xabcdUL + trial.to_uint64(), 12)
    let rec = fz_bytes(0x55aaUL + trial.to_uint64() * 7UL, trial % 60)
    try
      @tls13.open_record(suite, key, iv, trial.to_uint64(), rec) |> ignore
    catch {
      _ => ()
    } noraise {
      _ =>
        abort(
          "FALSE ACCEPT: open_record returned plaintext for a random record",
        )
    }
  }
}

///|
fn fz_slice(b : Bytes, start : Int, len : Int) -> Bytes {
  Bytes::makei(len, fn(i) { b[start + i] })
}

///|
fn fz_concat2(a : Bytes, b : Bytes) -> Bytes {
  Bytes::makei(a.length() + b.length(), fn(i) {
    if i < a.length() {
      a[i]
    } else {
      b[i - a.length()]
    }
  })
}

///|
test "fuzz: structural attacks on the server flight are rejected" {
  let suite = @tls13.CipherSuite::Aes128GcmSha256
  let ch = hs_hex(hs_client_hello)
  let sh = hs_hex(hs_server_hello)
  let flight = hs_hex(hs_server_flight)
  let ecdhe = hs_hex(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d",
  )
  let attempt = fn(bad : Bytes, what : String) {
    try
      @tls13.client_handshake_1rtt(suite, ch, sh, ecdhe, bad) |> ignore
    catch {
      _ => ()
    } noraise {
      _ => abort("FALSE ACCEPT: " + what)
    }
  }

  // (a) Every truncation of the flight.
  for n = 0; n < flight.length(); n = n + 1 {
    attempt(fz_slice(flight, 0, n), "truncated flight len " + n.to_string())
  }

  // (b) Trailing garbage after the (valid) flight.
  attempt(fz_concat2(flight, b"\x00"), "flight + trailing 0x00")
  attempt(fz_concat2(flight, flight), "flight doubled")

  // (c) Reordered messages (CertificateVerify before Certificate).
  let msgs = @tls13.parse_handshake_flight(flight)
  let ends : Array[Int] = []
  let mut off = 0
  for m in msgs {
    let (_, body) = m
    off = off + 4 + body.length()
    ends.push(off)
  }
  let ee = fz_slice(flight, 0, ends[0])
  let cert = fz_slice(flight, ends[0], ends[1] - ends[0])
  let cv = fz_slice(flight, ends[1], ends[2] - ends[1])
  let fin = fz_slice(flight, ends[2], ends[3] - ends[2])
  attempt(
    fz_concat2(fz_concat2(ee, cv), fz_concat2(cert, fin)),
    "Cert/CertVerify swapped",
  )
  attempt(
    fz_concat2(fz_concat2(cert, cv), fz_concat2(ee, fin)),
    "EE/Cert swapped",
  )
  // (d) Dropped CertificateVerify (3 messages).
  attempt(fz_concat2(fz_concat2(ee, cert), fin), "CertificateVerify dropped")
  // (e) Duplicated Finished (5 messages).
  attempt(fz_concat2(flight, fin), "Finished duplicated")

  // (f) Many multi-byte random mutations.
  for trial = 0; trial < 150; trial = trial + 1 {
    let mask = fz_bytes(
      0xdead0000UL + trial.to_uint64() * 99991UL,
      flight.length(),
    )
    // Sparse mutation: flip ~1/16 of bytes.
    let bad = Bytes::makei(flight.length(), fn(i) {
      if (mask[i].to_int() & 0x0f) == 0 {
        (flight[i].to_int() ^ mask[i].to_int()).to_byte()
      } else {
        flight[i]
      }
    })
    if bad != flight {
      attempt(bad, "multi-byte mutation trial " + trial.to_string())
    }
  }
}

///|
test "fuzz: tampering the RFC record is always rejected by open_record" {
  // The RFC 8448 §3 server flight record (server hs key/iv, seq 0).
  let suite = @tls13.CipherSuite::Aes128GcmSha256
  let key = hs_hex("3fce516009c21727d0f2e4e86ee403bc")
  let iv = hs_hex("5d313eb2671276ee13000b30")
  let record = hs_hex(rec_record)

  // The clean record opens.
  let _ = @tls13.open_record(suite, key, iv, 0UL, record)

  // Every single-byte flip must fail the AEAD tag (or framing) check.
  for off = 0; off < record.length(); off = off + 7 {
    let bad = fz_flip(record, off)
    try @tls13.open_record(suite, key, iv, 0UL, bad) |> ignore catch {
      _ => ()
    } noraise {
      _ =>
        abort(
          "FALSE ACCEPT: open_record accepted a tampered record at byte " +
          off.to_string(),
        )
    }
  }
}
