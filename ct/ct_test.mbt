// SCT verification tests. Synthetic but real crypto: a P-256 CT log key
// (openssl) signs the x509_entry signed data over a leaf cert (Node ECDSA-
// SHA256, DER), wrapped into a SignedCertificateTimestampList + OCTET STRING
// exactly as it appears in the X.509 SCT extension.

///|
fn chex(s : String) -> Bytes {
  fn nib(c : Char) -> Int {
    let n = c.to_int()
    if n >= 0x30 && n <= 0x39 {
      n - 0x30
    } else if n >= 0x61 && n <= 0x66 {
      n - 0x61 + 10
    } else {
      abort("bad hex")
    }
  }

  let len = s.length() / 2
  let out = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = ((nib(s.get_char(i * 2).unwrap()) << 4) |
    nib(s.get_char(i * 2 + 1).unwrap())).to_byte()
  }
  Bytes::makei(len, fn(j) { out[j] })
}

///|
let ct_spki : String = "3059301306072a8648ce3d020106082a8648ce3d0301070342000416036bddeefe4c2df32468e17783a2b16dcb2858e969f41cb0660dae681b30fefa4e0b410f790a5518bc59e428bcbdd8af35018b2ff1d7b7bfe3263e30c68aa9"

///|
let ct_cert : String = "3082017e30820125a003020102021465cab249ae3249ba4a45c7fb1c0b2d4a75d0731f300a06082a8648ce3d04030230153113301106035504030c0a63742e6578616d706c65301e170d3236303630323037313130375a170d3236303630343037313130375a30153113301106035504030c0a63742e6578616d706c653059301306072a8648ce3d020106082a8648ce3d03010703420004e27fa772474a9709c9141b54fc309a33df767c2f6a6bb357015d939154198c7be9abec29ec6ca3608694354eb190e0387c24f959097c7c0aa837dc59546e60c8a3533051301d0603551d0e0416041442f5035ab145924d63abaa9afffdc75490369955301f0603551d2304183016801442f5035ab145924d63abaa9afffdc75490369955300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034700304402206720b823906f6eede9629cd771dcb386beb2f8d58f03b11bb06c11d6f74ca8e1022062c9b18ce8ca7d151ecd12800589df4f2e003544ba545ba289f9629122f2a7f5"

///|
let ct_extn : String = "047b0079007700bfb17366dcad3cb7b42b6ae3833cd3f99d1e8a2980ddc0f5c544ef87ef6225290000018f3a2b1c000000040300483046022100cd727e5b21d7625e9036edb0963fc90e34bf5b286426bd39d86aa0d3674c1e310221008e9acb5bf19b1272d60c5fd98f518c2d843143b560d30a1dfeccb50b2bd85042"

///|
test "CT parse SCT list fields" {
  let scts = @ct.parse_sct_list(chex(ct_extn))
  inspect(scts.length(), content="1")
  let s = scts[0]
  inspect(s.version(), content="0")
  inspect(s.sig_scheme(), content="1027") // 0x0403 ecdsa_secp256r1_sha256
  inspect(s.timestamp().to_string(), content="1714667854848")
  inspect(s.log_id().length(), content="32")
  // log_id == SHA-256(SPKI)
  let want = @ct.log_id_for_spki(chex(ct_spki))
  let mut eq = true
  for i in 0..<32 {
    if s.log_id()[i] != want[i] {
      eq = false
    }
  }
  inspect(eq, content="true")
}

///|
test "CT verify_sct accepts a valid x509_entry SCT" {
  let sct = @ct.parse_sct_list(chex(ct_extn))[0]
  let entry = @ct.x509_entry(chex(ct_cert))
  inspect(@ct.verify_sct(sct, chex(ct_spki), 0, entry), content="true")
}

///|
test "CT verify_sct rejects a tampered entry (wrong cert)" {
  let sct = @ct.parse_sct_list(chex(ct_extn))[0]
  // Flip one byte of the certificate → signed data no longer matches.
  let cert = chex(ct_cert)
  let bad_cert = Bytes::makei(cert.length(), fn(i) {
    if i == 10 {
      (cert[i].to_int() ^ 0x01).to_byte()
    } else {
      cert[i]
    }
  })
  inspect(
    @ct.verify_sct(sct, chex(ct_spki), 0, @ct.x509_entry(bad_cert)),
    content="false",
  )
}

///|
test "CT verify_sct rejects a log-id / key mismatch" {
  let sct = @ct.parse_sct_list(chex(ct_extn))[0]
  // Flip a byte of the public-key bits in the SPKI: SHA-256(SPKI) changes, so
  // the SCT's log_id no longer matches this key.
  let spki = chex(ct_spki)
  let wrong_spki = Bytes::makei(spki.length(), fn(i) {
    if i == spki.length() - 1 {
      (spki[i].to_int() ^ 0x01).to_byte()
    } else {
      spki[i]
    }
  })
  inspect(
    @ct.verify_sct(sct, wrong_spki, 0, @ct.x509_entry(chex(ct_cert))),
    content="false",
  )
}

///|
test "CT precert_entry builds issuer_key_hash || u24(tbs) || tbs" {
  let ikh = Bytes::makei(32, fn(i) { i.to_byte() })
  let tbs = Bytes::makei(5, fn(_i) { b'\xaa' })
  let entry = @ct.precert_entry(ikh, tbs)
  inspect(entry.length(), content="40") // 32 + 3 + 5
  inspect(entry[32].to_int(), content="0") // u24 len high
  inspect(entry[34].to_int(), content="5") // u24 len low
}
