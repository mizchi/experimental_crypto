// Verified TLS 1.2 server-authentication tests. Material minted offline:
//   * a P-256 CA (trust anchor) and a CA-signed leaf (SAN=localhost,
//     keyUsage=digitalSignature, EKU=serverAuth);
//   * a ServerKeyExchange over client_random||server_random||params signed by
//     the leaf key (Node ECDSA-SHA256);
//   * OCSP good / revoked responses for the leaf, signed by the CA (openssl).
// `now` (20260603) is inside every validity window.

///|
let sa_now : String = "20260603000000Z"

///|
let sa_cr : String = "1111111111111111111111111111111111111111111111111111111111111111"

///|
let sa_sr : String = "2222222222222222222222222222222222222222222222222222222222222222"

///|
let sa_ca : String = "308201953082013ba00302010202143e6b78c4ea4f7b56af7679849d863b0ecd31dde4300a06082a8648ce3d04030230183116301406035504030c0d544c5331322054657374204341301e170d3236303630323034343531395a170d3336303533303034343531395a30183116301406035504030c0d544c53313220546573742043413059301306072a8648ce3d020106082a8648ce3d0301070342000469279f9d4fd364b07981e6cddb649ac30dd03d90ec27d3764f0889ab5b3910807bbf361db09309f6bef9eeca5abbaa21f2221681f65a13fcd3d72adad30dd473a3633061301d0603551d0e0416041407ddc3d1fbb69ff12ce4a635a14c6f81cd5e5447301f0603551d2304183016801407ddc3d1fbb69ff12ce4a635a14c6f81cd5e5447300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300a06082a8648ce3d0403020348003045022100c726c08feea8fb9bd28d0c6f2792c20fe6cee16ae48141e95ee16a820791bd200220701aebdbd4346b25b1da0a0e5c2eac8ce67f46e39ebe6a20cbda6f79ad368b67"

///|
let sa_leaf : String = "308201ac30820151a003020102021420a37e49f78d2b10dd5f6e06a0a5a143426c245e300a06082a8648ce3d04030230183116301406035504030c0d544c5331322054657374204341301e170d3236303630323034343532305a170d3238303930343034343532305a30143112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d030107034200048cb45fba4326be7a00367df1f440f633320a5edc33dc72321c2366ec95f3470b2659ac74be8827878efb23998ee7b25765f6b0591d21bd6f27fd835cd98fba6ca37d307b30140603551d11040d300b82096c6f63616c686f7374300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070301301d0603551d0e04160414efaf24d94bfad5781eb5be0d7d9c1fb3f3f88b60301f0603551d2304183016801407ddc3d1fbb69ff12ce4a635a14c6f81cd5e5447300a06082a8648ce3d0403020349003046022100dae0ff3c530f0d866a624bb58a858e8d18230a46cb0a2fd044bd753aebbd7201022100f99abfc82d99bebc32b1428ae5e6ea0ef100233f9902acea504f57c443f577ed"

///|
let sa_ske : String = "03001d2033333333333333333333333333333333333333333333333333333333333333330403004730450220451a28e90759413ba1dd888eb6915d98f1054adf2d8e735afee220c262c39f46022100c41fa3eb266f5fd26880b71629b1e80ada799dc061cca2f61068600685ba4fe2"

///|
let sa_ocsp_good : String = "3082011c0a0100a08201153082011106092b0601050507300101048201023081ff3081a6a11a30183116301406035504030c0d544c5331322054657374204341180f32303236303630323034343735385a30773075304d300906052b0e03021a0500041447c481969945db6e0fe0c8d80ec291c418b038d3041407ddc3d1fbb69ff12ce4a635a14c6f81cd5e5447021420a37e49f78d2b10dd5f6e06a0a5a143426c245e8000180f32303236303630323034343735385aa011180f32303236303630393034343735385a300a06082a8648ce3d0403020348003045022019ee03dd0fb6faaea77bfe6aee6618c33cbc59bda9983054e3c4b86691614d4c022100fa57e209b2d0b6edf0bc38db0038c23e8f991b94be5086a372e261e3b3313301"

///|
let sa_ocsp_revoked : String = "308201340a0100a082012d3082012906092b06010505073001010482011a308201163081bea11a30183116301406035504030c0d544c5331322054657374204341180f32303236303630323034343735385a30818e30818b304d300906052b0e03021a0500041447c481969945db6e0fe0c8d80ec291c418b038d3041407ddc3d1fbb69ff12ce4a635a14c6f81cd5e5447021420a37e49f78d2b10dd5f6e06a0a5a143426c245ea116180f32303236303630323034343532305aa0030a0100180f32303236303630323034343735385aa011180f32303236303630393034343735385a300a06082a8648ce3d0403020347003044022011f52678776be17c603acf1c820171383d306990c618547648092b3de560aaad02207fb94c7eadfbcaa0773ef09bf56a45bdba8c64ab9df44185a55c78b3c7e3dba0"

///|
fn sa_anchor() -> @pkix.Certificate raise {
  @pkix.parse_certificate(hx(sa_ca))
}

///|
fn sa_ske_parsed() -> @tls12.ServerKeyExchange raise {
  @tls12.parse_server_key_exchange(hx(sa_ske))
}

///|
fn sa_catch(thunk : () -> Unit raise) -> Bool {
  (try? thunk()) is Err(_)
}

///|
test "verify_server_auth accepts a trusted chain + valid SKE + matching host" {
  @tls12.verify_server_auth(
    [hx(sa_leaf)],
    sa_anchor(),
    sa_now,
    "localhost",
    sa_ske_parsed(),
    hx(sa_cr),
    hx(sa_sr),
  )
}

///|
test "verify_server_auth rejects a hostname mismatch" {
  let rejected = sa_catch(() => {
    @tls12.verify_server_auth(
      [hx(sa_leaf)],
      sa_anchor(),
      sa_now,
      "evil.example.com",
      sa_ske_parsed(),
      hx(sa_cr),
      hx(sa_sr),
    )
  })
  inspect(rejected, content="true")
}

///|
test "verify_server_auth rejects an untrusted anchor (self-signed leaf gap closed)" {
  // Use the leaf as its own 'anchor' — it is not a valid CA, so the chain
  // fails. This is exactly the self-signed cert that verify_server_key_exchange
  // alone would accept.
  let leaf_as_anchor = @pkix.parse_certificate(hx(sa_leaf))
  let rejected = sa_catch(() => {
    @tls12.verify_server_auth(
      [hx(sa_leaf)],
      leaf_as_anchor,
      sa_now,
      "localhost",
      sa_ske_parsed(),
      hx(sa_cr),
      hx(sa_sr),
    )
  })
  inspect(rejected, content="true")
}

///|
test "verify_server_auth rejects a tampered ServerKeyExchange signature" {
  let rejected = sa_catch(() => {
    @tls12.verify_server_auth(
      [hx(sa_leaf)],
      sa_anchor(),
      sa_now,
      "localhost",
      sa_ske_parsed(),
      rep(0x00, 32), // wrong client_random → SKE signature no longer matches
      hx(sa_sr),
    )
  })
  inspect(rejected, content="true")
}

///|
test "verify_server_auth: OCSP good staple passes HardFail" {
  @tls12.verify_server_auth(
    [hx(sa_leaf)],
    sa_anchor(),
    sa_now,
    "localhost",
    sa_ske_parsed(),
    hx(sa_cr),
    hx(sa_sr),
    stapled_ocsp=Some(hx(sa_ocsp_good)),
    revocation=@tls12.RevocationPolicy::HardFail,
  )
}

///|
test "verify_server_auth: OCSP revoked staple is rejected (even SoftFail)" {
  let rejected = sa_catch(() => {
    @tls12.verify_server_auth(
      [hx(sa_leaf)],
      sa_anchor(),
      sa_now,
      "localhost",
      sa_ske_parsed(),
      hx(sa_cr),
      hx(sa_sr),
      stapled_ocsp=Some(hx(sa_ocsp_revoked)),
      revocation=@tls12.RevocationPolicy::SoftFail,
    )
  })
  inspect(rejected, content="true")
}

///|
test "verify_server_auth: HardFail with no staple is rejected; SoftFail accepts" {
  let hard_rejected = sa_catch(() => {
    @tls12.verify_server_auth(
      [hx(sa_leaf)],
      sa_anchor(),
      sa_now,
      "localhost",
      sa_ske_parsed(),
      hx(sa_cr),
      hx(sa_sr),
      revocation=@tls12.RevocationPolicy::HardFail,
    )
  })
  inspect(hard_rejected, content="true")
  // SoftFail (default) accepts the absence of a stapled status.
  @tls12.verify_server_auth(
    [hx(sa_leaf)],
    sa_anchor(),
    sa_now,
    "localhost",
    sa_ske_parsed(),
    hx(sa_cr),
    hx(sa_sr),
  )
}
