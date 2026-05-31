// WebAuthn verification against real FIDO2 vectors (Yubico python-fido2) plus
// the hardened relying-party policy checks (rpIdHash, UP, UV) and a
// self-consistent ES256 assertion.

///|
fn wh(s : String) -> Bytes {
  fn hv(c : Char) -> Int {
    let n = c.to_int()
    if n >= '0'.to_int() && n <= '9'.to_int() {
      n - '0'.to_int()
    } else if n >= 'a'.to_int() && n <= 'f'.to_int() {
      n - 'a'.to_int() + 10
    } else {
      abort("hex")
    }
  }

  Bytes::makei(s.length() / 2, fn(i) {
    (hv(s.get_char(2 * i).unwrap()) * 16 + hv(s.get_char(2 * i + 1).unwrap())).to_byte()
  })
}

///|
fn att_obj(
  fmt : String,
  auth_data : Bytes,
  att_stmt : Array[(@cbor.CborValue, @cbor.CborValue)],
) -> Bytes {
  @cbor.encode(
    Map([
      (Text("fmt"), Text(fmt)),
      (Text("authData"), Bytes(auth_data)),
      (Text("attStmt"), Map(att_stmt)),
    ]),
  )
}

// rpIdHash = the first 32 bytes of authenticatorData.

///|
fn rpid_of(auth_data : Bytes) -> Bytes {
  Bytes::makei(32, fn(i) { auth_data[i] })
}

///|
let u2f_hash : String = "687134968222ec17202e42505f8ed2b16ae22f16bb05b88c25db9e602645f141"

///|
let u2f_sig : String = "30450220324779c68f3380288a1197b6095f7a6eb9b1b1c127f66ae12a99fe8532ec23b9022100e39516ac4d61ee64044d50b415a6a4d4d84ba6d895cb5ab7a1aa7d081de341fa"

///|
let u2f_authdata : String = "1194228da8fdbdeefd261bd7b6595cfd70a50d70c6407bcf013de96d4efb17de41000000000000000000000000000000000000000000403ebd89bf77ec509755ee9c2635efaaac7b2b9c5cef1736c3717da48534c8c6b654d7ff945f50b5cc4e78055bdd396b64f78da2c5f96200ccd415cd08fe420038a5010203262001215820e87625896ee4e46dc032766e8087962f36df9dfe8b567f3763015b1990a60e1422582027de612d66418bda1950581ebc5c8c1dad710cb14c22f8c97045f4612fb20c91"

///|
let u2f_x5c : String = "3082024a30820132a0030201020204046c8822300d06092a864886f70d01010b0500302e312c302a0603550403132359756269636f2055324620526f6f742043412053657269616c203435373230303633313020170d3134303830313030303030305a180f32303530303930343030303030305a302c312a302806035504030c2159756269636f205532462045452053657269616c203234393138323332343737303059301306072a8648ce3d020106082a8648ce3d030107034200043ccab92ccb97287ee8e639437e21fcd6b6f165b2d5a3f3db131d31c16b742bb476d8d1e99080eb546c9bbdf556e6210fd42785899e78cc589ebe310f6cdb9ff4a33b3039302206092b0601040182c40a020415312e332e362e312e342e312e34313438322e312e323013060b2b0601040182e51c020101040403020430300d06092a864886f70d01010b050003820101009f9b052248bc4cf42cc5991fcaabac9b651bbe5bdcdc8ef0ad2c1c1ffb36d18715d42e78b249224f92c7e6e7a05c49f0e7e4c881bf2e94f45e4a21833d7456851d0f6c145a29540c874f3092c934b43d222b8962c0f410cef1db75892af116b44a96f5d35adea3822fc7146f6004385bcb69b65c99e7eb6919786703c0d8cd41e8f75cca44aa8ab725ad8e799ff3a8696a6f1b2656e631b1e40183c08fda53fa4a8f85a05693944ae179a1339d002d15cabd810090ec722ef5def9965a371d415d624b68a2707cad97bcdd1785af97e258f33df56a031aa0356d8e8d5ebcadc74e071636c6b110ace5cc9b90dfeacae640ff1bb0f1fe5db4eff7a95f060733f5"

///|
let pk_hash : String = "985b6187d042fb1258892ed637cec88617ddf5f6632351a545617aa2b75261bf"

///|
let pk_sig : String = "304502200d15daf337d727ab4719b4027114a2ac43cd565d394ced62c3d9d1d90825f0b3022100989615e7394c87f4ad91f8fdae86f7a3326df332b3633db088aac76bffb9a46b"

///|
let pk_authdata : String = "0021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae124100000003f8a011f38c0a4d15800617111f9edc7d004060a386206a3aacecbdbb22d601853d955fdc5d11adfbd1aa6a950d966b348c7663d40173714a9f987df6461beadfb9cd6419ffdfe4d4cf2eec1aa605a4f59bdaa50102032620012158200edb27580389494d74d2373b8f8c2e8b76fa135946d4f30d0e187e120b423349225820e03400d189e85a55de9ab0f538ed60736eb750f5f0306a80060fe1b13010560d"

///|
let pk_x5c : String = "308202b73082019fa00302010202041d31330d300d06092a864886f70d01010b0500302a3128302606035504030c1f59756269636f2050726576696577204649444f204174746573746174696f6e301e170d3138303332383036333932345a170d3139303332383036333932345a306e310b300906035504061302534531123010060355040a0c0959756269636f20414231223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e3127302506035504030c1e59756269636f205532462045452053657269616c203438393736333539373059301306072a8648ce3d020106082a8648ce3d030107034200047d71e8367cafd0ea6cf0d61e4c6a416ba5bb6d8fad52db2389ad07969f0f463bfdddddc29d39d3199163ee49575a3336c04b3309d607f6160c81e023373e0197a36c306a302206092b0601040182c40a020415312e332e362e312e342e312e34313438322e312e323013060b2b0601040182e51c0201010404030204303021060b2b0601040182e51c01010404120410f8a011f38c0a4d15800617111f9edc7d300c0603551d130101ff04023000300d06092a864886f70d01010b050003820101009b904ceadbe1f1985486fead02baeaa77e5ab4e6e52b7e6a2666a4dc06e241578169193b63dadec5b2b78605a128b2e03f7fe2a98eaeb4219f52220995f400ce15d630cf0598ba662d7162459f1ad1fc623067376d4e4091be65ac1a33d8561b9996c0529ec1816d1710786384d5e8783aa1f7474cb99fe8f5a63a79ff454380361c299d67cb5cc7c79f0d8c09f8849b0500f6d625408c77cbbc26ddee11cb581beb7947137ad4f05aaf38bd98da10042ddcac277604a395a5b3eaa88a5c8bb27ab59c8127d59d6bbba5f11506bf7b75fda7561a0837c46f025fd54dcf1014fc8d17c859507ac57d4b1dea99485df0ba8f34d00103c3eef2ef3bbfec7a6613de"

///|
test "parse authenticatorData (fido2 make-credential and get-assertion)" {
  let mc = wh(
    "0021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae12410000001cf8a011f38c0a4d15800617111f9edc7d0040fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a5290",
  )
  let ad = @webauthn.parse_authenticator_data(mc)
  @debug.assert_eq(ad.flags, 0x41)
  @debug.assert_eq(ad.sign_count, 28U)
  @debug.assert_eq(ad.user_present(), true)
  @debug.assert_eq(ad.attested_credential_data_present(), true)
  match ad.credential_public_key {
    Some(k) =>
      match @webauthn.parse_cose_key(k) {
        Es256(_) => ()
        _ => abort("expected ES256 credential key")
      }
    None => abort("no credential public key")
  }
  let ga = @webauthn.parse_authenticator_data(
    wh(
      "0021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae12010000001d",
    ),
  )
  @debug.assert_eq(ga.flags, 0x01)
  @debug.assert_eq(ga.sign_count, 29U)
  @debug.assert_eq(ga.attested_credential_data_present(), false)
}

///|
test "verify fido-u2f attestation (real fido2 vector)" {
  let auth_data = wh(u2f_authdata)
  let obj = att_obj("fido-u2f", auth_data, [
    (Text("sig"), Bytes(wh(u2f_sig))),
    (Text("x5c"), Array([Bytes(wh(u2f_x5c))])),
  ])
  let res = @webauthn.verify_attestation(
    obj,
    wh(u2f_hash),
    rp_id_hash=rpid_of(auth_data),
  )
  @debug.assert_eq(res.fmt, "fido-u2f")
  @debug.assert_eq(
    res.attestation_type,
    @webauthn.AttestationType::CertificateAttestation,
  )
  @debug.assert_eq(res.trust_path.length(), 1)

  // Tampered clientDataHash -> signature fails.
  let bad = Bytes::makei(32, fn(i) {
    (wh(u2f_hash)[i].to_int() ^ 0x01).to_byte()
  })
  try
    @webauthn.verify_attestation(obj, bad, rp_id_hash=rpid_of(auth_data))
    |> ignore
  catch {
    SignatureInvalid => ()
    e => abort("expected SignatureInvalid, got " + repr(e))
  } noraise {
    _ => abort("accepted tampered fido-u2f attestation")
  }

  // Wrong rpId -> rejected before the credential is trusted.
  try
    @webauthn.verify_attestation(obj, wh(u2f_hash), rp_id_hash=wh(pk_hash))
    |> ignore
  catch {
    RpIdMismatch => ()
    e => abort("expected RpIdMismatch, got " + repr(e))
  } noraise {
    _ => abort("accepted wrong rpId at registration")
  }
}

///|
test "verify packed attestation (real fido2 vector)" {
  let auth_data = wh(pk_authdata)
  let obj = att_obj("packed", auth_data, [
    (Nint(6UL), Nint(6UL)),
    (Text("sig"), Bytes(wh(pk_sig))),
    (Text("x5c"), Array([Bytes(wh(pk_x5c))])),
  ])
  let res = @webauthn.verify_attestation(
    obj,
    wh(pk_hash),
    rp_id_hash=rpid_of(auth_data),
  )
  @debug.assert_eq(res.fmt, "packed")
  @debug.assert_eq(
    res.attestation_type,
    @webauthn.AttestationType::CertificateAttestation,
  )
  match @webauthn.parse_cose_key(res.credential_public_key) {
    Es256(_) => ()
    _ => abort("expected ES256 credential key")
  }

  // No user-presence flag -> rejected (craft authData with UP cleared).
  let no_up = Bytes::makei(auth_data.length(), fn(i) {
    if i == 32 {
      (auth_data[i].to_int() & 0xbf).to_byte() // clear AT? keep AT, clear UP
    } else {
      auth_data[i]
    }
  })
  // Clearing only UP (bit 0): flags 0x41 -> 0x40.
  let no_up2 = Bytes::makei(auth_data.length(), fn(i) {
    if i == 32 {
      (auth_data[i].to_int() & 0xfe).to_byte()
    } else {
      auth_data[i]
    }
  })
  ignore(no_up)
  let obj_no_up = att_obj("packed", no_up2, [
    (Nint(6UL), Nint(6UL)),
    (Text("sig"), Bytes(wh(pk_sig))),
    (Text("x5c"), Array([Bytes(wh(pk_x5c))])),
  ])
  try
    @webauthn.verify_attestation(
      obj_no_up,
      wh(pk_hash),
      rp_id_hash=rpid_of(auth_data),
    )
    |> ignore
  catch {
    UserNotPresent => ()
    e => abort("expected UserNotPresent, got " + repr(e))
  } noraise {
    _ => abort("accepted attestation with UP=0")
  }
}

///|
test "assertion: policy + signature (ES256), with negative cases" {
  let sk = @p256.PrivateKey::from_bytes(
    wh("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"),
  )
  let pubu = sk.public_key().to_uncompressed()
  let x = Bytes::makei(32, fn(i) { pubu[1 + i] })
  let y = Bytes::makei(32, fn(i) { pubu[33 + i] })
  let cose = @cbor.encode(
    Map([
      (Uint(1UL), Uint(2UL)),
      (Uint(3UL), Nint(6UL)),
      (Nint(0UL), Uint(1UL)),
      (Nint(1UL), Bytes(x)),
      (Nint(2UL), Bytes(y)),
    ]),
  )
  let rpid = wh(
    "0021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae12",
  )
  fn auth(flags : Int) -> Bytes {
    Bytes::makei(37, fn(i) {
      if i < 32 {
        rpid[i]
      } else if i == 32 {
        flags.to_byte()
      } else if i == 36 {
        b'\x2a'
      } else {
        b'\x00'
      }
    })
  }

  let client_data_hash = @hash.sha256(b"client data to bind")
  fn sign(ad : Bytes) -> Bytes {
    let signed = Bytes::makei(ad.length() + client_data_hash.length(), fn(i) {
      if i < ad.length() {
        ad[i]
      } else {
        client_data_hash[i - ad.length()]
      }
    })
    sk.sign(signed, format=@p256.SignatureFormat::Der)
  }

  // UP set: verifies.
  let ad_up = auth(0x01)
  @webauthn.verify_assertion(
    cose,
    ad_up,
    client_data_hash,
    sign(ad_up),
    rp_id_hash=rpid,
  )
  // Wrong rpId -> RpIdMismatch.
  try
    @webauthn.verify_assertion(
      cose,
      ad_up,
      client_data_hash,
      sign(ad_up),
      rp_id_hash=wh(
        "00000000000000000000000000000000000000000000000000000000000000ff",
      ),
    )
    |> ignore
  catch {
    RpIdMismatch => ()
    e => abort("expected RpIdMismatch, got " + repr(e))
  } noraise {
    _ => abort("accepted wrong rpId")
  }
  // UP cleared -> UserNotPresent (even with a valid signature).
  let ad_noup = auth(0x00)
  try
    @webauthn.verify_assertion(
      cose,
      ad_noup,
      client_data_hash,
      sign(ad_noup),
      rp_id_hash=rpid,
    )
    |> ignore
  catch {
    UserNotPresent => ()
    e => abort("expected UserNotPresent, got " + repr(e))
  } noraise {
    _ => abort("accepted UP=0 assertion")
  }
  // require UV but UV not set -> UserNotVerified.
  try
    @webauthn.verify_assertion(
      cose,
      ad_up,
      client_data_hash,
      sign(ad_up),
      rp_id_hash=rpid,
      require_user_verification=true,
    )
    |> ignore
  catch {
    UserNotVerified => ()
    e => abort("expected UserNotVerified, got " + repr(e))
  } noraise {
    _ => abort("accepted UV=0 when UV required")
  }
  // UV set + required -> verifies.
  let ad_uv = auth(0x05)
  @webauthn.verify_assertion(
    cose,
    ad_uv,
    client_data_hash,
    sign(ad_uv),
    rp_id_hash=rpid,
    require_user_verification=true,
  )
  // Wrong clientDataHash -> SignatureInvalid.
  try
    @webauthn.verify_assertion(
      cose,
      ad_up,
      @hash.sha256(b"different"),
      sign(ad_up),
      rp_id_hash=rpid,
    )
    |> ignore
  catch {
    SignatureInvalid => ()
    e => abort("expected SignatureInvalid, got " + repr(e))
  } noraise {
    _ => abort("accepted wrong clientDataHash")
  }
}

///|
test "clientDataJSON type/challenge/origin binding" {
  let cdj = "{\"type\":\"webauthn.get\",\"challenge\":\"q1c5\",\"origin\":\"https://example.com\"}"
  @webauthn.verify_client_data(
    cdj, "webauthn.get", "q1c5", "https://example.com",
  )
  try
    @webauthn.verify_client_data(
      cdj, "webauthn.get", "q1c5", "https://evil.com",
    )
    |> ignore
  catch {
    ClientDataInvalid(_) => ()
    e => abort("expected ClientDataInvalid, got " + repr(e))
  } noraise {
    _ => abort("accepted a mismatched origin")
  }
}
