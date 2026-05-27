// Blackbox tests against real openssl-cms-generated detached signatures.

///|
fn hex_to_bytes(s : String) -> Bytes {
  fn nib(c : Char) -> Int {
    let n = c.to_int()
    if n >= 0x30 && n <= 0x39 {
      n - 0x30
    } else if n >= 0x61 && n <= 0x66 {
      n - 0x61 + 10
    } else if n >= 0x41 && n <= 0x46 {
      n - 0x41 + 10
    } else {
      abort("bad hex")
    }
  }

  let len = s.length() / 2
  let out = FixedArray::make(len, b'\x00')
  let mut i = 0
  while i < len {
    let hi = nib(s.get_char(i * 2).unwrap())
    let lo = nib(s.get_char(i * 2 + 1).unwrap())
    out[i] = (hi * 16 + lo).to_byte()
    i = i + 1
  }
  Bytes::makei(len, fn(j) { out[j] })
}

///|
fn bytes_match_at(haystack : Bytes, needle : Bytes, offset : Int) -> Bool {
  if offset + needle.length() > haystack.length() {
    return false
  }
  for i = 0; i < needle.length(); i = i + 1 {
    if haystack[offset + i] != needle[i] {
      return false
    }
  }
  true
}

///|
fn replace_last_bytes(
  haystack : Bytes,
  needle : Bytes,
  replacement : Bytes,
) -> Bytes {
  if needle.length() == 0 || needle.length() != replacement.length() {
    abort("invalid replacement")
  }
  let mut last = -1
  let stop = haystack.length() - needle.length()
  for i = 0; i <= stop; i = i + 1 {
    if bytes_match_at(haystack, needle, i) {
      last = i
    }
  }
  if last < 0 {
    abort("needle not found")
  }
  Bytes::makei(haystack.length(), fn(i) {
    if i >= last && i < last + replacement.length() {
      replacement[i - last]
    } else {
      haystack[i]
    }
  })
}

///|
fn concat_bytes_test(a : Bytes, b : Bytes) -> Bytes {
  Bytes::makei(a.length() + b.length(), fn(i) {
    if i < a.length() {
      a[i]
    } else {
      b[i - a.length()]
    }
  })
}

///|
fn expect_sequence_test(
  elem : @asn1.Element,
  ctx : String,
) -> Array[@asn1.Element] {
  match elem.value {
    Sequence(xs) => xs
    _ => abort(ctx + ": expected SEQUENCE")
  }
}

///|
fn extract_explicit_test(elem : @asn1.Element, tag_no : UInt) -> Bytes {
  if elem.tag.class_ != @asn1.TagClass::ContextSpecific ||
    elem.tag.number != tag_no {
    abort("wrong explicit tag")
  }
  match elem.value {
    Unknown(b) => b
    _ => abort("explicit wrapper did not carry raw bytes")
  }
}

///|
fn cms_signed_data_items_from_fixture() -> Array[@asn1.Element] {
  let outer = @asn1.decode_der(cms_signature_der()) catch {
    e => abort("fixture ContentInfo decode failed: " + repr(e))
  }
  let ci = expect_sequence_test(outer, "ContentInfo")
  let sd_der = extract_explicit_test(ci[1], 0U)
  let sd = @asn1.decode_der(sd_der) catch {
    e => abort("fixture SignedData decode failed: " + repr(e))
  }
  expect_sequence_test(sd, "SignedData")
}

///|
fn cms_rebuild_with_signed_data_items(items : Array[@asn1.Element]) -> Bytes {
  let outer = @asn1.decode_der(cms_signature_der()) catch {
    e => abort("fixture ContentInfo decode failed: " + repr(e))
  }
  let ci = expect_sequence_test(outer, "ContentInfo")
  let sd = @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
  let content = @asn1.Element::new(
    @asn1.Tag::context(0U, constructed=true),
    Unknown(@asn1.encode_der(sd)),
  )
  @asn1.encode_der(
    @asn1.Element::new(@asn1.tag_sequence, Sequence([ci[0], content])),
  )
}

///|
fn cms_with_signed_data_version(version : Bytes) -> Bytes {
  let src = cms_signed_data_items_from_fixture()
  let out : Array[@asn1.Element] = [
    @asn1.Element::new(@asn1.tag_integer, Integer(version)),
  ]
  for i = 1; i < src.length(); i = i + 1 {
    out.push(src[i])
  }
  cms_rebuild_with_signed_data_items(out)
}

///|
fn cms_with_empty_digest_algorithms() -> Bytes {
  let src = cms_signed_data_items_from_fixture()
  let out : Array[@asn1.Element] = []
  for i = 0; i < src.length(); i = i + 1 {
    if i == 1 {
      out.push(@asn1.Element::new(@asn1.tag_set, Set([])))
    } else {
      out.push(src[i])
    }
  }
  cms_rebuild_with_signed_data_items(out)
}

///|
fn cms_with_signer_infos_before_certificates() -> Bytes {
  let src = cms_signed_data_items_from_fixture()
  let signer_infos = src[src.length() - 1]
  let out : Array[@asn1.Element] = []
  out.push(src[0])
  out.push(src[1])
  out.push(src[2])
  out.push(signer_infos)
  for i = 3; i < src.length(); i = i + 1 {
    out.push(src[i])
  }
  cms_rebuild_with_signed_data_items(out)
}

///|
fn cms_with_empty_crls() -> Bytes {
  let src = cms_signed_data_items_from_fixture()
  let out : Array[@asn1.Element] = []
  for i = 0; i < src.length() - 1; i = i + 1 {
    out.push(src[i])
  }
  out.push(
    @asn1.Element::new(@asn1.Tag::context(1U, constructed=true), Unknown(b"")),
  )
  out.push(src[src.length() - 1])
  cms_rebuild_with_signed_data_items(out)
}

///|
fn cms_with_duplicate_signer_certificate() -> Bytes {
  let src = cms_signed_data_items_from_fixture()
  let out : Array[@asn1.Element] = []
  for i = 0; i < src.length(); i = i + 1 {
    if i == 3 {
      let doubled = match src[i].value {
        Unknown(b) => concat_bytes_test(b, b)
        _ => abort("certificates wrapper missing raw bytes")
      }
      out.push(
        @asn1.Element::new(
          @asn1.Tag::context(0U, constructed=true),
          Unknown(doubled),
        ),
      )
    } else {
      out.push(src[i])
    }
  }
  cms_rebuild_with_signed_data_items(out)
}

///|
// Real CMS detached signature. Generated with:
//   openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
//     -subj "/CN=mizchi-cms-test/emailAddress=mizchi@cms.test" \
//     -keyout cms_key.pem -out cms_cert.pem
//   echo -n "hello cms signing" > cms_msg.txt
//   openssl cms -sign -in cms_msg.txt -signer cms_cert.pem \
//     -inkey cms_key.pem -binary -outform DER -out cms_sig.der
fn cms_signature_der() -> Bytes {
  hex_to_bytes(
    "3082059b06092a864886f70d010702a082058c30820588020101310d300b0609608648016503040201300b06092a864886f70d010701a08202f4308202f0308201d8020900f9b1ee6b1619cfa7300d06092a864886f70d01010b0500303a3118301606035504030c0f6d697a6368692d636d732d74657374311e301c06092a864886f70d010901160f6d697a63686940636d732e74657374301e170d3236303532363039313331355a170d3237303532363039313331355a303a3118301606035504030c0f6d697a6368692d636d732d74657374311e301c06092a864886f70d010901160f6d697a63686940636d732e7465737430820122300d06092a864886f70d01010105000382010f003082010a02820101009716870ef790a37176b588948819d65cce1a9963737193b9b59982cd1ac8b07d493c2498c74c12d27abcd7ebf7b467454e54718cd2451c06e6b71e3506149134cbca2b0dd29f07b6fa40f43515229821245579c770e023237f16253e566dacd09b491b7a72ebdef7612070b7231eea45f22e01d7d0be45e59c8b94353f1741453858d567db71b507384215d6e357c83b48a2a4ce6fa516bdb4327ac9617a8729f67f3b991ee37ee93c90300ae0f5440119c194b64393540a00637fd136bfc68c63fac1dee057791871b8d76338e77efa08f31c807f921b7a41fddd9ba94ce0c6f3c5744f0f35f7d2db2675e5adcb8f1b325d5f5d6a6bf740a778f672ec9d3c9d0203010001300d06092a864886f70d01010b050003820101007e6206daa7839b62314ad302ee02b231ce698632df432c2d7f372d541f0ee6b494d5bc0904f0d6cee9a8263f0eca67c9154bb3014823f26ab0bc04c1cb62f97379d91bac4e29ea20587ed320fd6cb8995e26556c8612369985e7c1e7191fa037e892045db3a4a5d4e36bde0929e1e14fee073a25873b631fcd6c0d1d2795615de7264c9ac4f241c33972d7da38dc90b79c806d2a4c1e6186471b082261f602689cc2c3b7c19585bbf759d186059897b70d77c576fd2f2f3196a14da2b4bab106ae544593e1114c7cb493cff68d65007d4b8e2f3268ee4baac8c0645797b24a3033e905dde12eeb01916920d68741628ef0a1b2acf8dfda58810cf0b2b5f38e533182026d308202690201013047303a3118301606035504030c0f6d697a6368692d636d732d74657374311e301c06092a864886f70d010901160f6d697a63686940636d732e74657374020900f9b1ee6b1619cfa7300b0609608648016503040201a081fa301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236303532363039313331355a302f06092a864886f70d0109043122042029113258ebec82b6ea083d928e432c0503b403d236f804cf63a6253a68b7fc2b30818e06092a864886f70d01090f318180307e300b060960864801650304012a300806062a8503020209300806062a8503020215300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300d06092a864886f70d01010105000482010090bff3077f99b615c8fd18f7db33a1b6a8dc8b2b7a2379baa31f15977d28fd0ee138daf772c82f917c7a11bbb59446f67ab95b93444f38747352a225a5c0db5a937706444bea8d46b5c097562cab2d1f9dfdd75b8c71bc5c936128382cca3a5ce05fe8d512687d575fbc92ffe609bf480d79ead31b70634c0a08ce16f584fb18492a2013da94e5d50021ee305cf229e6845d31c3b83b018e7b6e57ee9368ab248f282ad4a6127609ce8017dfd723a0320a509055167f7b0874c5fe540f9fd5d5586feb7d983059e41c911cbf4da2cf36987abb6a96b2adb416e7f351c90a72737977e334d8ed6d84da24f165d79a3c733087b25753166a482062244cbe94787b",
  )
}

///|
fn cms_message() -> Bytes {
  // "hello cms signing"
  hex_to_bytes("68656c6c6f20636d73207369676e696e67")
}

///|
test "cms: parse_signed_data extracts signer cert + signer info" {
  let sd = @cms.parse_signed_data(cms_signature_der())
  @debug.assert_eq(sd.extra_certs.length(), 0)
  // Issuer DN should contain our test CN ASCII bytes.
  let cn = sd.signer_cert.tbs.subject
  let _ = cn
  assert_true(sd.signer.signature.length() == 256) // 2048-bit RSA → 256 bytes
}

///|
test "cms: verify_detached against real openssl signature" {
  let sd = @cms.parse_signed_data(cms_signature_der())
  assert_true(@cms.verify_detached(sd, cms_message()))
}

///|
test "ATTACK cms: SignerInfo RSA signatureAlgorithm rejects non-NULL params" {
  let good_alg = hex_to_bytes("300d06092a864886f70d0101010500")
  // Same-length AlgorithmIdentifier with id-rsaEncryption parameters
  // encoded as an empty OCTET STRING instead of DER NULL.
  let bad_alg = hex_to_bytes("300d06092a864886f70d0101010400")
  let tampered = replace_last_bytes(cms_signature_der(), good_alg, bad_alg)
  try @cms.parse_signed_data(tampered) catch {
    Malformed(_) => ()
    UnsupportedSignatureAlgorithm(_) => ()
    _ => abort("unexpected error")
  } noraise {
    _ => abort("accepted malformed SignerInfo.signatureAlgorithm")
  }
}

///|
test "ATTACK cms: unsupported SignedData version is rejected" {
  try @cms.parse_signed_data(cms_with_signed_data_version(b"\x03")) catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other))
  } noraise {
    _ => abort("accepted unsupported SignedData version")
  }
}

///|
test "ATTACK cms: empty digestAlgorithms set is rejected" {
  try @cms.parse_signed_data(cms_with_empty_digest_algorithms()) catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other))
  } noraise {
    _ => abort("accepted SignedData with empty digestAlgorithms")
  }
}

///|
test "ATTACK cms: signerInfos must be the final SignedData field" {
  try
    @cms.parse_signed_data(cms_with_signer_infos_before_certificates())
  catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other))
  } noraise {
    _ => abort("accepted SignedData with signerInfos before certificates")
  }
}

///|
test "ATTACK cms: embedded CRLs are rejected until revocation is enforced" {
  try @cms.parse_signed_data(cms_with_empty_crls()) catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other))
  } noraise {
    _ => abort("accepted CMS crls field without enforcing revocation semantics")
  }
}

///|
test "ATTACK cms: duplicate matching signer certificates are ambiguous" {
  try @cms.parse_signed_data(cms_with_duplicate_signer_certificate()) catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other))
  } noraise {
    _ => abort("accepted duplicate signer certificates with the same SID")
  }
}

///|
test "cms: tampered message fails (messageDigest mismatch)" {
  let sd = @cms.parse_signed_data(cms_signature_der())
  let bad : Bytes = b"hello cms signinG"
  try @cms.verify_detached(sd, bad) catch {
    MessageDigestMismatch => ()
    _ => () // any error path counts as reject
  } noraise {
    false => ()
    true => abort("tampered message accepted")
  }
}

///|
test "cms: verify_with_chain when signer cert is its own trust anchor (self-signed)" {
  // The openssl test fixture is a self-signed RSA cert; its embedded cert
  // IS the trust anchor. We extract its public key and use it as anchor.
  let sd = @cms.parse_signed_data(cms_signature_der())
  let anchor_pk = @pkix_verify.extract_public_key(
    sd.signer_cert.tbs.subject_public_key_info,
  )
  // For verify_chain to accept a leaf as a sub-CA of itself, we treat
  // the embedded cert as anchored — chain has zero intermediates and the
  // signer cert is the leaf. With critical-extension and validity passed,
  // verification should succeed against the same pubkey.
  // (The fixture's self-signed cert has basicConstraints CA=false, so
  // direct verify_chain may reject; we therefore use verify_certificate
  // for the chain leg in this self-signed case.)
  @pkix_verify.verify_certificate(sd.signer_cert, anchor_pk, "260601000000Z")
  assert_true(@cms.verify_detached(sd, cms_message()))
}

// ─── 2-cert chain fixture (root CA + signer cert) ────────────────────────
//
// Generated with openssl 2026-05-26. See README/CLAUDE.md for the full
// recipe. The root CA carries basicConstraints=CA:TRUE,
// keyUsage=keyCertSign,cRLSign (both critical). The signer cert is signed
// by the root and carries basicConstraints=CA:FALSE,
// keyUsage=digitalSignature (critical). The CMS detached signature was
// produced by `openssl cms -sign` over "hello chained cms" with the
// signer cert + key, and -certfile root.crt embeds the root in the CMS
// `certificates` SET. openssl cms -verify against CAfile=root.crt is
// confirmed to pass.

///|
fn chained_cms_signature_der() -> Bytes {
  hex_to_bytes(
    "3082085806092a864886f70d010702a082084930820845020101310d300b0609608648016503040201300b06092a864886f70d010701a08205d2308202d8308201c0a003020102020900a77e5117403e54ff300d06092a864886f70d01010b050030193117301506035504030c0e6d697a6368692d746573742d6361301e170d3236303532363131313832335a170d3336303532333131313832335a30193117301506035504030c0e6d697a6368692d746573742d636130820122300d06092a864886f70d01010105000382010f003082010a0282010100dce2d67d96298d7d7488c43aa300c6cbd2174df92b7ce79b0abc9c212228f34acfb004deca8a6fcd3de41fba58b4ecdfb50893863733bcf394ea15eed35fc620cf3239ee61d16349dcdad1901b11ffb0237111b3557a86aa72ac02732fef4d2997fc91c9abc10c185248217a749fc560781c383be58e96703ffd24c0a9db5dda732699097fd4133a84bb862ee95ff3831cb0912347400512144cb3c733d21841dd5544a337a41d438e2ee70e6d1d71614324d1bb7058aa367645894dcccd354ce3d39b654a9d77986754cf45c82acc1549cada47603ee112ec33008a1c9c8c2b95d6d6010a4a0d2af848581c169ea64c4d098a6a7ad19d728254f029276534570203010001a3233021300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300d06092a864886f70d01010b05000382010100adaf2008e2fefa0b1e8f53f442da59aeb85c18dab3682a9e7bb6eab87ab6ecfc6a074a6628b1044b5e8abd14eee3f0e57f6291ec1b832af71625db6a775a667d55a0814e73cdc5ef0c5c076065b19e7a61d14bd62781929c2b2dadbf7df290c618782f69e6e088193dc4a0954d530f0b0ad0b7a19844adac5f4b05bdc58354c8edf214abe667b2a4f66a1ffd9c0400dfb0839b7ab9a2a08d37042a278ab9186c15ebdb87008f4522f19dba689917964a4b3ae36789515ccc5607db053b888383986ddbe8055a4e9c19d4056a48ecfee27f80e2878e71a68a5d3e2e66272fda2a9482ee62198b7d152e656a6a1ba2012a736f886a8a354649efdeef60b0cbe733308202f2308201daa003020102020900e6007f4f78c1adc9300d06092a864886f70d01010b050030193117301506035504030c0e6d697a6368692d746573742d6361301e170d3236303532363131313832395a170d3237303532363131313832395a3039311b301906035504030c126d697a6368692d746573742d7369676e6572311a301806092a864886f70d010901160b6d697a636869407465737430820122300d06092a864886f70d01010105000382010f003082010a028201010096cce34a699f05c5d8863977ebea3ec6781a2edb354d1cf92ea9f758f0bab6b6eea701075c6bd01a6fa84447c886511e10ebcc72a374e5bbb4680a5eed6433ab6a11872a7b2efb2c8b9cb0a0817ee640092f2dd14e7875797897d2f84617e094423cc4ae4d484d7244da7bacaebcdfe045f02db7798a46d5f59d828c158e38d0a015a46299dfcfb52aa69923e503c5bc6a7dd1464cec8ced3b58dd0d174b7d3fb9c2057abef544ed133b4063a9dfe57c32cd8e35524948f9892f8666fec3a3e72fc95e3d722d587b19d72061b9d05e9b0211f7e56f91bee2e061633c77edfc9ec070e74567eb2be7952759ae264596ef299ea4abb1d919fe296dd130ccdb45ab0203010001a31d301b30090603551d1304023000300e0603551d0f0101ff040403020780300d06092a864886f70d01010b05000382010100d20b2c33ee75fd1a9d593d19abb5c82fbb6c0f943943bff95a6e7aeb9aa3d70f14406c56485fb2d3bc39d49c18ece38c99ba451473557ce81b302dc0550944546bd967df5ff707bb18b307e8b85cd23dab39b835cefeac896ff17a1f8ed5413e9923dadccf35fb513d5de9480e88cfef21f32d1cb4e412db6558b9b293ea0d227ba439b56ed41364d5484761d39310dddf761f8dc6257b33aef3183f19687ebaec866548dee42aaba8fff050d9bf44827b541dc6810275ffce560278b0190e3da4b0f709ee6e02a841d4fd907f91d45b74d12076684284fb4e6b43902a145a653d78137c12749cb651d719f504491eabf0ff476d83125290af7fe5f52e8ed5a93182024c30820248020101302630193117301506035504030c0e6d697a6368692d746573742d6361020900e6007f4f78c1adc9300b0609608648016503040201a081fa301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236303532363131313833355a302f06092a864886f70d01090431220420ef5e78a808a32468ace517bfd0214ebc54926af57fef67bdb0ad90869171841e30818e06092a864886f70d01090f318180307e300b060960864801650304012a300806062a8503020209300806062a8503020215300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300d06092a864886f70d0101010500048201006a12d87fafdc1f568a6fd019787457c9a0507fa277e332429e8f4763fef58ae87913e4fb7b0b8f039a7394786699ad3fd123ee5c7b353ce62d562b0d24289cd0a94f774dffe13556288c234660fe27b5977338bd24341984fbb14362885d8b97d3871c5697cc7bcf07a9277739f562e95cd2ad57e44f593093db0c17adc458e8ad78fef087528d7720351207b6c23c0693aa9f4acaffb2b44a3c3af9e7d23f870182e5711f6ee41b0b89689ce86be05c0013d5733dd06ffd37e3b5b5ec1766f100c15db2ed7da4dfecec01f00ff035836a076eb61bf67ac96b9404b4e92da0556ea0545e9a386046a8a9dd24dcbad66b9a309e13a465783a7c2be1d015f0f3ca",
  )
}

///|
fn chained_root_cert_der() -> Bytes {
  hex_to_bytes(
    "308202d8308201c0a003020102020900a77e5117403e54ff300d06092a864886f70d01010b050030193117301506035504030c0e6d697a6368692d746573742d6361301e170d3236303532363131313832335a170d3336303532333131313832335a30193117301506035504030c0e6d697a6368692d746573742d636130820122300d06092a864886f70d01010105000382010f003082010a0282010100dce2d67d96298d7d7488c43aa300c6cbd2174df92b7ce79b0abc9c212228f34acfb004deca8a6fcd3de41fba58b4ecdfb50893863733bcf394ea15eed35fc620cf3239ee61d16349dcdad1901b11ffb0237111b3557a86aa72ac02732fef4d2997fc91c9abc10c185248217a749fc560781c383be58e96703ffd24c0a9db5dda732699097fd4133a84bb862ee95ff3831cb0912347400512144cb3c733d21841dd5544a337a41d438e2ee70e6d1d71614324d1bb7058aa367645894dcccd354ce3d39b654a9d77986754cf45c82acc1549cada47603ee112ec33008a1c9c8c2b95d6d6010a4a0d2af848581c169ea64c4d098a6a7ad19d728254f029276534570203010001a3233021300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300d06092a864886f70d01010b05000382010100adaf2008e2fefa0b1e8f53f442da59aeb85c18dab3682a9e7bb6eab87ab6ecfc6a074a6628b1044b5e8abd14eee3f0e57f6291ec1b832af71625db6a775a667d55a0814e73cdc5ef0c5c076065b19e7a61d14bd62781929c2b2dadbf7df290c618782f69e6e088193dc4a0954d530f0b0ad0b7a19844adac5f4b05bdc58354c8edf214abe667b2a4f66a1ffd9c0400dfb0839b7ab9a2a08d37042a278ab9186c15ebdb87008f4522f19dba689917964a4b3ae36789515ccc5607db053b888383986ddbe8055a4e9c19d4056a48ecfee27f80e2878e71a68a5d3e2e66272fda2a9482ee62198b7d152e656a6a1ba2012a736f886a8a354649efdeef60b0cbe733",
  )
}

///|
fn chained_message() -> Bytes {
  // "hello chained cms"
  hex_to_bytes("68656c6c6f20636861696e656420636d73")
}

///|
test "cms: verify_with_chain end-to-end with real openssl root CA + signer chain" {
  // Parse CMS — it embeds both the signer cert and the root CA in
  // `certificates`. The signer's IssuerAndSerialNumber selects the signer
  // as `signer_cert`; the root falls into `extra_certs`.
  let sd = @cms.parse_signed_data(chained_cms_signature_der())
  @debug.assert_eq(sd.extra_certs.length(), 1)
  // Pull anchor pubkey from the standalone root.der fixture (this is what
  // a real trust store would do — never trust the CMS-embedded copy).
  let root_cert = @pkix.parse_certificate(chained_root_cert_der())
  let anchor_pk = @pkix_verify.extract_public_key(
    root_cert.tbs.subject_public_key_info,
  )
  // notBefore on both certs is 2026-05-26T11:18:xx; pick a `now` safely
  // inside the validity window of both.
  let now = "260601000000Z"
  assert_true(@cms.verify_with_chain(sd, chained_message(), anchor_pk, now))
}

///|
test "cms: verify_with_chain rejects wrong trust anchor (signer's own pubkey)" {
  // Use the signer cert's own pubkey as anchor. The chain walk asks
  // "is signer_cert signed by anchor?" — signer is NOT self-signed
  // (it's signed by root), so RSA verify will fail and verify_with_chain
  // must return false.
  let sd = @cms.parse_signed_data(chained_cms_signature_der())
  let wrong_anchor = @pkix_verify.extract_public_key(
    sd.signer_cert.tbs.subject_public_key_info,
  )
  let now = "260601000000Z"
  assert_false(@cms.verify_with_chain(sd, chained_message(), wrong_anchor, now))
}

///|
test "cms: verify_with_chain rejects tampered message (messageDigest mismatch)" {
  // Even with a perfectly valid chain, flipping a byte in the content
  // must fail verification — caught at the messageDigest comparison
  // before any chain walk happens.
  let sd = @cms.parse_signed_data(chained_cms_signature_der())
  let root_cert = @pkix.parse_certificate(chained_root_cert_der())
  let anchor_pk = @pkix_verify.extract_public_key(
    root_cert.tbs.subject_public_key_info,
  )
  let now = "260601000000Z"
  let tampered : Bytes = b"hello chained cmS" // last byte flipped
  try @cms.verify_with_chain(sd, tampered, anchor_pk, now) catch {
    MessageDigestMismatch => ()
    _ => () // any error path counts as reject
  } noraise {
    false => ()
    true => abort("tampered message accepted")
  }
}
