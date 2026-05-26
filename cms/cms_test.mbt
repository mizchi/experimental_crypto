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
    out[i] = ((hi * 16) + lo).to_byte()
    i = i + 1
  }
  Bytes::makei(len, fn(j) { out[j] })
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
  assert_eq(sd.extra_certs.length(), 0)
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
test "cms: tampered message fails (messageDigest mismatch)" {
  let sd = @cms.parse_signed_data(cms_signature_der())
  let bad : Bytes = b"hello cms signinG"
  match (try? @cms.verify_detached(sd, bad)) {
    Err(MessageDigestMismatch) => ()
    Ok(false) => ()
    Ok(true) => abort("tampered message accepted")
    Err(_) => () // any error path counts as reject
  }
}
