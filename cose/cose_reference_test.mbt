// Reference vectors from RFC 9052 Appendix C for supported COSE algorithms.

///|
fn ref_cose_hex(s : String) -> Bytes {
  let clean : Array[Char] = []
  for c in s {
    if c != ' ' && c != '\n' {
      clean.push(c)
    }
  }
  let n = clean.length() / 2
  Bytes::makei(n, fn(i) {
    let hi = ref_cose_hex_nibble(clean[i * 2])
    let lo = ref_cose_hex_nibble(clean[i * 2 + 1])
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn ref_cose_hex_nibble(c : Char) -> Int {
  let code = c.to_int()
  if code >= '0'.to_int() && code <= '9'.to_int() {
    code - '0'.to_int()
  } else if code >= 'a'.to_int() && code <= 'f'.to_int() {
    code - 'a'.to_int() + 10
  } else if code >= 'A'.to_int() && code <= 'F'.to_int() {
    code - 'A'.to_int() + 10
  } else {
    abort("bad hex")
  }
}

///|
test "RFC 9052 C.2.1: COSE_Sign1 ES256 example verifies" {
  let x = ref_cose_hex(
    "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff",
  )
  let y = ref_cose_hex(
    "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e",
  )
  let pk = @p256.PublicKey::from_uncompressed(
    Bytes::makei(65, fn(i) {
      if i == 0 {
        b'\x04'
      } else if i <= 32 {
        x[i - 1]
      } else {
        y[i - 33]
      }
    }),
  )
  let payload = b"This is the content."
  let protected_bytes = ref_cose_hex("a10126") // { 1: -7 } == ES256.
  let signature = ref_cose_hex(
    "8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e" +
    "2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36",
  )
  let cose_sign1 = @cbor.encode(
    Tag(
      18UL,
      Array([
        Bytes(protected_bytes),
        Map([(Uint(4UL), Bytes(b"11"))]),
        Bytes(payload),
        Bytes(signature),
      ]),
    ),
  )
  let key : @cose.CoseKey = Ec2P256(pubkey=pk)
  assert_true(@cose.verify_sign1(cose_sign1, payload, key))
}
