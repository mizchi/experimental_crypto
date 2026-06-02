// SHA-3 / SHAKE known-answer tests (NIST FIPS 202, via Python hashlib).

///|
fn s3hex(b : Bytes) -> String {
  let d = "0123456789abcdef"
  let sb = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    sb.write_char(d.get_char(v >> 4).unwrap())
    sb.write_char(d.get_char(v & 0xf).unwrap())
  }
  sb.to_string()
}

///|
fn rep(byte : Int, n : Int) -> Bytes {
  Bytes::makei(n, fn(_i) { (byte & 0xff).to_byte() })
}

///|
test "SHA3-256 KAT" {
  inspect(
    s3hex(@sha3.sha3_256(b"")),
    content="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
  )
  inspect(
    s3hex(@sha3.sha3_256(b"abc")),
    content="3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
  )
  // 200-byte input crosses the 136-byte rate boundary (two absorb blocks).
  inspect(
    s3hex(@sha3.sha3_256(rep(0xa3, 200))),
    content="79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787",
  )
}

///|
test "SHA3-512 KAT" {
  inspect(
    s3hex(@sha3.sha3_512(b"")),
    content="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
  )
  inspect(
    s3hex(@sha3.sha3_512(b"abc")),
    content="b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
  )
}

///|
test "SHAKE128 / SHAKE256 KAT" {
  inspect(
    s3hex(@sha3.shake128(b"", 32)),
    content="7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
  )
  inspect(
    s3hex(@sha3.shake256(b"", 32)),
    content="46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
  )
  inspect(
    s3hex(@sha3.shake128(b"abc", 64)),
    content="5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378",
  )
  inspect(
    s3hex(@sha3.shake256(b"abc", 64)),
    content="483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
  )
}

///|
test "SHAKE256 200-byte output crosses the squeeze-rate boundary (>136)" {
  inspect(
    s3hex(@sha3.shake256(b"", 200)),
    content="46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d677231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5caaae314ed9083dab",
  )
}

///|
test "SHAKE128 long output crossing the squeeze-rate boundary" {
  // 64 bytes < 168-byte rate, but 200-byte input crosses absorb boundary.
  inspect(
    s3hex(@sha3.shake128(rep(0xa3, 200), 64)),
    content="131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037cf232ef7164a6d1eb448c8908186ad852d3f85a5cf28da1ab6fe343817197846",
  )
}
