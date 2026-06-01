// AES-KW known-answer tests, RFC 3394 §4 (cross-checked against Node's
// id-aesNNN-wrap).

///|
fn kw_hex(s : String) -> Bytes {
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
  for i = 0; i < len; i = i + 1 {
    out[i] = ((nib(s.get_char(i * 2).unwrap()) << 4) |
    nib(s.get_char(i * 2 + 1).unwrap())).to_byte()
  }
  Bytes::makei(len, fn(j) { out[j] })
}

///|
fn kw_to_hex(b : Bytes) -> String {
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
test "AES-KW RFC 3394 §4.1: 128-bit KEK / 128-bit key" {
  let kek = kw_hex("000102030405060708090a0b0c0d0e0f")
  let key = kw_hex("00112233445566778899aabbccddeeff")
  let w = @aeskw.wrap(kek, key)
  inspect(
    kw_to_hex(w),
    content="1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5",
  )
  inspect(kw_to_hex(@aeskw.unwrap(kek, w)), content=kw_to_hex(key))
}

///|
test "AES-KW RFC 3394 §4.2: 192-bit KEK / 128-bit key" {
  let kek = kw_hex("000102030405060708090a0b0c0d0e0f1011121314151617")
  let key = kw_hex("00112233445566778899aabbccddeeff")
  let w = @aeskw.wrap(kek, key)
  inspect(
    kw_to_hex(w),
    content="96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d",
  )
  inspect(kw_to_hex(@aeskw.unwrap(kek, w)), content=kw_to_hex(key))
}

///|
test "AES-KW RFC 3394 §4.6: 256-bit KEK / 256-bit key" {
  let kek = kw_hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let key = kw_hex(
    "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f",
  )
  let w = @aeskw.wrap(kek, key)
  inspect(
    kw_to_hex(w),
    content="28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21",
  )
  inspect(kw_to_hex(@aeskw.unwrap(kek, w)), content=kw_to_hex(key))
}

///|
test "AES-KW unwrap rejects a tampered blob" {
  let kek = kw_hex("000102030405060708090a0b0c0d0e0f")
  let w = kw_hex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe4") // last nibble flipped
  let mut rejected = false
  let _ = @aeskw.unwrap(kek, w) catch {
    _ => {
      rejected = true
      b""
    }
  }
  inspect(rejected, content="true")
}

///|
test "AES-KW rejects a bad KEK size" {
  let mut rejected = false
  let _ = @aeskw.wrap(
    kw_hex("0011223344556677"),
    kw_hex("00112233445566778899aabbccddeeff"),
  ) catch {
    _ => {
      rejected = true
      b""
    }
  }
  inspect(rejected, content="true")
}
