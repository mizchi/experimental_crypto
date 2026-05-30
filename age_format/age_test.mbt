// age conformance against the C2SP/CCTV age test vectors (non-armored,
// non-compressed X25519 cases) plus encrypt/decrypt round-trips.

///|
fn ax_hexval(c : Char) -> Int {
  let n = c.to_int()
  if n >= '0'.to_int() && n <= '9'.to_int() {
    n - '0'.to_int()
  } else if n >= 'a'.to_int() && n <= 'f'.to_int() {
    n - 'a'.to_int() + 10
  } else {
    abort("bad hex")
  }
}

///|
fn ax_hex(s : String) -> Bytes {
  Bytes::makei(s.length() / 2, fn(i) {
    (ax_hexval(s.get_char(2 * i).unwrap()) * 16 +
    ax_hexval(s.get_char(2 * i + 1).unwrap())).to_byte()
  })
}

///|
let id_main : String = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0"

///|
let id_other : String = "AGE-SECRET-KEY-143WN7DCXU4G8R5AXQSSYD9AEPYDNT3HXSLWSPK36CDU6E8M59SSSAGZ3KG"

///|
let v_x25519 : String = "6167652d656e6372797074696f6e2e6f72672f76310a2d3e20583235353139205445694630797071722b6270766371584e7943564a704c374f757750645677504c374b51456246444f43630a686a6162475877534c5139633353364c7732692b5332547532666977514848736c62424e36423431464c450a2d2d2d2057794a7039462f39464f5a6837674a646865713257494a637748675963384e495668336464776872634e670aeecf62c7ce91b433274e68d4f2f9134cb74c5bfef7beaa52c8f0bc0e992c1e8331fb66"

///|
let v_no_match : String = "6167652d656e6372797074696f6e2e6f72672f76310a2d3e2058323535313920616a7471417644456b564e723242377a554f7471326d4151584453426c4e725641754d2f644b62357354340a48554b747a3052326a35426c324552374868415a725552696b43467069496a4e61304b6a48636a624147550a2d2d2d20727270546c764b454b724b334571686f4f504a6550314b45384f31643261727252657a37376d77656b52630adddf72d06fbcab57df3d0d312496ad218cd7fd6f8078bbf8812dd87947155eb7bd5e88"

///|
let v_bad_tag : String = "6167652d656e6372797074696f6e2e6f72672f76310a2d3e20583235353139205445694630797071722b6270766371584e7943564a704c374f757750645677504c374b51456246444f43630a686a6162475877534c5139633353364c7732692b5332547532666977514848736c62424e364234314645340a2d2d2d207a4f434870796e563061563770345236632b624f6170677071395474704667476759676851322b504958380aeecf62c7ce91b433274e68d4f2f9134cb74c5bfef7beaa52c8f0bc0e992c1e8331fb66"

///|
let v_hmac_bad : String = "6167652d656e6372797074696f6e2e6f72672f76310a2d3e20583235353139205445694630797071722b6270766371584e7943564a704c374f757750645677504c374b51456246444f43630a686a6162475877534c5139633353364c7732692b5332547532666977514848736c62424e36423431464c450a2d2d2d20384d634533697839523334452f764c7251763379657073486a6f2f4c5868667332324162335579496e6d670aeecf62c7ce91b433274e68d4f2f9134cb74c5bfef7beaa52c8f0bc0e992c1e8331fb66"

///|
let v_low_order : String = "6167652d656e6372797074696f6e2e6f72672f76310a2d3e205832353531392058357956764b4e516a435378304c46566e49507657775245584d52594849364732434a4f336443664564630a3345304e7046616e732f6d30574c5746372b35345a42644e6a33697151717072614744466961526b7642410a2d2d2d20735877333237594d54312f554c58652b5a79524d624d59305a326a6e5748476749396a31776536795138410aac5d3f3706e55071d3a604204697b9090595c2f7f5dbaee80d7a018c2872058af3ce7c"

///|
let v_extra_arg : String = "6167652d656e6372797074696f6e2e6f72672f76310a2d3e20583235353139205445694630797071722b6270766371584e7943564a704c374f757750645677504c374b51456246444f436320313233340a686a6162475877534c5139633353364c7732692b5332547532666977514848736c62424e36423431464c450a2d2d2d206c3745302f505150353448425a594b55753530356e316d755737456e694446714d7258674d68466d6569410aeecf62c7ce91b433274e68d4f2f9134cb74c5bfef7beaa52c8f0bc0e992c1e8331fb66"

///|
let v_short_share : String = "6167652d656e6372797074696f6e2e6f72672f76310a2d3e20583235353139206c376f346f545839583545332f4b4f44612f3743513043724139664b4d57736d39494a6a597a536c4a670a795547503561506f6236594a2b767a5266427444543944314b2f776d7968655a452f586c2f6d44534b41340a2d2d2d205a6e312f565274487044393348744958537631532b2b504f58654b6351463777312b687058684d6941626b0aac5d3f3706e55071d3a604204697b9090595c2f7f5dbaee80d7a018c2872058af3ce7c"

///|
let v_stream_bad_tag : String = "6167652d656e6372797074696f6e2e6f72672f76310a2d3e20583235353139205445694630797071722b6270766371584e7943564a704c374f757750645677504c374b51456246444f43630a686a6162475877534c5139633353364c7732692b5332547532666977514848736c62424e36423431464c450a2d2d2d2057794a7039462f39464f5a6837674a646865713257494a637748675963384e495668336464776872634e670aeecf62c7ce91b433274e68d4f2f9134cb74c5bfef7beaa52c8f0bc0e992c1e8331fb46"

///|
let v_multi : String = "6167652d656e6372797074696f6e2e6f72672f76310a2d3e2058323535313920616a7471417644456b564e723242377a554f7471326d4151584453426c4e725641754d2f644b62357354340a306576724b2f48515856735134596144652b3635396c354f517a76417a443279744c4748514c51697178670a2d3e205832353531392030714337753641624c7875776e4d387450464f575674575a6e2f5a5a65377a3767637350356b67413046490a59334f7a65764c6d3233567837504e396b33334639792b65726357652f62635a4a4c7168714133683430380a2d2d2d20383535704b626c517a5a336f6162446f777852445176536a2f786f34375a53683557546a6b6d4b304930550af0b818be0f355442399920ad8084964b6f95c36db35e4f59d8f89e3cf26f2d1fa54213"

///|
test "CCTV x25519: success decrypts to the expected payload" {
  let id = @age_format.X25519Identity::from_bech32(id_main)
  let pt = @age_format.decrypt([id], ax_hex(v_x25519))
  @debug.assert_eq(
    @hash.sha256(pt),
    ax_hex("013f54400c82da08037759ada907a8b864e97de81c088a182062c4b5622fd2ab"),
  )
}

///|
test "CCTV x25519_multiple_recipients: matches the first stanza" {
  let id = @age_format.X25519Identity::from_bech32(id_main)
  let pt = @age_format.decrypt([id], ax_hex(v_multi))
  @debug.assert_eq(
    @hash.sha256(pt),
    ax_hex("013f54400c82da08037759ada907a8b864e97de81c088a182062c4b5622fd2ab"),
  )
}

///|
test "CCTV failure classes are reported correctly" {
  let id = @age_format.X25519Identity::from_bech32(id_main)
  let other = @age_format.X25519Identity::from_bech32(id_other)
  let expect_no_match = fn(
    v : String,
    who : @age_format.X25519Identity,
    what : String,
  ) {
    try @age_format.decrypt([who], ax_hex(v)) |> ignore catch {
      NoMatch => ()
      e => abort(what + ": expected NoMatch, got " + repr(e))
    } noraise {
      _ => abort(what + ": expected NoMatch but decrypted")
    }
  }
  expect_no_match(v_no_match, other, "x25519_no_match")
  expect_no_match(v_bad_tag, id, "x25519_bad_tag")
  try @age_format.decrypt([id], ax_hex(v_hmac_bad)) |> ignore catch {
    HmacFailure => ()
    e => abort("hmac_bad: expected HmacFailure, got " + repr(e))
  } noraise {
    _ => abort("hmac_bad decrypted")
  }
  let expect_header = fn(v : String, what : String) {
    try @age_format.decrypt([id], ax_hex(v)) |> ignore catch {
      HeaderFailure(_) => ()
      e => abort(what + ": expected HeaderFailure, got " + repr(e))
    } noraise {
      _ => abort(what + ": expected HeaderFailure but decrypted")
    }
  }
  expect_header(v_low_order, "x25519_low_order")
  expect_header(v_extra_arg, "x25519_extra_argument")
  expect_header(v_short_share, "x25519_short_share")
  try @age_format.decrypt([id], ax_hex(v_stream_bad_tag)) |> ignore catch {
    PayloadFailure(_) => ()
    e => abort("stream_bad_tag: expected PayloadFailure, got " + repr(e))
  } noraise {
    _ => abort("stream_bad_tag decrypted")
  }
}

///|
test "encrypt/decrypt round-trip (single chunk, multi-chunk, empty)" {
  let id = @age_format.X25519Identity::from_bech32(id_main)
  let recipient = id.public_key_bytes()
  let file_key = Bytes::makei(16, fn(i) { (i + 1).to_byte() })
  let eph = Bytes::makei(32, fn(i) { (0x40 + i).to_byte() })
  let nonce = Bytes::makei(16, fn(i) { (0x90 + i).to_byte() })
  let small = b"the quick brown fox"
  @debug.assert_eq(
    @age_format.decrypt(
      [id],
      @age_format.encrypt_x25519(recipient, small, file_key, eph, nonce),
    ),
    small,
  )
  let big_len = 65536 * 2 + 123
  let big = Bytes::makei(big_len, fn(i) { ((i * 31 + 7) & 0xff).to_byte() })
  @debug.assert_eq(
    @age_format.decrypt(
      [id],
      @age_format.encrypt_x25519(recipient, big, file_key, eph, nonce),
    ),
    big,
  )
  @debug.assert_eq(
    @age_format.decrypt(
      [id],
      @age_format.encrypt_x25519(recipient, b"", file_key, eph, nonce),
    ),
    b"",
  )
}

///|
test "bech32 rejects a corrupted identity checksum" {
  // Flip one character of a valid identity -> checksum / format failure.
  let bad = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM1"
  try @age_format.X25519Identity::from_bech32(bad) |> ignore catch {
    KeyError(_) => ()
    e => abort("expected KeyError, got " + repr(e))
  } noraise {
    _ => abort("accepted a corrupted bech32 identity")
  }
}
