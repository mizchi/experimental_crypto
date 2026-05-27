// Fuzz-style blackbox tests for HPKE Mode_Base. These keep attacker-controlled
// message material, AAD, info, and ephemeral key bytes moving through the full
// setup/seal/open path while pinning the recipient key to a known-valid RFC
// 9180 vector.

///|
let fuzz_sk_r : Bytes = b"\x80\x57\x99\x1e\xef\x8f\x1f\x1a\xf1\x8f\x4a\x94\x91\xd1\x6a\x1c\xe3\x33\xf6\x95\xd4\xdb\x8e\x38\xda\x75\x97\x5c\x44\x78\xe0\xfb"

///|
let fuzz_pk_r : Bytes = b"\x43\x10\xee\x97\xd8\x8c\xc1\xf0\x88\xa5\x57\x6c\x77\xab\x0c\xf5\xc3\xac\x79\x7f\x3d\x95\x13\x9c\x6c\x84\xb5\x42\x9c\x59\x66\x2a"

///|
fn hpke_ensure_length(b : Bytes, target : Int) -> Bytes {
  if b.length() == target {
    b
  } else if b.length() == 0 {
    Bytes::makei(target, fn(i) { (i + 1).to_byte() })
  } else if b.length() > target {
    Bytes::makei(target, fn(i) { b[i] })
  } else {
    let n = b.length()
    Bytes::makei(target, fn(i) { b[i % n] })
  }
}

///|
fn hpke_flip_first(b : Bytes) -> Bytes {
  Bytes::makei(b.length(), fn(i) {
    if i == 0 {
      (b[i].to_int() ^ 0x01).to_byte()
    } else {
      b[i]
    }
  })
}

///|
test "fuzz hpke: setup/seal/open roundtrip over arbitrary inputs" {
  let n = 50
  let infos : Array[Bytes] = @quickcheck.samples(n)
  let aads : Array[Bytes] = @quickcheck.samples(n)
  let pts : Array[Bytes] = @quickcheck.samples(n)
  let ephemerals : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let sk_e = hpke_ensure_length(ephemerals[i], 32)
    let (enc, ctx_s) = @hpke.setup_base_s(fuzz_pk_r, infos[i], sk_e~)
    let ctx_r = @hpke.setup_base_r(enc, fuzz_sk_r, infos[i])
    let ct = ctx_s.seal(aads[i], pts[i])
    let opened = ctx_r.open(aads[i], ct)
    @debug.assert_eq(opened, pts[i])
  }
}

///|
test "fuzz hpke: wrong info or tampered ciphertext rejects" {
  let n = 50
  let infos : Array[Bytes] = @quickcheck.samples(n)
  let aads : Array[Bytes] = @quickcheck.samples(n)
  let pts : Array[Bytes] = @quickcheck.samples(n)
  let ephemerals : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let sk_e = hpke_ensure_length(ephemerals[i], 32)
    let (enc, ctx_s) = @hpke.setup_base_s(fuzz_pk_r, infos[i], sk_e~)
    let ct = ctx_s.seal(aads[i], pts[i])
    let wrong_info = if infos[i] == b"" { b"\x00" } else { b"" }
    try @hpke.setup_base_r(enc, fuzz_sk_r, wrong_info).open(aads[i], ct) catch {
      AeadFailure => ()
      e => abort("expected AeadFailure for wrong info, got " + repr(e))
    } noraise {
      _ => abort("open with wrong HPKE info must reject")
    }
    let ctx_r = @hpke.setup_base_r(enc, fuzz_sk_r, infos[i])
    let tampered = hpke_flip_first(ct)
    try ctx_r.open(aads[i], tampered) catch {
      AeadFailure => ()
      e => abort("expected AeadFailure for tampered ciphertext, got " + repr(e))
    } noraise {
      _ => abort("open with tampered HPKE ciphertext must reject")
    }
  }
}
