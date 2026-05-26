// RFC 9180 §A.1.1 test vector for
//   DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305, Mode_Base.
//
// Source: https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json
// (the matching record for {mode:0, kem_id:0x20, kdf_id:0x01, aead_id:0x03}).
//
// We pass `skEm` directly to setup_base_s rather than running DeriveKeyPair
// from `ikmE`. DeriveKeyPair is itself a LabeledExtract + clamp; verifying
// every other downstream byte (key / base_nonce / enc / exporter_secret /
// ciphertexts) against the published values transitively proves the
// LabeledExtract/Expand wiring even though we skip the derivation step.

///|
let test_info : Bytes = b"\x4f\x64\x65\x20\x6f\x6e\x20\x61\x20\x47\x72\x65\x63\x69\x61\x6e\x20\x55\x72\x6e"

///|
let test_sk_e : Bytes = b"\xf4\xec\x9b\x33\xb7\x92\xc3\x72\xc1\xd2\xc2\x06\x35\x07\xb6\x84\xef\x92\x5b\x8c\x75\xa4\x2d\xbc\xbf\x57\xd6\x3c\xcd\x38\x16\x00"

///|
let test_sk_r : Bytes = b"\x80\x57\x99\x1e\xef\x8f\x1f\x1a\xf1\x8f\x4a\x94\x91\xd1\x6a\x1c\xe3\x33\xf6\x95\xd4\xdb\x8e\x38\xda\x75\x97\x5c\x44\x78\xe0\xfb"

///|
let test_pk_r : Bytes = b"\x43\x10\xee\x97\xd8\x8c\xc1\xf0\x88\xa5\x57\x6c\x77\xab\x0c\xf5\xc3\xac\x79\x7f\x3d\x95\x13\x9c\x6c\x84\xb5\x42\x9c\x59\x66\x2a"

///|
let test_enc : Bytes = b"\x1a\xfa\x08\xd3\xde\xc0\x47\xa6\x43\x88\x51\x63\xf1\x18\x04\x76\xfa\x7d\xdb\x54\xc6\xa8\x02\x9e\xa3\x3f\x95\x79\x6b\xf2\xac\x4a"

///|
let test_key : Bytes = b"\xad\x27\x44\xde\x8e\x17\xf4\xeb\xba\x57\x5b\x3f\x5f\x5a\x8f\xa1\xf6\x9c\x2a\x07\xf6\xe7\x50\x0b\xc6\x0c\xa6\xe3\xe3\xec\x1c\x91"

///|
let test_base_nonce : Bytes = b"\x5c\x4d\x98\x15\x06\x61\xb8\x48\x85\x3b\x54\x7f"

///|
let test_exporter_secret : Bytes = b"\xa3\xb0\x10\xd4\x99\x48\x90\xe2\xc6\x96\x8a\x36\xf6\x44\x70\xd3\xc8\x24\xc8\xf5\x02\x99\x42\xfe\xb1\x1e\x7a\x74\xb2\x92\x19\x22"

// ─── Sealed ciphertexts ────────────────────────────────────────────────────

///|
let test_pt : Bytes = b"\x42\x65\x61\x75\x74\x79\x20\x69\x73\x20\x74\x72\x75\x74\x68\x2c\x20\x74\x72\x75\x74\x68\x20\x62\x65\x61\x75\x74\x79"

///|
let test_aad0 : Bytes = b"\x43\x6f\x75\x6e\x74\x2d\x30" // "Count-0"

///|
let test_ct0 : Bytes = b"\x1c\x52\x50\xd8\x03\x4e\xc2\xb7\x84\xba\x2c\xfd\x69\xdb\xdb\x8a\xf4\x06\xcf\xe3\xff\x93\x8e\x13\x1f\x0d\xef\x8c\x8b\x60\xb4\xdb\x21\x99\x3c\x62\xce\x81\x88\x3d\x2d\xd1\xb5\x1a\x28"

///|
let test_aad1 : Bytes = b"\x43\x6f\x75\x6e\x74\x2d\x31"

///|
let test_ct1 : Bytes = b"\x6b\x53\xc0\x51\xe4\x19\x9c\x51\x8d\xe7\x95\x94\xe1\xc4\xab\x18\xb9\x6f\x08\x15\x49\xd4\x5c\xe0\x15\xbe\x00\x20\x90\xbb\x11\x9e\x85\x28\x53\x37\xcc\x95\xba\x5f\x59\x99\x2d\xc9\x8c"

///|
let test_aad2 : Bytes = b"\x43\x6f\x75\x6e\x74\x2d\x32"

///|
let test_ct2 : Bytes = b"\x71\x14\x6b\xd6\x79\x5c\xcc\x9c\x49\xce\x25\xdd\xa1\x12\xa4\x8f\x20\x2a\xd2\x20\x55\x95\x02\xce\xf1\xf3\x42\x71\xe0\xcb\x4b\x02\xb4\xf1\x0e\xca\xc6\xf4\x8c\x32\xf8\x78\xfa\xe8\x6b"

// ─── Export vectors ────────────────────────────────────────────────────────

///|
let test_export_empty : Bytes = b"\x4b\xbd\x62\x43\xb8\xbb\x54\xce\xc3\x11\xfa\xc9\xdf\x81\x84\x1b\x6f\xd6\x1f\x56\x53\x8a\x77\x5e\x7c\x80\xa9\xf4\x01\x60\x60\x6e"

///|
let test_export_00 : Bytes = b"\x8c\x1d\xf1\x47\x32\x58\x0e\x55\x01\xb0\x0f\x82\xb1\x0a\x16\x47\xb4\x07\x13\x19\x1b\x7c\x12\x40\xac\x80\xe2\xb6\x88\x08\xba\x69"

///|
let test_export_ctx_testcontext : Bytes = b"\x54\x65\x73\x74\x43\x6f\x6e\x74\x65\x78\x74" // "TestContext"

///|
let test_export_testcontext : Bytes = b"\x5a\xcb\x09\x21\x11\x39\xc4\x3b\x30\x90\x48\x9a\x9d\xa4\x33\xe8\xa3\x0e\xe7\x18\x8b\xa8\xb0\xa9\xa1\xcc\xf0\xc2\x29\x28\x3e\x53"

// ─── White-box: KDF derivation against RFC 9180 §A.1.1 ─────────────────────

///|
test "hpke: RFC 9180 A.1.1 — setup_base_s derives key/base_nonce/enc/exporter" {
  let (enc, ctx) = @hpke.setup_base_s(test_pk_r, test_info, sk_e=test_sk_e)
  assert_eq(enc, test_enc)
  assert_eq(ctx.key, test_key)
  assert_eq(ctx.base_nonce, test_base_nonce)
  assert_eq(ctx.exporter_secret, test_exporter_secret)
}

///|
test "hpke: RFC 9180 A.1.1 — setup_base_r recovers same context" {
  let ctx_r = @hpke.setup_base_r(test_enc, test_sk_r, test_info)
  assert_eq(ctx_r.key, test_key)
  assert_eq(ctx_r.base_nonce, test_base_nonce)
  assert_eq(ctx_r.exporter_secret, test_exporter_secret)
}

///|
test "hpke: RFC 9180 A.1.1 — Seal #0 matches published ciphertext" {
  let (_, ctx) = @hpke.setup_base_s(test_pk_r, test_info, sk_e=test_sk_e)
  let ct0 = ctx.seal(test_aad0, test_pt)
  assert_eq(ct0, test_ct0)
}

///|
test "hpke: RFC 9180 A.1.1 — three consecutive Seals increment counter" {
  let (_, ctx) = @hpke.setup_base_s(test_pk_r, test_info, sk_e=test_sk_e)
  let ct0 = ctx.seal(test_aad0, test_pt)
  let ct1 = ctx.seal(test_aad1, test_pt)
  let ct2 = ctx.seal(test_aad2, test_pt)
  assert_eq(ct0, test_ct0)
  assert_eq(ct1, test_ct1)
  assert_eq(ct2, test_ct2)
}

///|
test "hpke: RFC 9180 A.1.1 — Open #0 on the receiver recovers plaintext" {
  let ctx_r = @hpke.setup_base_r(test_enc, test_sk_r, test_info)
  let pt = ctx_r.open(test_aad0, test_ct0)
  assert_eq(pt, test_pt)
}

///|
test "hpke: RFC 9180 A.1.1 — three Opens on the receiver in order" {
  let ctx_r = @hpke.setup_base_r(test_enc, test_sk_r, test_info)
  let p0 = ctx_r.open(test_aad0, test_ct0)
  let p1 = ctx_r.open(test_aad1, test_ct1)
  let p2 = ctx_r.open(test_aad2, test_ct2)
  assert_eq(p0, test_pt)
  assert_eq(p1, test_pt)
  assert_eq(p2, test_pt)
}

///|
test "hpke: RFC 9180 A.1.1 — Export with empty context, L=32" {
  let (_, ctx) = @hpke.setup_base_s(test_pk_r, test_info, sk_e=test_sk_e)
  let exp = ctx.export(b"", 32)
  assert_eq(exp, test_export_empty)
}

///|
test "hpke: RFC 9180 A.1.1 — Export with context = 0x00, L=32" {
  let (_, ctx) = @hpke.setup_base_s(test_pk_r, test_info, sk_e=test_sk_e)
  let exp = ctx.export(b"\x00", 32)
  assert_eq(exp, test_export_00)
}

///|
test "hpke: RFC 9180 A.1.1 — Export with context = 'TestContext', L=32" {
  let (_, ctx) = @hpke.setup_base_s(test_pk_r, test_info, sk_e=test_sk_e)
  let exp = ctx.export(test_export_ctx_testcontext, 32)
  assert_eq(exp, test_export_testcontext)
}

// ─── Roundtrip + behavioural tests ────────────────────────────────────────

///|
test "hpke: roundtrip Seal/Open with arbitrary message" {
  let (enc, ctx_s) = @hpke.setup_base_s(test_pk_r, b"app", sk_e=test_sk_e)
  let ctx_r = @hpke.setup_base_r(enc, test_sk_r, b"app")
  let aad : Bytes = b"\xaa\xbb\xcc"
  let pt : Bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  let ct = ctx_s.seal(aad, pt)
  let pt2 = ctx_r.open(aad, ct)
  assert_eq(pt2, pt)
}

///|
test "hpke: export gives the same output on both sides" {
  let (enc, ctx_s) = @hpke.setup_base_s(test_pk_r, test_info, sk_e=test_sk_e)
  let ctx_r = @hpke.setup_base_r(enc, test_sk_r, test_info)
  let exp_s = ctx_s.export(b"app1", 32)
  let exp_r = ctx_r.export(b"app1", 32)
  assert_eq(exp_s, exp_r)
  inspect(exp_s.length(), content="32")
}

///|
test "hpke: open fails with wrong aad" {
  let (enc, ctx_s) = @hpke.setup_base_s(test_pk_r, b"app", sk_e=test_sk_e)
  let ctx_r = @hpke.setup_base_r(enc, test_sk_r, b"app")
  let ct = ctx_s.seal(b"good-aad", b"\x01\x02\x03")
  let mut failed = false
  let _ = ctx_r.open(b"bad-aad", ct) catch {
    AeadFailure => {
      failed = true
      b""
    }
    e => raise e
  }
  assert_true(failed)
}

///|
test "hpke: invalid pk_r length is rejected" {
  let mut got_err = false
  let _ = @hpke.setup_base_s(b"\x00\x01\x02", test_info, sk_e=test_sk_e) catch {
    InvalidPublicKey(_) => {
      got_err = true
      (b"", { key: b"", base_nonce: b"", sequence: 0UL, exporter_secret: b"" })
    }
    e => raise e
  }
  assert_true(got_err)
}

///|
test "hpke: invalid sk_e length is rejected" {
  let mut got_err = false
  let _ = @hpke.setup_base_s(test_pk_r, test_info, sk_e=b"\x00\x01") catch {
    InvalidEphemeral(_) => {
      got_err = true
      (b"", { key: b"", base_nonce: b"", sequence: 0UL, exporter_secret: b"" })
    }
    e => raise e
  }
  assert_true(got_err)
}

///|
test "hpke: seal refuses exhausted sequence before AEAD" {
  let ctx : @hpke.HpkeContext = {
    key: b"short",
    base_nonce: test_base_nonce,
    sequence: 0xffffffffffffffffUL,
    exporter_secret: test_exporter_secret,
  }
  let mut got_err = false
  let _ = ctx.seal(b"", b"") catch {
    SequenceOverflow => {
      got_err = true
      b""
    }
    e => raise e
  }
  assert_true(got_err)
}

///|
test "hpke: open refuses exhausted sequence before AEAD" {
  let ctx : @hpke.HpkeContext = {
    key: b"short",
    base_nonce: test_base_nonce,
    sequence: 0xffffffffffffffffUL,
    exporter_secret: test_exporter_secret,
  }
  let mut got_err = false
  let _ = ctx.open(b"", b"") catch {
    SequenceOverflow => {
      got_err = true
      b""
    }
    e => raise e
  }
  assert_true(got_err)
}
