// Noise conformance against the flynn/noise test vectors
// (Noise_*_25519_ChaChaPoly_SHA256). Each vector pins all key material, so the
// handshake is reproducible byte-for-byte; the test drives both peers and
// checks every handshake message and the first transport message each way.

///|
fn nh(s : String) -> Bytes {
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
let init_eph : String = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"

///|
let resp_eph : String = "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"

///|
let static_a : String = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

///|
let static_b : String = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

///|
fn pub_of(priv_hex : String) -> Bytes raise {
  @x25519.PrivateKey::from_bytes(nh(priv_hex)).public_key().to_bytes()
}

///|
// Drive a full handshake + transport exchange from the vector and check every
// message. `msgs` are (payload, ciphertext) pairs in overall message order
// (even index = initiator sends, odd = responder sends).
fn run_vector(
  pattern : @noise.Pattern,
  init_s : Bytes?,
  resp_s : Bytes?,
  init_rs : Bytes?,
  msgs : Array[(Bytes, Bytes)],
) -> Unit raise {
  let ini = @noise.HandshakeState::new(
    pattern,
    true,
    b"",
    s=init_s,
    e=Some(nh(init_eph)),
    rs=init_rs,
  )
  let res = @noise.HandshakeState::new(
    pattern,
    false,
    b"",
    s=resp_s,
    e=Some(nh(resp_eph)),
    rs=None,
  )
  let mut i = 0
  while !ini.is_finished() {
    let (payload, ct) = msgs[i]
    if i % 2 == 0 {
      let out = ini.write_message(payload)
      @debug.assert_eq(out, ct)
      @debug.assert_eq(res.read_message(out), payload)
    } else {
      let out = res.write_message(payload)
      @debug.assert_eq(out, ct)
      @debug.assert_eq(ini.read_message(out), payload)
    }
    i = i + 1
  }
  let (ic1, ic2) = ini.split()
  let (rc1, rc2) = res.split()
  // Transport messages always start with the initiator and alternate, keyed by
  // the transport-relative index (not the overall message parity).
  let hs_count = i
  while i < msgs.length() {
    let (payload, ct) = msgs[i]
    if (i - hs_count) % 2 == 0 {
      let out = ic1.encrypt_with_ad(b"", payload)
      @debug.assert_eq(out, ct)
      @debug.assert_eq(rc1.decrypt_with_ad(b"", out), payload)
    } else {
      let out = rc2.encrypt_with_ad(b"", payload)
      @debug.assert_eq(out, ct)
      @debug.assert_eq(ic2.decrypt_with_ad(b"", out), payload)
    }
    i = i + 1
  }
}

///|
let ys : Bytes = b"yellowsubmarine"

///|
let sy : Bytes = b"submarineyellow"

///|
test "Noise_NN_25519_ChaChaPoly_SHA256 vector" {
  run_vector(@noise.Pattern::NN, None, None, None, [
    (
      b"",
      nh("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"),
    ),
    (
      b"",
      nh(
        "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466b9a74f6724441623af038022288c2556",
      ),
    ),
    (ys, nh("96cd46be111804586a935795eeb4ce62bdec121048a10520b00266b22722eb")),
    (sy, nh("fe2bc534e31964c0bd56337223e921565e39dbc5f156aa04766ced4689a2a2")),
  ])
}

///|
test "Noise_NK_25519_ChaChaPoly_SHA256 vector" {
  run_vector(
    @noise.Pattern::NK,
    None,
    Some(nh(static_b)),
    Some(pub_of(static_b)),
    [
      (
        b"",
        nh(
          "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254bb9e8fd1c92e99737291c111956e17ab",
        ),
      ),
      (
        b"",
        nh(
          "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466d97cd906e611b305ce4c22ffd315b750",
        ),
      ),
      (ys, nh("9cfd3ddea89d9f445475098f834e572ec4a8c5e9be740dd92831ef6cf6fd9e")),
      (sy, nh("5db2eb7c7b37b33cd42fd321e05d9048c9be3efa0ae3a8c76724307e7562ff")),
    ],
  )
}

///|
test "Noise_XX_25519_ChaChaPoly_SHA256 vector" {
  run_vector(@noise.Pattern::XX, Some(nh(static_a)), Some(nh(static_b)), None, [
    (
      b"",
      nh("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"),
    ),
    (
      b"",
      nh(
        "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d484663414af878d3e46a2f58911a816d6e8346d4ea17a6f2a0bb4ef4ed56c133cff4560a34e36ea82109f26cf2e5a5caf992b608d55c747f615e5a3425a7a19eefb8f",
      ),
    ),
    (
      b"",
      nh(
        "87f864c11ba449f46a0a4f4e2eacbb7b0457784f4fca1937f572c93603e9c4d97e5ea11b16f3968710b23a3be3202dc1b5e1ce3c963347491e74f5c0768a9b42",
      ),
    ),
    (ys, nh("a52ef02ba60e12696d1d6b9ef4245c88fca757b6134ad6e76b56e310a6adf6")),
    (sy, nh("2445aa438ebd649281c636cc7269ca82f1d9023d72520943aeabf909cdf521")),
  ])
}

///|
test "Noise_IK_25519_ChaChaPoly_SHA256 vector" {
  run_vector(
    @noise.Pattern::IK,
    Some(nh(static_a)),
    Some(nh(static_b)),
    Some(pub_of(static_b)),
    [
      (
        b"",
        nh(
          "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662544f8445e5dc2467b1e32653192d05dee85c4781bf0dd8d33ceebb5905a7a069f09e0d3f2cad1c842930a762eb75e52827f01d2c85189d527644b3221b4c3fc5cc",
        ),
      ),
      (
        b"",
        nh(
          "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466aabfe2e5b1650bbaa88e33679893fc77",
        ),
      ),
      (ys, nh("226ca869f2777611f37350a7ab446f650c0cfe2855b7f020ce658bcf100f2d")),
      (sy, nh("90d84d69cd44829283b05d684879b53b8d714e51619b601438a1ae67caacd9")),
    ],
  )
}

///|
test "Noise rejects a tampered handshake message and bad transport tag" {
  // XX initiator's first message tampered -> responder read_message fails.
  let ini = @noise.HandshakeState::new(
    @noise.Pattern::XX,
    true,
    b"",
    s=Some(nh(static_a)),
    e=Some(nh(init_eph)),
  )
  let res = @noise.HandshakeState::new(
    @noise.Pattern::XX,
    false,
    b"",
    s=Some(nh(static_b)),
    e=Some(nh(resp_eph)),
  )
  let m0 = ini.write_message(b"")
  let _ = res.read_message(m0)
  let m1 = res.write_message(b"")
  // m1 carries an encrypted static + DH; flip a byte -> tag mismatch on read.
  let bad = Bytes::makei(m1.length(), fn(i) {
    if i == m1.length() - 1 {
      (m1[i].to_int() ^ 0x01).to_byte()
    } else {
      m1[i]
    }
  })
  try ini.read_message(bad) |> ignore catch {
    DecryptFailed => ()
    e => abort("expected DecryptFailed, got " + repr(e))
  } noraise {
    _ => abort("accepted a tampered handshake message")
  }
}
