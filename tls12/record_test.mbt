// TLS 1.2 AES-GCM record-layer tests. The reference record is produced by
// Node's `crypto` (aes-128-gcm) with the TLS 1.2 nonce/AAD framing, so this
// pins the on-wire layout against an independent AES-GCM implementation.

///|
test "TLS 1.2 GCM seal matches Node crypto reference record" {
  let keys = @tls12.GcmKeys::new(
    @aead.Aes128Gcm,
    hx("000102030405060708090a0b0c0d0e0f"),
    hx("a0a1a2a3"),
  )
  let pt = hx("68656c6c6f20746c7320312e32207265636f7264") // "hello tls 1.2 record"
  let rec = @tls12.seal_gcm_record(
    keys,
    1UL,
    @tls12.ContentType::ApplicationData,
    pt,
  )
  inspect(
    tohx(rec),
    content="170303002c00000000000000012e14709e03a4033cf44c7739e924e603729d6be79f83cdd67882def959ec2b03cd714988",
  )
}

///|
test "TLS 1.2 GCM open round-trips the reference record" {
  let keys = @tls12.GcmKeys::new(
    @aead.Aes128Gcm,
    hx("000102030405060708090a0b0c0d0e0f"),
    hx("a0a1a2a3"),
  )
  let rec = hx(
    "170303002c00000000000000012e14709e03a4033cf44c7739e924e603729d6be79f83cdd67882def959ec2b03cd714988",
  )
  let (ct, pt) = @tls12.open_gcm_record(keys, 1UL, rec)
  inspect(ct.to_int(), content="23") // ApplicationData
  inspect(tohx(pt), content="68656c6c6f20746c7320312e32207265636f7264")
}

///|
test "TLS 1.2 GCM seal/open round-trip across sequence numbers" {
  let keys = @tls12.GcmKeys::new(@aead.Aes256Gcm, rep(0x5a, 32), hx("deadbeef"))
  for seq = 0UL; seq < 5UL; seq = seq + 1UL {
    let msg = rep(0x30 + seq.to_int(), 24)
    let rec = @tls12.seal_gcm_record(
      keys,
      seq,
      @tls12.ContentType::Handshake,
      msg,
    )
    let (ct, pt) = @tls12.open_gcm_record(keys, seq, rec)
    inspect(ct.to_int(), content="22") // Handshake
    inspect(tohx(pt), content=tohx(msg))
  }
}

///|
test "TLS 1.2 GCM open rejects a tampered tag" {
  let keys = @tls12.GcmKeys::new(
    @aead.Aes128Gcm,
    hx("000102030405060708090a0b0c0d0e0f"),
    hx("a0a1a2a3"),
  )
  let rec = hx(
    "170303002c00000000000000012e14709e03a4033cf44c7739e924e603729d6be79f83cdd67882def959ec2b03cd714987",
  ) // last byte flipped 88 -> 87
  let mut rejected = false
  let _ = @tls12.open_gcm_record(keys, 1UL, rec) catch {
    _ => {
      rejected = true
      (@tls12.ContentType::Alert, b"")
    }
  }
  inspect(rejected, content="true")
}

///|
test "TLS 1.2 GCM open rejects wrong sequence number (AAD/nonce mismatch)" {
  let keys = @tls12.GcmKeys::new(
    @aead.Aes128Gcm,
    hx("000102030405060708090a0b0c0d0e0f"),
    hx("a0a1a2a3"),
  )
  let rec = hx(
    "170303002c00000000000000012e14709e03a4033cf44c7739e924e603729d6be79f83cdd67882def959ec2b03cd714988",
  )
  let mut rejected = false
  let _ = @tls12.open_gcm_record(keys, 2UL, rec) catch {
    _ => {
      rejected = true
      (@tls12.ContentType::Alert, b"")
    }
  }
  inspect(rejected, content="true")
}
