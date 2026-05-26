// HPKE (RFC 9180) — Hybrid Public Key Encryption.
//
// v0 scope: single ciphersuite, Mode_Base only.
//   KEM:  DHKEM(X25519, HKDF-SHA256)  (0x0020)
//   KDF:  HKDF-SHA256                  (0x0001)
//   AEAD: ChaCha20Poly1305             (0x0003)
//
// Cross-module wiring:
//   - DH:     mizchi/x25519
//   - HKDF:   mizchi/hkdf  (Extract / Expand for the labeled variants)
//   - AEAD:   mizchi/aead  (ChaCha20Poly1305 Seal / Open)
//
// What's NOT here: PSK / Auth / AuthPSK modes, KEM(P-256), KEM(P-384),
// KEM(X448), AEAD(AES-128-GCM), AEAD(AES-256-GCM), AEAD(ExportOnly). All are
// straight extensions of the Mode_Base + DHKEM(X25519) + ChaCha20-Poly1305
// skeleton wired below.
//
// Implementation notes (gotchas worth knowing before editing this file):
//
//   1. The HPKE labeled-KDF uses two DIFFERENT "suite_id" strings:
//
//        suite_id (KEM)  = "KEM"  || I2OSP(kem_id, 2)              (5 bytes)
//        suite_id (HPKE) = "HPKE" || I2OSP(kem_id, 2)
//                                 || I2OSP(kdf_id, 2)
//                                 || I2OSP(aead_id, 2)             (10 bytes)
//
//      DHKEM Extract-and-Expand uses the KEM suite_id; KeySchedule and
//      Export use the HPKE suite_id. Mixing them up is the #1 way to ship
//      an HPKE implementation that mostly looks right but doesn't interop.
//
//   2. `labeled_info` for LabeledExpand is:
//        I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
//      The 2-byte length prefix is part of the HKDF-Expand info, not a
//      separate argument — it goes BEFORE "HPKE-v1".
//
//   3. The per-call AEAD nonce is `base_nonce XOR I2OSP(seq, Nn)`. The seq
//      is encoded big-endian into the LOW bytes of an Nn-byte buffer
//      (i.e., right-aligned) before XOR-ing.
//
//   4. MoonBit `Buffer.write_string` writes UTF-16LE, which is wrong for
//      our needs. All labels here use byte literals (b"...") so the bytes
//      go in as ASCII.

///|
pub suberror HpkeError {
  InvalidPublicKey(Int)
  InvalidPrivateKey(Int)
  InvalidEphemeral(Int)
  KemFailure
  SequenceOverflow
  KdfFailure
  AeadFailure
} derive(Debug)

// ─── Ciphersuite constants ────────────────────────────────────────────────

///|
const KEM_ID : Int = 0x0020 // DHKEM(X25519, HKDF-SHA256)

///|
const KDF_ID : Int = 0x0001 // HKDF-SHA256

///|
const AEAD_ID : Int = 0x0003 // ChaCha20Poly1305

///|
const NH : Int = 32 // HKDF-SHA256 output size (also DHKEM N_secret)

///|
const NK : Int = 32 // ChaCha20Poly1305 key length

///|
const NN : Int = 12 // ChaCha20Poly1305 nonce length

///|
const NPK : Int = 32 // X25519 serialized public key length

///|
const NSK : Int = 32 // X25519 serialized private key length

///|
const MODE_BASE : Byte = b'\x00'

// ─── Bytes helpers ────────────────────────────────────────────────────────

///|
fn i2osp2(n : Int) -> Bytes {
  let hi = ((n >> 8) & 0xff).to_byte()
  let lo = (n & 0xff).to_byte()
  Bytes::makei(2, fn(i) { if i == 0 { hi } else { lo } })
}

///|
fn bytes_concat(a : Bytes, b : Bytes) -> Bytes {
  let n = a.length() + b.length()
  Bytes::makei(n, fn(i) {
    if i < a.length() {
      a[i]
    } else {
      b[i - a.length()]
    }
  })
}

///|
fn bytes_concat3(a : Bytes, b : Bytes, c : Bytes) -> Bytes {
  bytes_concat(bytes_concat(a, b), c)
}

///|
fn bytes_concat4(a : Bytes, b : Bytes, c : Bytes, d : Bytes) -> Bytes {
  bytes_concat(bytes_concat3(a, b, c), d)
}

///|
fn bytes_concat5(
  a : Bytes,
  b : Bytes,
  c : Bytes,
  d : Bytes,
  e : Bytes,
) -> Bytes {
  bytes_concat(bytes_concat4(a, b, c, d), e)
}

// ─── Suite IDs (RFC 9180 §4.1 / §5.1) ─────────────────────────────────────

///|
fn kem_suite_id() -> Bytes {
  // "KEM" || I2OSP(kem_id, 2)
  bytes_concat(b"KEM", i2osp2(KEM_ID))
}

///|
fn hpke_suite_id() -> Bytes {
  // "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
  bytes_concat4(b"HPKE", i2osp2(KEM_ID), i2osp2(KDF_ID), i2osp2(AEAD_ID))
}

// ─── Labeled Extract / Expand (RFC 9180 §4) ──────────────────────────────

///|
fn labeled_extract(
  suite_id : Bytes,
  salt : Bytes,
  label : Bytes,
  ikm : Bytes,
) -> Bytes raise HpkeError {
  // labeled_ikm = "HPKE-v1" || suite_id || label || ikm
  let lab_ikm = bytes_concat4(b"HPKE-v1", suite_id, label, ikm)
  @hkdf.extract(@hkdf.HashAlg::Sha256, salt, lab_ikm) catch {
    _ => raise KdfFailure
  }
}

///|
fn labeled_expand(
  suite_id : Bytes,
  prk : Bytes,
  label : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes raise HpkeError {
  if length < 0 || length > 0xffff {
    raise KdfFailure
  }
  // labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
  let lab_info = bytes_concat5(
    i2osp2(length),
    b"HPKE-v1",
    suite_id,
    label,
    info,
  )
  @hkdf.expand(@hkdf.HashAlg::Sha256, prk, lab_info, length) catch {
    _ => raise KdfFailure
  }
}

// ─── DHKEM(X25519, HKDF-SHA256) (RFC 9180 §4.1) ──────────────────────────

///|
fn extract_and_expand(dh : Bytes, kem_context : Bytes) -> Bytes raise HpkeError {
  let sid = kem_suite_id()
  let eae_prk = labeled_extract(sid, b"", b"eae_prk", dh)
  labeled_expand(sid, eae_prk, b"shared_secret", kem_context, NH)
}

///|
fn x25519_pub_from_priv(sk : Bytes) -> Bytes raise HpkeError {
  let priv_key = @x25519.PrivateKey::from_bytes(sk) catch {
    _ => raise InvalidPrivateKey(sk.length())
  }
  priv_key.public_key().to_bytes()
}

///|
fn x25519_dh(sk : Bytes, pk : Bytes) -> Bytes raise HpkeError {
  let priv_key = @x25519.PrivateKey::from_bytes(sk) catch {
    _ => raise InvalidPrivateKey(sk.length())
  }
  let pub_key = @x25519.PublicKey::from_bytes(pk) catch {
    _ => raise InvalidPublicKey(pk.length())
  }
  let shared = @x25519.diffie_hellman(priv_key, pub_key) catch {
    _ => raise KemFailure
  }
  shared.to_bytes()
}

///|
/// DHKEM Encap with caller-supplied ephemeral private key. RFC 9180 §4.1
/// defines GenerateKeyPair as ikm-driven; we accept the raw ephemeral
/// private key directly to keep this implementation RNG-free. Callers must
/// supply a fresh CSPRNG-derived `sk_e` for each Encap.
fn dhkem_encap(pk_r : Bytes, sk_e : Bytes) -> (Bytes, Bytes) raise HpkeError {
  if pk_r.length() != NPK {
    raise InvalidPublicKey(pk_r.length())
  }
  if sk_e.length() != NSK {
    raise InvalidEphemeral(sk_e.length())
  }
  let pk_e = x25519_pub_from_priv(sk_e)
  let dh = x25519_dh(sk_e, pk_r)
  let kem_context = bytes_concat(pk_e, pk_r)
  let shared_secret = extract_and_expand(dh, kem_context)
  (shared_secret, pk_e)
}

///|
fn dhkem_decap(enc : Bytes, sk_r : Bytes) -> Bytes raise HpkeError {
  if enc.length() != NPK {
    raise InvalidPublicKey(enc.length())
  }
  if sk_r.length() != NSK {
    raise InvalidPrivateKey(sk_r.length())
  }
  let pk_r = x25519_pub_from_priv(sk_r)
  let dh = x25519_dh(sk_r, enc)
  let kem_context = bytes_concat(enc, pk_r)
  extract_and_expand(dh, kem_context)
}

// ─── KeySchedule (RFC 9180 §5.1) ─────────────────────────────────────────

///|
pub(all) struct HpkeContext {
  key : Bytes // 32 bytes for ChaCha20Poly1305
  base_nonce : Bytes // 12 bytes
  mut sequence : UInt64
  exporter_secret : Bytes // 32 bytes (Nh)
}

///|
fn key_schedule_base(
  shared_secret : Bytes,
  info : Bytes,
) -> HpkeContext raise HpkeError {
  let sid = hpke_suite_id()

  // For Mode_Base: default_psk_id = "", default_psk = "".
  //   psk_id_hash = LabeledExtract("", "psk_id_hash", default_psk_id="")
  //   info_hash   = LabeledExtract("", "info_hash", info)
  let pid_hash = labeled_extract(sid, b"", b"psk_id_hash", b"")
  let i_hash = labeled_extract(sid, b"", b"info_hash", info)

  // key_schedule_context = mode || psk_id_hash || info_hash
  let mode_b = Bytes::makei(1, fn(_) { MODE_BASE })
  let ksc = bytes_concat3(mode_b, pid_hash, i_hash)

  // secret = LabeledExtract(shared_secret, "secret", default_psk="")
  let secret = labeled_extract(sid, shared_secret, b"secret", b"")
  let key = labeled_expand(sid, secret, b"key", ksc, NK)
  let base_nonce = labeled_expand(sid, secret, b"base_nonce", ksc, NN)
  let exporter_secret = labeled_expand(sid, secret, b"exp", ksc, NH)
  { key, base_nonce, sequence: 0UL, exporter_secret }
}

// ─── Setup / Seal / Open / Export ────────────────────────────────────────

///|
/// Setup the sender side of Mode_Base HPKE.
///
/// `sk_e` is the caller-supplied ephemeral X25519 private key. The repo has
/// no RNG primitive at this layer (see `mizchi/getrandom`), so the caller
/// is responsible for sourcing a fresh 32-byte ephemeral per call. Reusing
/// `sk_e` across calls trivially compromises confidentiality.
pub fn setup_base_s(
  pk_r : Bytes,
  info : Bytes,
  sk_e~ : Bytes,
) -> (Bytes, HpkeContext) raise HpkeError {
  let (shared_secret, enc) = dhkem_encap(pk_r, sk_e)
  let ctx = key_schedule_base(shared_secret, info)
  (enc, ctx)
}

///|
/// Setup the receiver side of Mode_Base HPKE.
pub fn setup_base_r(
  enc : Bytes,
  sk_r : Bytes,
  info : Bytes,
) -> HpkeContext raise HpkeError {
  let shared_secret = dhkem_decap(enc, sk_r)
  key_schedule_base(shared_secret, info)
}

///|
/// Per-call nonce = base_nonce XOR I2OSP(sequence, Nn). Nn = 12.
fn compute_nonce(base_nonce : Bytes, sequence : UInt64) -> Bytes {
  // Encode `sequence` as a 12-byte big-endian integer (top 4 bytes are
  // zero since UInt64 fits in 8 bytes) and XOR into base_nonce.
  Bytes::makei(NN, fn(i) {
    let shift = (NN - 1 - i) * 8
    let seq_byte = if shift >= 64 {
      0
    } else {
      ((sequence >> shift) & 0xffUL).to_int()
    }
    (base_nonce[i].to_int() ^ seq_byte).to_byte()
  })
}

///|
/// Cap is 2^(8*Nn) - 1 (RFC 9180 §5.2). For Nn = 12 that's 2^96 - 1, way
/// beyond UInt64; we only need to refuse UInt64::MaxValue.
fn increment_seq(ctx : HpkeContext) -> Unit raise HpkeError {
  if ctx.sequence == 0xFFFFFFFFFFFFFFFFUL {
    raise SequenceOverflow
  }
  ctx.sequence = ctx.sequence + 1UL
}

///|
fn validate_aead_context(ctx : HpkeContext) -> Unit raise HpkeError {
  if ctx.sequence == 0xFFFFFFFFFFFFFFFFUL {
    raise SequenceOverflow
  }
  if ctx.key.length() != NK || ctx.base_nonce.length() != NN {
    raise AeadFailure
  }
}

///|
pub fn HpkeContext::seal(
  self : HpkeContext,
  aad : Bytes,
  pt : Bytes,
) -> Bytes raise HpkeError {
  validate_aead_context(self)
  let nonce = compute_nonce(self.base_nonce, self.sequence)
  let ct = @aead.seal(
    @aead.Algorithm::ChaCha20Poly1305,
    self.key,
    nonce,
    aad,
    pt,
  ) catch {
    _ => raise AeadFailure
  }
  increment_seq(self)
  ct
}

///|
pub fn HpkeContext::open(
  self : HpkeContext,
  aad : Bytes,
  ct : Bytes,
) -> Bytes raise HpkeError {
  validate_aead_context(self)
  let nonce = compute_nonce(self.base_nonce, self.sequence)
  let pt = @aead.open(
    @aead.Algorithm::ChaCha20Poly1305,
    self.key,
    nonce,
    aad,
    ct,
  ) catch {
    _ => raise AeadFailure
  }
  increment_seq(self)
  pt
}

///|
/// RFC 9180 §5.3 Export: secret-export interface.
///
///   Export(exporter_context, L) = LabeledExpand(exporter_secret, "sec",
///                                               exporter_context, L)
///
/// using the HPKE suite_id (not the KEM one).
pub fn HpkeContext::export_secret(
  self : HpkeContext,
  exporter_context : Bytes,
  length : Int,
) -> Bytes raise HpkeError {
  labeled_expand(
    hpke_suite_id(),
    self.exporter_secret,
    b"sec",
    exporter_context,
    length,
  )
}
