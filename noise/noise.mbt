// Noise Protocol Framework (https://noiseprotocol.org/noise.html, rev 34),
// instantiated as 25519 + ChaChaPoly + SHA256 — the same primitive lineup as
// the age module, here driving a mutual-auth secure channel (the basis of
// WireGuard and Signal's X3DH). Patterns: NN, NK, XX, IK.
//
// The handshake is pure and deterministic: the caller supplies the local
// static / ephemeral private keys (the ephemeral MUST come from a CSPRNG and
// be unique per handshake). This matches how the official test vectors pin all
// key material for reproducible, byte-exact validation.

///|
pub suberror NoiseError {
  // Decryption / tag verification failed (a forged or corrupt message).
  DecryptFailed
  // A handshake message was shorter than the pattern requires.
  Truncated
  // A required key (static / ephemeral / remote static) was not provided.
  MissingKey(String)
  // write_message / read_message called after the handshake finished, or
  // split() called before it finished.
  WrongState(String)
  Dh(String)
  // The per-CipherState nonce reached 2^64-1, the reserved value (Noise §5.1).
  // The party must terminate rather than reuse a nonce.
  NonceExhausted
} derive(Debug)

///|
// Noise §5.1: nonce 2^64-1 is reserved and must never be used to encrypt; a
// party reaching it must terminate the session. In practice MoonBit's Bytes
// size limit makes this unreachable, but the guard keeps the invariant explicit
// (and fail-closed) rather than wrapping the nonce on overflow.
const MAX_NONCE : UInt64 = 0xffff_ffff_ffff_ffffUL

// ─── DH / hash / HKDF primitives (25519 + SHA256) ────────────────────────

///|
fn dh(local_priv : Bytes, remote_pub : Bytes) -> Bytes raise NoiseError {
  let sk = @x25519.PrivateKey::from_bytes(local_priv) catch {
    e => raise Dh(repr(e))
  }
  let pk = @x25519.PublicKey::from_bytes(remote_pub) catch {
    e => raise Dh(repr(e))
  }
  let ss = @x25519.diffie_hellman(sk, pk) catch { e => raise Dh(repr(e)) }
  ss.to_bytes()
}

///|
fn pubkey(secret : Bytes) -> Bytes raise NoiseError {
  let sk = @x25519.PrivateKey::from_bytes(secret) catch {
    e => raise Dh(repr(e))
  }
  sk.public_key().to_bytes()
}

///|
fn sha256(data : Bytes) -> Bytes {
  @hash.sha256(data)
}

///|
fn cat(a : Bytes, b : Bytes) -> Bytes {
  Bytes::makei(a.length() + b.length(), fn(i) {
    if i < a.length() {
      a[i]
    } else {
      b[i - a.length()]
    }
  })
}

///|
fn slice(b : Bytes, start : Int, len : Int) -> Bytes {
  Bytes::makei(len, fn(i) { b[start + i] })
}

///|
// Noise HKDF (§4.3): num_outputs * 32 bytes = HKDF-Expand(HKDF-Extract(ck,
// ikm), "", n*32), which matches RFC 5869 with empty info — exactly what
// mizchi/hkdf computes.
fn noise_hkdf(ck : Bytes, ikm : Bytes, num : Int) -> Array[Bytes] {
  let prk = @hkdf.extract(@hkdf.HashAlg::Sha256, ck, ikm)
  let okm = @hkdf.expand(@hkdf.HashAlg::Sha256, prk, b"", num * 32) catch {
    _ => abort("noise hkdf expand")
  }
  let out : Array[Bytes] = []
  for i in 0..<num {
    out.push(slice(okm, i * 32, 32))
  }
  out
}

// ─── CipherState (§5.1) ──────────────────────────────────────────────────

///|
/// A Noise CipherState: an AEAD key plus a 64-bit nonce counter.
pub struct CipherState {
  mut key : Bytes // empty == no key
  mut nonce : UInt64
}

///|
fn CipherState::empty() -> CipherState {
  { key: b"", nonce: 0UL }
}

///|
fn CipherState::has_key(self : CipherState) -> Bool {
  self.key.length() == 32
}

///|
fn CipherState::init_key(self : CipherState, k : Bytes) -> Unit {
  self.key = k
  self.nonce = 0UL
}

///|
// ChaChaPoly nonce (§12.3): 4 zero bytes || little-endian uint64(n).
fn noise_nonce(n : UInt64) -> Bytes {
  Bytes::makei(12, fn(i) {
    if i < 4 {
      b'\x00'
    } else {
      ((n >> ((i - 4) * 8)) & 0xffUL).to_int().to_byte()
    }
  })
}

///|
/// AEAD-encrypt `plaintext` with associated data `ad`. With no key set this is
/// the identity (used during the early handshake), per the Noise spec.
pub fn CipherState::encrypt_with_ad(
  self : CipherState,
  ad : Bytes,
  plaintext : Bytes,
) -> Bytes raise NoiseError {
  if !self.has_key() {
    return plaintext
  }
  if self.nonce == MAX_NONCE {
    raise NonceExhausted
  }
  let ct = @aead.seal(
    @aead.Algorithm::ChaCha20Poly1305,
    self.key,
    noise_nonce(self.nonce),
    ad,
    plaintext,
  ) catch {
    _ => raise DecryptFailed
  }
  self.nonce = self.nonce + 1UL
  ct
}

///|
/// AEAD-decrypt `ciphertext` with associated data `ad`. Raises `DecryptFailed`
/// on a bad tag. With no key set this is the identity.
pub fn CipherState::decrypt_with_ad(
  self : CipherState,
  ad : Bytes,
  ciphertext : Bytes,
) -> Bytes raise NoiseError {
  if !self.has_key() {
    return ciphertext
  }
  if self.nonce == MAX_NONCE {
    raise NonceExhausted
  }
  let pt = @aead.open(
    @aead.Algorithm::ChaCha20Poly1305,
    self.key,
    noise_nonce(self.nonce),
    ad,
    ciphertext,
  ) catch {
    _ => raise DecryptFailed
  }
  self.nonce = self.nonce + 1UL
  pt
}

// ─── SymmetricState (§5.2) ───────────────────────────────────────────────

///|
struct SymmetricState {
  mut ck : Bytes
  mut h : Bytes
  cs : CipherState
}

///|
fn SymmetricState::new(protocol_name : String) -> SymmetricState {
  let name = Bytes::makei(protocol_name.length(), fn(i) {
    (protocol_name.get_char(i).unwrap().to_int() & 0xff).to_byte()
  })
  let h = if name.length() <= 32 {
    Bytes::makei(32, fn(i) { if i < name.length() { name[i] } else { b'\x00' } })
  } else {
    sha256(name)
  }
  { ck: h, h, cs: CipherState::empty() }
}

///|
fn SymmetricState::mix_key(self : SymmetricState, ikm : Bytes) -> Unit {
  let out = noise_hkdf(self.ck, ikm, 2)
  self.ck = out[0]
  self.cs.init_key(out[1])
}

///|
fn SymmetricState::mix_hash(self : SymmetricState, data : Bytes) -> Unit {
  self.h = sha256(cat(self.h, data))
}

///|
fn SymmetricState::encrypt_and_hash(
  self : SymmetricState,
  plaintext : Bytes,
) -> Bytes raise NoiseError {
  let ct = self.cs.encrypt_with_ad(self.h, plaintext)
  self.mix_hash(ct)
  ct
}

///|
fn SymmetricState::decrypt_and_hash(
  self : SymmetricState,
  ciphertext : Bytes,
) -> Bytes raise NoiseError {
  let pt = self.cs.decrypt_with_ad(self.h, ciphertext)
  self.mix_hash(ciphertext)
  pt
}

///|
fn SymmetricState::split(self : SymmetricState) -> (CipherState, CipherState) {
  let out = noise_hkdf(self.ck, b"", 2)
  let c1 = CipherState::empty()
  c1.init_key(out[0])
  let c2 = CipherState::empty()
  c2.init_key(out[1])
  (c1, c2)
}

// ─── handshake patterns ──────────────────────────────────────────────────

///|
enum Token {
  E
  S
  EE
  ES
  SE
  SS
} derive(Eq)

///|
/// A supported Noise handshake pattern.
pub(all) enum Pattern {
  NN
  NK
  XX
  IK
} derive(Eq, Debug)

///|
fn Pattern::name(self : Pattern) -> String {
  match self {
    NN => "NN"
    NK => "NK"
    XX => "XX"
    IK => "IK"
  }
}

///|
// (pre_responder_has_s, messages). None of our patterns use an initiator
// pre-message; NK and IK pre-share the responder's static.
fn Pattern::layout(self : Pattern) -> (Bool, Array[Array[Token]]) {
  match self {
    NN => (false, [[E], [E, EE]])
    NK => (true, [[E, ES], [E, EE]])
    XX => (false, [[E], [E, EE, S, ES], [S, SE]])
    IK => (true, [[E, ES, S, SS], [E, EE, SE]])
  }
}

// ─── HandshakeState (§5.3) ───────────────────────────────────────────────

///|
/// A Noise handshake in progress. Drive it with `write_message` /
/// `read_message` (the two peers alternate, initiator first); when
/// `is_finished` is true, call `split` for the transport CipherStates.
pub struct HandshakeState {
  ss : SymmetricState
  initiator : Bool
  messages : Array[Array[Token]]
  mut msg_index : Int
  s : Bytes? // local static private
  e : Bytes? // local ephemeral private
  mut rs : Bytes? // remote static public
  mut re : Bytes? // remote ephemeral public
}

///|
/// Create a handshake. `prologue` is mixed into the transcript. `s` is the
/// local static private key (required by patterns that send "s"); `e` is the
/// local ephemeral private key (required — supply from a CSPRNG); `rs` is the
/// remote static public key (required for the initiator of NK / IK).
pub fn HandshakeState::new(
  pattern : Pattern,
  initiator : Bool,
  prologue : Bytes,
  s? : Bytes? = None,
  e? : Bytes? = None,
  rs? : Bytes? = None,
) -> HandshakeState raise NoiseError {
  let ss = SymmetricState::new(
    "Noise_" + pattern.name() + "_25519_ChaChaPoly_SHA256",
  )
  ss.mix_hash(prologue)
  let (pre_resp_s, messages) = pattern.layout()
  // Pre-message: the responder's static public key is known to both sides.
  if pre_resp_s {
    let resp_static_pub = if initiator {
      match rs {
        Some(k) => k
        None => raise MissingKey("rs (remote static) required")
      }
    } else {
      match s {
        Some(k) => pubkey(k)
        None => raise MissingKey("s (local static) required")
      }
    }
    ss.mix_hash(resp_static_pub)
  }
  { ss, initiator, messages, msg_index: 0, s, e, rs, re: None }
}

///|
/// True once all handshake messages have been processed.
pub fn HandshakeState::is_finished(self : HandshakeState) -> Bool {
  self.msg_index >= self.messages.length()
}

///|
/// The handshake hash `h` (RFC: a unique channel binding).
pub fn HandshakeState::handshake_hash(self : HandshakeState) -> Bytes {
  self.ss.h
}

///|
fn HandshakeState::mix_dh(
  self : HandshakeState,
  token : Token,
) -> Unit raise NoiseError {
  let need = fn(o : Bytes?, what : String) -> Bytes raise NoiseError {
    match o {
      Some(k) => k
      None => raise MissingKey(what)
    }
  }
  let ikm = match token {
    EE => dh(need(self.e, "e"), need(self.re, "re"))
    SS => dh(need(self.s, "s"), need(self.rs, "rs"))
    ES =>
      if self.initiator {
        dh(need(self.e, "e"), need(self.rs, "rs"))
      } else {
        dh(need(self.s, "s"), need(self.re, "re"))
      }
    SE =>
      if self.initiator {
        dh(need(self.s, "s"), need(self.re, "re"))
      } else {
        dh(need(self.e, "e"), need(self.rs, "rs"))
      }
    _ => abort("mix_dh: not a DH token")
  }
  self.ss.mix_key(ikm)
}

///|
/// Write the next handshake message: process the current message pattern's
/// tokens, then append the (encrypted) `payload`. Returns the wire message.
pub fn HandshakeState::write_message(
  self : HandshakeState,
  payload : Bytes,
) -> Bytes raise NoiseError {
  if self.is_finished() {
    raise WrongState("handshake already finished")
  }
  let pattern = self.messages[self.msg_index]
  let mut out = b""
  for token in pattern {
    match token {
      E => {
        let e = match self.e {
          Some(k) => k
          None => raise MissingKey("e (local ephemeral) required")
        }
        let epub = pubkey(e)
        out = cat(out, epub)
        self.ss.mix_hash(epub)
      }
      S => {
        let spub = match self.s {
          Some(k) => pubkey(k)
          None => raise MissingKey("s (local static) required")
        }
        out = cat(out, self.ss.encrypt_and_hash(spub))
      }
      _ => self.mix_dh(token)
    }
  }
  out = cat(out, self.ss.encrypt_and_hash(payload))
  self.msg_index = self.msg_index + 1
  out
}

///|
/// Read the next handshake message: consume the current pattern's tokens from
/// `message`, then decrypt the trailing payload. Returns the payload.
pub fn HandshakeState::read_message(
  self : HandshakeState,
  message : Bytes,
) -> Bytes raise NoiseError {
  if self.is_finished() {
    raise WrongState("handshake already finished")
  }
  let pattern = self.messages[self.msg_index]
  let mut pos = 0
  for token in pattern {
    match token {
      E => {
        if message.length() - pos < 32 {
          raise Truncated
        }
        let re = slice(message, pos, 32)
        pos = pos + 32
        self.re = Some(re)
        self.ss.mix_hash(re)
      }
      S => {
        let n = if self.ss.cs.has_key() { 48 } else { 32 }
        if message.length() - pos < n {
          raise Truncated
        }
        let temp = slice(message, pos, n)
        pos = pos + n
        self.rs = Some(self.ss.decrypt_and_hash(temp))
      }
      _ => self.mix_dh(token)
    }
  }
  if pos > message.length() {
    raise Truncated
  }
  let rest = slice(message, pos, message.length() - pos)
  let payload = self.ss.decrypt_and_hash(rest)
  self.msg_index = self.msg_index + 1
  payload
}

///|
/// After the handshake is finished, derive the two transport CipherStates.
/// For the initiator the first is the send state and the second the receive
/// state; for the responder it is the reverse.
pub fn HandshakeState::split(
  self : HandshakeState,
) -> (CipherState, CipherState) raise NoiseError {
  if !self.is_finished() {
    raise WrongState("handshake not finished")
  }
  self.ss.split()
}
