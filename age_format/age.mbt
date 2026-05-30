// age v1 file decryption (https://age-encryption.org/v1), X25519 recipients.
//
// Composes mizchi/x25519 (ECDH), mizchi/hkdf (HKDF-SHA256), mizchi/aead
// (ChaCha20-Poly1305) and mizchi/hash (HMAC-SHA256). This is the verify-side
// "open a file" path: it parses the textual header, unwraps the file key from
// an X25519 stanza, verifies the header HMAC, and decrypts the STREAM payload.
// Errors mirror the C2SP/CCTV age test-suite failure classes.

///|
pub suberror AgeError {
  // The header failed to parse / a stanza was structurally invalid.
  HeaderFailure(String)
  // The header parsed but no recipient stanza could be unwrapped.
  NoMatch
  // A file key was unwrapped but the header HMAC did not match.
  HmacFailure
  // The STREAM payload failed to decrypt all the way to the end.
  PayloadFailure(String)
  // A key string (bech32) was malformed.
  KeyError(String)
} derive(Debug)

// ─── X25519 identity ─────────────────────────────────────────────────────

///|
/// An X25519 recipient identity (the holder's private key).
pub(all) struct X25519Identity {
  scalar : Bytes
}

///|
/// Build an identity from a 32-byte X25519 scalar.
pub fn X25519Identity::from_bytes(b : Bytes) -> X25519Identity raise AgeError {
  if b.length() != 32 {
    raise KeyError("X25519 identity must be 32 bytes")
  }
  { scalar: b }
}

///|
/// Parse an `AGE-SECRET-KEY-1...` bech32 identity.
pub fn X25519Identity::from_bech32(s : String) -> X25519Identity raise AgeError {
  let (hrp, data) = bech32_decode(s) catch {
    e => raise KeyError("bech32: " + repr(e))
  }
  if hrp != "age-secret-key-" {
    raise KeyError("not an age secret key (hrp=" + hrp + ")")
  }
  X25519Identity::from_bytes(data)
}

// ─── base64 (standard, unpadded as used by age) ──────────────────────────

///|
fn b64_decode(s : String) -> Bytes raise AgeError {
  // age uses standard base64 with no padding; @base64.decode wants padding.
  let n = s.length()
  if n % 4 == 1 {
    raise HeaderFailure("invalid base64 length")
  }
  let buf = StringBuilder::new()
  buf.write_string(s)
  for _ in 0..<((4 - n % 4) % 4) {
    buf.write_char('=')
  }
  @base64.decode(buf.to_string()) catch {
    _ => raise HeaderFailure("invalid base64")
  }
}

// ─── header model ────────────────────────────────────────────────────────

///|
priv struct Stanza {
  args : Array[String]
  body : Bytes
}

///|
priv struct Header {
  stanzas : Array[Stanza]
  mac : Bytes // the file's header HMAC (decoded)
  mac_input : Bytes // header bytes up to and including "---"
  payload : Bytes // everything after the header (nonce || STREAM)
}

///|
fn byte_at(b : Bytes, i : Int) -> Int {
  b[i].to_int()
}

///|
// Read the line starting at `off` (bytes up to but excluding the next '\n').
// Returns (line_string, next_offset_after_newline). Raises if there is no '\n'
// (the header must be newline-terminated) or a stray '\r' appears.
fn read_line(buf : Bytes, off : Int) -> (String, Int) raise AgeError {
  let sb = StringBuilder::new()
  let mut i = off
  while i < buf.length() {
    let c = byte_at(buf, i)
    if c == 0x0a {
      return (sb.to_string(), i + 1)
    }
    if c == 0x0d {
      raise HeaderFailure("CR not allowed in header")
    }
    sb.write_char(c.to_char().unwrap())
    i = i + 1
  }
  raise HeaderFailure("unterminated header line")
}

///|
fn split_spaces(s : String) -> Array[String] {
  let out : Array[String] = []
  let cur = StringBuilder::new()
  let mut count = 0
  for c in s {
    if c == ' ' {
      out.push(cur.to_string())
      cur.reset()
      count = 0
    } else {
      cur.write_char(c)
      count = count + 1
    }
  }
  let _ = count
  out.push(cur.to_string())
  out
}

///|
fn parse_header(buf : Bytes) -> Header raise AgeError {
  // Version line.
  let (v, off0) = read_line(buf, 0)
  if v != "age-encryption.org/v1" {
    raise HeaderFailure("bad version line")
  }
  let stanzas : Array[Stanza] = []
  let mut off = off0
  for ;; {
    if off >= buf.length() {
      raise HeaderFailure("header ended before MAC line")
    }
    let (line, next) = read_line(buf, off)
    if line.length() >= 3 &&
      line.get_char(0).unwrap() == '-' &&
      line.get_char(1).unwrap() == '-' &&
      line.get_char(2).unwrap() == '-' {
      // MAC line: "--- " + base64(32-byte HMAC). mac_input = up to "---".
      let mac_input_len = off + 3
      let mac_input = Bytes::makei(mac_input_len, fn(i) { buf[i] })
      if line.length() < 5 || line.get_char(3).unwrap() != ' ' {
        raise HeaderFailure("malformed MAC line")
      }
      let mac_b64 = StringBuilder::new()
      for i = 4; i < line.length(); i = i + 1 {
        mac_b64.write_char(line.get_char(i).unwrap())
      }
      let mac = b64_decode(mac_b64.to_string())
      if mac.length() != 32 {
        raise HeaderFailure("MAC is not 32 bytes")
      }
      let payload = Bytes::makei(buf.length() - next, fn(i) { buf[next + i] })
      return { stanzas, mac, mac_input, payload }
    }
    // Stanza line: "-> " args.
    if line.length() < 3 ||
      line.get_char(0).unwrap() != '-' ||
      line.get_char(1).unwrap() != '>' ||
      line.get_char(2).unwrap() != ' ' {
      raise HeaderFailure("expected stanza or MAC line")
    }
    let rest = StringBuilder::new()
    for i = 3; i < line.length(); i = i + 1 {
      rest.write_char(line.get_char(i).unwrap())
    }
    let args = split_spaces(rest.to_string())
    if args.length() == 0 || args[0].length() == 0 {
      raise HeaderFailure("empty stanza type")
    }
    for a in args {
      if a.length() == 0 {
        raise HeaderFailure("empty stanza argument")
      }
    }
    // Body: full 64-char lines until a terminating line of < 64 chars.
    let body_b64 = StringBuilder::new()
    let mut boff = next
    for ;; {
      let (bl, bnext) = read_line(buf, boff)
      if bl.length() > 64 {
        raise HeaderFailure("stanza body line too long")
      }
      body_b64.write_string(bl)
      boff = bnext
      if bl.length() < 64 {
        break
      }
    }
    let body = b64_decode(body_b64.to_string())
    stanzas.push({ args, body })
    off = boff
  }
}

// ─── crypto helpers ──────────────────────────────────────────────────────

///|
fn hkdf_sha256(ikm : Bytes, salt : Bytes, info : Bytes, len : Int) -> Bytes {
  let prk = @hkdf.extract(@hkdf.HashAlg::Sha256, salt, ikm)
  @hkdf.expand(@hkdf.HashAlg::Sha256, prk, info, len) catch {
    _ => abort("hkdf expand")
  }
}

///|
fn ascii(s : String) -> Bytes {
  Bytes::makei(s.length(), fn(i) {
    (s.get_char(i).unwrap().to_int() & 0xff).to_byte()
  })
}

///|
fn concat3(a : Bytes, b : Bytes) -> Bytes {
  Bytes::makei(a.length() + b.length(), fn(i) {
    if i < a.length() {
      a[i]
    } else {
      b[i - a.length()]
    }
  })
}

// ─── X25519 stanza unwrap ────────────────────────────────────────────────

///|
let x25519_label : String = "age-encryption.org/v1/X25519"

///|
// Try to unwrap the file key from one X25519 stanza with one identity.
// Returns Some(file_key) on a clean unwrap, None on an authentication failure
// (try the next identity/stanza). Raises HeaderFailure for structural problems
// (wrong arg count, bad share length, low-order share, wrong file-key length).
fn try_x25519(
  stanza : Stanza,
  identity : X25519Identity,
) -> Bytes? raise AgeError {
  if stanza.args.length() != 2 {
    raise HeaderFailure("X25519 stanza must have exactly one argument")
  }
  let share = b64_decode(stanza.args[1])
  if share.length() != 32 {
    raise HeaderFailure("X25519 share must be 32 bytes")
  }
  let sk = @x25519.PrivateKey::from_bytes(identity.scalar) catch {
    e => raise KeyError(repr(e))
  }
  let pk = @x25519.PublicKey::from_bytes(share) catch {
    e => raise HeaderFailure("bad X25519 share: " + repr(e))
  }
  // Low-order share => all-zero shared secret => the spec's header failure.
  let shared = @x25519.diffie_hellman(sk, pk) catch {
    _ => raise HeaderFailure("X25519 low-order share")
  }
  let our_pub = sk.public_key().to_bytes()
  let salt = concat3(share, our_pub)
  let wrap_key = hkdf_sha256(shared.to_bytes(), salt, ascii(x25519_label), 32)
  let nonce = Bytes::makei(12, fn(_) { b'\x00' })
  let file_key = @aead.open(
    @aead.Algorithm::ChaCha20Poly1305,
    wrap_key,
    nonce,
    b"",
    stanza.body,
  ) catch {
    _ => return None
  }
  if file_key.length() != 16 {
    raise HeaderFailure("file key must be 16 bytes")
  }
  Some(file_key)
}

// ─── STREAM payload (ChaCha20-Poly1305, 64 KiB chunks) ───────────────────

///|
let chunk_size : Int = 65536

///|
fn stream_nonce(counter : Int, last : Bool) -> Bytes {
  // 11-byte big-endian counter || 1-byte last flag.
  Bytes::makei(12, fn(i) {
    if i == 11 {
      if last {
        b'\x01'
      } else {
        b'\x00'
      }
    } else {
      // counter occupies the low bytes of the 11-byte field.
      let from_end = 10 - i
      if from_end < 4 {
        ((counter >> (from_end * 8)) & 0xff).to_byte()
      } else {
        b'\x00'
      }
    }
  })
}

///|
fn stream_decrypt(file_key : Bytes, payload : Bytes) -> Bytes raise AgeError {
  if payload.length() < 16 {
    raise PayloadFailure("missing STREAM nonce")
  }
  let nonce = Bytes::makei(16, fn(i) { payload[i] })
  let key = hkdf_sha256(file_key, nonce, ascii("payload"), 32)
  let ct_len = payload.length() - 16
  if ct_len == 0 {
    raise PayloadFailure("no STREAM chunks")
  }
  let out : Array[Byte] = []
  let tag = 16
  let max_chunk = chunk_size + tag
  let mut pos = 16
  let mut counter = 0
  for ;; {
    let remaining = payload.length() - pos
    let take = if remaining < max_chunk { remaining } else { max_chunk }
    let last = pos + take >= payload.length()
    if take < tag {
      raise PayloadFailure("short STREAM chunk")
    }
    // A non-final chunk must be exactly a full chunk.
    if !last && take != max_chunk {
      raise PayloadFailure("non-final chunk not full")
    }
    let chunk = Bytes::makei(take, fn(i) { payload[pos + i] })
    let pt = @aead.open(
      @aead.Algorithm::ChaCha20Poly1305,
      key,
      stream_nonce(counter, last),
      b"",
      chunk,
    ) catch {
      _ => raise PayloadFailure("STREAM chunk authentication failed")
    }
    for i in 0..<pt.length() {
      out.push(pt[i])
    }
    pos = pos + take
    counter = counter + 1
    if last {
      break
    }
  }
  Bytes::makei(out.length(), fn(i) { out[i] })
}

// ─── top-level decrypt ───────────────────────────────────────────────────

///|
/// Decrypt an age v1 file with the given X25519 identities. Returns the
/// plaintext. Tries each X25519 stanza against each identity; on the first
/// successful unwrap it verifies the header HMAC and decrypts the payload.
/// Raises `NoMatch` if no stanza unwraps, `HmacFailure` on a bad header MAC,
/// `PayloadFailure` on a bad payload, and `HeaderFailure` on a malformed file.
pub fn decrypt(
  identities : Array[X25519Identity],
  ciphertext : Bytes,
) -> Bytes raise AgeError {
  let header = parse_header(ciphertext)
  let mut file_key : Bytes? = None
  for stanza in header.stanzas {
    if stanza.args[0] != "X25519" {
      continue
    }
    for id in identities {
      match try_x25519(stanza, id) {
        Some(fk) => {
          file_key = Some(fk)
          break
        }
        None => ()
      }
    }
    match file_key {
      Some(_) => break
      None => ()
    }
  }
  let fk = match file_key {
    Some(k) => k
    None => raise NoMatch
  }
  // Verify the header HMAC.
  let mac_key = hkdf_sha256(fk, b"", ascii("header"), 32)
  let expected = @hash.hmac_sha256(mac_key, header.mac_input)
  if !@hash.ct_eq(expected, header.mac) {
    raise HmacFailure
  }
  stream_decrypt(fk, header.payload)
}

// ─── encryption (deterministic core; caller supplies the randomness) ─────

///|
fn b64_encode(b : Bytes) -> String {
  @base64.encode(b[:], padding=false)
}

///|
/// The X25519 public key for this identity (the recipient's public key).
pub fn X25519Identity::public_key_bytes(
  self : X25519Identity,
) -> Bytes raise AgeError {
  let sk = @x25519.PrivateKey::from_bytes(self.scalar) catch {
    e => raise KeyError(repr(e))
  }
  sk.public_key().to_bytes()
}

///|
fn stream_encrypt(file_key : Bytes, nonce : Bytes, plaintext : Bytes) -> Bytes {
  let key = hkdf_sha256(file_key, nonce, ascii("payload"), 32)
  let out : Array[Byte] = []
  let n = plaintext.length()
  let mut pos = 0
  let mut counter = 0
  // Always emit at least one (possibly empty) final chunk.
  for ;; {
    let remaining = n - pos
    let take = if remaining < chunk_size { remaining } else { chunk_size }
    let last = pos + take >= n
    let pt = Bytes::makei(take, fn(i) { plaintext[pos + i] })
    let ct = @aead.seal(
      @aead.Algorithm::ChaCha20Poly1305,
      key,
      stream_nonce(counter, last),
      b"",
      pt,
    ) catch {
      _ => abort("stream seal")
    }
    for i in 0..<ct.length() {
      out.push(ct[i])
    }
    pos = pos + take
    counter = counter + 1
    if last {
      break
    }
  }
  Bytes::makei(out.length(), fn(i) { out[i] })
}

///|
/// Encrypt `plaintext` to a single X25519 recipient, producing an age v1 file.
/// The caller supplies all randomness: a 16-byte `file_key`, a 32-byte
/// `ephemeral_scalar`, and a 16-byte `payload_nonce` (each MUST come from a
/// CSPRNG and be unique per file). This deterministic core is what a
/// CSPRNG-wrapping convenience would call.
pub fn encrypt_x25519(
  recipient_pubkey : Bytes,
  plaintext : Bytes,
  file_key : Bytes,
  ephemeral_scalar : Bytes,
  payload_nonce : Bytes,
) -> Bytes raise AgeError {
  if file_key.length() != 16 {
    raise KeyError("file_key must be 16 bytes")
  }
  if payload_nonce.length() != 16 {
    raise KeyError("payload_nonce must be 16 bytes")
  }
  let eph_sk = @x25519.PrivateKey::from_bytes(ephemeral_scalar) catch {
    e => raise KeyError(repr(e))
  }
  let eph_share = eph_sk.public_key().to_bytes()
  let rpk = @x25519.PublicKey::from_bytes(recipient_pubkey) catch {
    e => raise KeyError(repr(e))
  }
  let shared = @x25519.diffie_hellman(eph_sk, rpk) catch {
    e => raise KeyError(repr(e))
  }
  let salt = concat3(eph_share, recipient_pubkey)
  let wrap_key = hkdf_sha256(shared.to_bytes(), salt, ascii(x25519_label), 32)
  let zero12 = Bytes::makei(12, fn(_) { b'\x00' })
  let body = @aead.seal(
    @aead.Algorithm::ChaCha20Poly1305,
    wrap_key,
    zero12,
    b"",
    file_key,
  ) catch {
    e => raise KeyError("wrap: " + repr(e))
  }
  let stanza = "-> X25519 " +
    b64_encode(eph_share) +
    "\n" +
    b64_encode(body) +
    "\n"
  let prefix = "age-encryption.org/v1\n" + stanza + "---"
  let prefix_bytes = ascii(prefix)
  let mac_key = hkdf_sha256(file_key, b"", ascii("header"), 32)
  let mac = @hash.hmac_sha256(mac_key, prefix_bytes)
  let mac_line = ascii(" " + b64_encode(mac) + "\n")
  let payload = concat3(
    payload_nonce,
    stream_encrypt(file_key, payload_nonce, plaintext),
  )
  concat3(concat3(prefix_bytes, mac_line), payload)
}
