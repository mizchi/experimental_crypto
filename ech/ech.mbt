// Encrypted ClientHello (ECH) — the HPKE-based protection of a TLS 1.3
// ClientHelloInner (draft-ietf-tls-esni / TLS ECH, config version 0xfe0d).
//
// This module parses an ECHConfigList, and seals / opens a payload (the encoded
// ClientHelloInner) to an ECHConfig's HPKE public key, building the ECH `info`
// (`"tls ech" || 0x00 || ECHConfig`). It uses the library's HPKE suite —
// DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305 — so it accepts
// configs whose KEM is X25519 (0x0020) offering the AEAD ChaCha20Poly1305
// (0x0003); AES-GCM HPKE AEADs are not yet wired.
//
// Assembling the outer/inner ClientHello and the ClientHelloOuterAAD is the
// caller's job; this module owns the HPKE half.

///|
pub suberror EchError {
  Truncated(String)
  Malformed(String)
  UnsupportedKem(Int)
  NoSupportedSuite
  Hpke(@hpke.HpkeError)
} derive(Debug)

///|
/// HPKE id for DHKEM(X25519, HKDF-SHA256).
pub let kem_x25519 : Int = 0x0020

///|
/// HPKE id for HKDF-SHA256.
pub let kdf_hkdf_sha256 : Int = 0x0001

///|
/// HPKE id for ChaCha20Poly1305.
pub let aead_chacha20_poly1305 : Int = 0x0003

///|
/// A parsed ECHConfig (version 0xfe0d). `raw` is the full on-wire ECHConfig
/// (version || length || contents), needed verbatim to build the HPKE `info`.
pub struct EchConfig {
  raw : Bytes
  config_id : Int
  kem_id : Int
  public_key : Bytes
  cipher_suites : Array[(Int, Int)] // (kdf_id, aead_id)
  maximum_name_length : Int
  public_name : String
}

///|
pub fn EchConfig::config_id(self : EchConfig) -> Int {
  self.config_id
}

///|
pub fn EchConfig::kem_id(self : EchConfig) -> Int {
  self.kem_id
}

///|
pub fn EchConfig::public_key(self : EchConfig) -> Bytes {
  self.public_key
}

///|
pub fn EchConfig::public_name(self : EchConfig) -> String {
  self.public_name
}

///|
pub fn EchConfig::cipher_suites(self : EchConfig) -> Array[(Int, Int)] {
  self.cipher_suites
}

///|
priv struct Reader {
  data : Bytes
  mut pos : Int
}

///|
fn Reader::u8(self : Reader, what : String) -> Int raise EchError {
  if self.pos + 1 > self.data.length() {
    raise Truncated(what)
  }
  let v = self.data[self.pos].to_int()
  self.pos += 1
  v
}

///|
fn Reader::u16(self : Reader, what : String) -> Int raise EchError {
  (self.u8(what) << 8) | self.u8(what)
}

///|
fn Reader::take(self : Reader, n : Int, what : String) -> Bytes raise EchError {
  if self.pos + n > self.data.length() {
    raise Truncated(what)
  }
  let start = self.pos
  self.pos += n
  Bytes::makei(n, fn(i) { self.data[start + i] })
}

///|
fn Reader::remaining(self : Reader) -> Int {
  self.data.length() - self.pos
}

///|
// Parse one ECHConfigContents body (already sliced to `length` bytes) given its
// version and the full raw ECHConfig bytes.
fn parse_contents(
  raw : Bytes,
  version : Int,
  body : Bytes,
) -> EchConfig raise EchError {
  if version != 0xfe0d {
    raise Malformed("unsupported ECHConfig version 0x" + version.to_string())
  }
  let r = Reader::{ data: body, pos: 0 }
  let config_id = r.u8("config_id")
  let kem_id = r.u16("kem_id")
  let pk_len = r.u16("public_key length")
  let public_key = r.take(pk_len, "public_key")
  let cs_len = r.u16("cipher_suites length")
  if cs_len % 4 != 0 {
    raise Malformed("cipher_suites length not a multiple of 4")
  }
  let cipher_suites : Array[(Int, Int)] = []
  for _i in 0..<(cs_len / 4) {
    let kdf = r.u16("kdf_id")
    let aead = r.u16("aead_id")
    cipher_suites.push((kdf, aead))
  }
  let maximum_name_length = r.u8("maximum_name_length")
  let pn_len = r.u8("public_name length")
  let pn = r.take(pn_len, "public_name")
  let public_name = String::from_array(
    Array::makei(pn.length(), fn(i) { pn[i].to_int().to_char().unwrap() }),
  )
  // extensions<0..2^16-1> — parsed for length only (none understood here).
  let ext_len = r.u16("extensions length")
  let _exts = r.take(ext_len, "extensions")
  {
    raw,
    config_id,
    kem_id,
    public_key,
    cipher_suites,
    maximum_name_length,
    public_name,
  }
}

///|
/// Parse an `ECHConfigList` (a `uint16`-length-prefixed sequence of ECHConfig).
/// Unknown-version configs are skipped (per the spec a client ignores configs
/// it can't use); a malformed structure raises.
pub fn parse_ech_config_list(data : Bytes) -> Array[EchConfig] raise EchError {
  let outer = Reader::{ data, pos: 0 }
  let list_len = outer.u16("ECHConfigList length")
  if outer.remaining() != list_len {
    raise Malformed("ECHConfigList length mismatch")
  }
  let configs : Array[EchConfig] = []
  while outer.remaining() > 0 {
    let version = outer.u16("ECHConfig version")
    let length = outer.u16("ECHConfig length")
    let body = outer.take(length, "ECHConfig contents")
    // Reconstruct the full raw ECHConfig (version || length || body) for `info`.
    let raw = Bytes::makei(4 + length, fn(i) {
      if i == 0 {
        ((version >> 8) & 0xff).to_byte()
      } else if i == 1 {
        (version & 0xff).to_byte()
      } else if i == 2 {
        ((length >> 8) & 0xff).to_byte()
      } else if i == 3 {
        (length & 0xff).to_byte()
      } else {
        body[i - 4]
      }
    })
    if version == 0xfe0d {
      configs.push(parse_contents(raw, version, body))
    }
    // else: unknown version, skip (already consumed).
  }
  configs
}

///|
/// The HPKE `info` for this config: `"tls ech" || 0x00 || ECHConfig`
/// (draft-ietf-tls-esni §6.1).
pub fn EchConfig::hpke_info(self : EchConfig) -> Bytes {
  let prefix = b"tls ech\x00"
  Bytes::makei(prefix.length() + self.raw.length(), fn(i) {
    if i < prefix.length() {
      prefix[i]
    } else {
      self.raw[i - prefix.length()]
    }
  })
}

///|
// Require X25519 KEM and an offered ChaCha20Poly1305 suite (the library's HPKE).
fn EchConfig::check_supported(self : EchConfig) -> Unit raise EchError {
  if self.kem_id != kem_x25519 {
    raise UnsupportedKem(self.kem_id)
  }
  let mut ok = false
  for cs in self.cipher_suites {
    let (kdf, aead) = cs
    if kdf == kdf_hkdf_sha256 && aead == aead_chacha20_poly1305 {
      ok = true
      break
    }
  }
  if !ok {
    raise NoSupportedSuite
  }
}

///|
/// Seal `client_hello_inner` to this ECHConfig with HPKE Mode_Base. `aad` is
/// the ClientHelloOuterAAD; `sk_e` is a fresh 32-byte X25519 ephemeral (the
/// caller sources it from a CSPRNG — reuse is catastrophic). Returns
/// `(enc, payload)` for the `encrypted_client_hello` extension.
pub fn EchConfig::seal(
  self : EchConfig,
  client_hello_inner : Bytes,
  aad : Bytes,
  sk_e : Bytes,
) -> (Bytes, Bytes) raise EchError {
  self.check_supported()
  let (enc, ctx) = @hpke.setup_base_s(self.public_key, self.hpke_info(), sk_e~) catch {
    e => raise Hpke(e)
  }
  let payload = ctx.seal(aad, client_hello_inner) catch { e => raise Hpke(e) }
  (enc, payload)
}

///|
/// Recipient side: recover the ClientHelloInner from `(enc, payload)` using the
/// server's HPKE private key `sk_r`. Raises on an AEAD/HPKE failure.
pub fn EchConfig::open(
  self : EchConfig,
  enc : Bytes,
  sk_r : Bytes,
  aad : Bytes,
  payload : Bytes,
) -> Bytes raise EchError {
  self.check_supported()
  let ctx = @hpke.setup_base_r(enc, sk_r, self.hpke_info()) catch {
    e => raise Hpke(e)
  }
  ctx.open(aad, payload) catch {
    e => raise Hpke(e)
  }
}
