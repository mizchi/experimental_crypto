// OpenPGP verify interop shim (reverse direction).
//
// The repo's pgp/gpg_interop.sh proves gpg verifies MoonBit-produced PGP
// signatures; this shim proves the opposite — that MoonBit `pgp.verify_armor`
// accepts signatures GnuPG produced. The Node driver drives real `gpg` for
// Ed25519 / RSA / ECDSA keys and checks valid + tampered cases.

///|
fn hexval(c : Char) -> Int {
  let v = c.to_int()
  if v >= '0'.to_int() && v <= '9'.to_int() {
    v - '0'.to_int()
  } else if v >= 'a'.to_int() && v <= 'f'.to_int() {
    v - 'a'.to_int() + 10
  } else if v >= 'A'.to_int() && v <= 'F'.to_int() {
    v - 'A'.to_int() + 10
  } else {
    abort("non-hex char")
  }
}

///|
fn from_hex(s : String) -> Bytes {
  let n = s.length() / 2
  Bytes::makei(n, fn(i) {
    ((hexval(s.get_char(i * 2).unwrap()) << 4) |
    hexval(s.get_char(i * 2 + 1).unwrap())).to_byte()
  })
}

///|
/// Verify a detached PGP signature armor over `message_hex` under the public
/// key in `pubkey_armor`. Returns 1 valid / 0 invalid / 2 key parse error.
pub fn pgp_verify(
  pubkey_armor : String,
  message_hex : String,
  sig_armor : String,
) -> Int {
  let pk = @pgp.parse_pubkey_armor(pubkey_armor) catch { _ => return 2 }
  let ok = @pgp.verify_armor(sig_armor, from_hex(message_hex), pk.key) catch {
    _ => return 0
  }
  if ok {
    1
  } else {
    0
  }
}
