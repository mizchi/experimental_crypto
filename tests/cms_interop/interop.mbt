// CMS / PKCS#7 SignedData interop shim.
//
// openssl `cms -sign` produces a detached SignedData (see driver.mjs); this
// shim parses it and verifies the detached signature over the message with
// MoonBit `cms`, using the signer certificate embedded in the bundle.

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
/// Verify a detached CMS SignedData (DER, hex) over `message_hex`.
/// Returns 1 valid / 0 invalid / 2 parse error.
pub fn cms_verify(sd_der_hex : String, message_hex : String) -> Int {
  let sd = @cms.parse_signed_data(from_hex(sd_der_hex)) catch { _ => return 2 }
  let ok = @cms.verify_detached(sd, from_hex(message_hex)) catch {
    _ => return 0
  }
  if ok {
    1
  } else {
    0
  }
}
