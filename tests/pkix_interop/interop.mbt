// X.509 chain-validation interop shim.
//
// openssl mints a root -> intermediate -> leaf chain (see driver.mjs); this
// shim hands it to MoonBit `pkix_verify` and reports the verdict, exercising
// the intermediate-handling path (signature linkage, validity, basic
// constraints / pathlen, anchor linkage, dNSName SAN) against a reference CA.
//
// Return codes (kept flat for the JS boundary):
//   1 = chain trusted to the anchor AND hostname matches a leaf SAN
//   0 = chain not trusted (bad signature, expired, broken linkage, ...)
//   2 = a certificate failed to parse
//   3 = chain trusted but hostname does not match any leaf dNSName SAN

///|
fn unpack(b : Bytes) -> Array[Bytes] {
  let out : Array[Bytes] = []
  let mut o = 0
  while o + 4 <= b.length() {
    let n = (b[o].to_int() << 24) |
      (b[o + 1].to_int() << 16) |
      (b[o + 2].to_int() << 8) |
      b[o + 3].to_int()
    o = o + 4
    let start = o
    out.push(Bytes::makei(n, fn(i) { b[start + i] }))
    o = o + n
  }
  out
}

///|
/// Validate `leaf` (+ packed `intermediates`) up to `anchor_der` at `now`
/// (GeneralizedTime), then check `hostname` against the leaf's dNSName SANs.
pub fn verify_chain(
  leaf_der : Bytes,
  intermediates_packed : Bytes,
  anchor_der : Bytes,
  now : String,
  hostname : String,
) -> Int {
  let leaf = @pkix.parse_certificate(leaf_der) catch { _ => return 2 }
  let anchor = @pkix.parse_certificate(anchor_der) catch { _ => return 2 }
  let intermediates : Array[@pkix.Certificate] = []
  for der in unpack(intermediates_packed) {
    intermediates.push(@pkix.parse_certificate(der) catch { _ => return 2 })
  }
  @pkix_verify.verify_chain_with_anchor_cert(leaf, intermediates, anchor, now) catch {
    _ => return 0
  }
  let sans = @pkix_verify.extract_dns_san(leaf) catch { _ => return 0 }
  for s in sans {
    if s == hostname {
      return 1
    }
  }
  3
}
