// Proof-carrying packet-length-encoding helper for `mizchi/pgp`.
//
// OpenPGP new-format packets (RFC 9580 §4.2.1) encode the body length in
// 1, 2, or 5 octets depending on the value:
//
//   body_len < 192        → 1 octet  (value verbatim)
//   192 ≤ body_len < 8384 → 2 octets (192 + ((b0-192)<<8) + b1)
//   body_len ≥ 8384       → 5 octets (0xFF || 4 BE bytes)
//
// (Partial-length packets and old-format length-type fields are handled
// elsewhere — this helper covers the deterministic full-length case the
// encoder emits.)
//
// Pinning the byte count anchors the encoder's scratch-buffer sizing
// before serialising a packet header, sister to `asn1/wrap`'s
// `der_length_prefix_size`.

///|
/// Number of octets `write_packet_length` emits for a given body length
/// in OpenPGP new-format. Result is always 1, 2, or 5.
pub fn pgp_packet_length_octets(
  body_len : Int,
) -> Int where {
  proof_require: pgp_packet_length_valid(body_len),
  proof_ensure: result => result == pgp_packet_length_octets_logic(body_len),
} {
  if body_len < 192 {
    1
  } else if body_len < 8384 {
    2
  } else {
    5
  }
}
