// Proof-carrying base64url length helper for `mizchi/jwt`.
//
// JWT / JWS / JWE / JWK / WebAuthn all rely on RFC 4648 §5 base64url
// without padding (RFC 7515 §C: "Padding ('=') characters are not
// generated when emitted as JSON, and not allowed when consumed.").
// The output character count for `n` input bytes is `ceil(4n/3)`, which
// the closed form `(4n + 2) / 3` evaluates with integer division.
//
// Pinning this helper anchors scratch-buffer sizing in `jwt.encode` and
// boundary-length checks in `jwt.decode_segment`, both of which would
// otherwise drift between callers if base64url were re-implemented in
// terms of the padded variant `4*ceil(n/3)`.

///|
/// Number of base64url characters needed to encode `input_bytes` bytes
/// without trailing '=' padding. Equivalent to `ceil(4 * input_bytes / 3)`.
///
/// Cap on `input_bytes` keeps `input_bytes * 4 + 2` within 32-bit `Int`:
/// `Int.max = 2^31 - 1`, so `input_bytes ≤ (Int.max - 2) / 4 = 536870911`
/// (~ 512 MiB), which is far above any realistic JWT segment payload.
pub fn base64url_unpadded_len(
  input_bytes : Int,
) -> Int where {
  proof_require: 0 <= input_bytes,
  proof_require: input_bytes <= 536870911,
  proof_ensure: result => result >= 0,
  proof_ensure: result => 3 * result >= 4 * input_bytes,
  proof_ensure: result => 3 * result < 4 * input_bytes + 3,
  proof_ensure: result => input_bytes == 0 || result >= 2,
} {
  (input_bytes * 4 + 2) / 3
}
