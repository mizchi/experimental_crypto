// Proof-carrying hardened-index detection helper for `mizchi/bip32`.
//
// BIP-32 §3 splits the 32-bit child-index space at `0x80000000`. Indices in
// `[0, 2^31)` are *normal* and derive through CKDpub-compatible elliptic
// curve arithmetic; indices in `[2^31, 2^32)` are *hardened* and require
// the parent private key. The hardened bit is therefore the MSB of the
// big-endian serialized index `ser32(i)` (BIP-32 §5).
//
// MoonBit's `Int` is 32-bit signed, so `0x80000000` itself is not a legal
// `Int` literal here. We anchor the BIP-32 split on the MSB *byte* of the
// serialized index instead: `ser32(i)[0] >= 0x80` iff `i` is hardened.
// This is the form CKDpriv consumes on the wire and the one that matters
// for the security-relevant dispatch (hardened → secret-key-only path,
// non-hardened → public-key-allowed path).
//
// Returns 1 for hardened, 0 for normal. Bool would be more natural but the
// current `moon prove` lowering keeps every leaf wrap on `Int` so the Why3
// frontend stays in the linear-integer fragment.

///|
/// BIP-32 §3 hardened-index threshold in the MSB byte of `ser32(i)`.
/// `0x80` corresponds to `i = 2^31` once the byte is shifted into bits
/// 24..31 of the 32-bit big-endian index.
pub let bip32_hardened_msb : Int = 128

///|
/// Decide whether a child index is hardened, given the high byte of its
/// big-endian serialization. Returns 1 for hardened, 0 for normal.
///
/// Anchors the BIP-32 §3 dispatch invariant: every `ser32(i)[0] >= 0x80`
/// input must take the secret-key derivation path and every
/// `ser32(i)[0] < 0x80` input must take the public-key derivation path.
pub fn is_hardened_from_msb(
  msb : Int,
) -> Int where {
  proof_require: 0 <= msb,
  proof_require: msb <= 255,
  proof_ensure: result => result == 0 || result == 1,
  proof_ensure: result => msb >= 128 || result == 0,
  proof_ensure: result => msb < 128 || result == 1,
} {
  if msb >= 128 {
    1
  } else {
    0
  }
}
