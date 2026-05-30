// Proof-carrying versions of small, leaf primitives used elsewhere in the
// workspace. The goal is to anchor concrete arithmetic / bit-twiddling
// invariants in SMT, not to re-derive cryptographic theorems.
//
// To verify:
//   eval "$(opam env --switch=experimental_crypto)"
//   moon prove -p mizchi/proofs

///|
/// Smoke test: absolute value.
/// Mirrors `try_mbtp` so we can confirm the toolchain is wired correctly.
pub fn abs(
  x : Int,
) -> Int where {
  proof_ensure: result => result >= 0,
  proof_ensure: result => result == x || result == -x,
} {
  if x >= 0 {
    x
  } else {
    -x
  }
}

///|
/// Non-negative modular reduction. Returned value always falls in `[0, m)`,
/// regardless of the sign of `a`. Used pervasively in field arithmetic where
/// `Int` % may return a negative remainder.
pub fn mod_pos(
  a : Int,
  m : Int,
) -> Int where {
  proof_require: m > 0,
  proof_ensure: result => 0 <= result,
  proof_ensure: result => result < m,
} {
  let r = a % m
  if r < 0 {
    r + m
  } else {
    r
  }
}

///|
/// Hex character → 4-bit value. Caller must guarantee a valid hex digit
/// (`0..9` / `a..f` / `A..F`); the postcondition is that the result is a
/// well-formed nibble.
pub fn hex_value(
  c : Int,
) -> Int where {
  proof_require: (0x30 <= c && c <= 0x39) ||
  (0x61 <= c && c <= 0x66) ||
  (0x41 <= c && c <= 0x46),
  proof_ensure: result => 0 <= result,
  proof_ensure: result => result < 16,
} {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else {
    c - 0x41 + 10
  }
}

///|
/// Constant-time conditional select using arithmetic only.
/// The mask must be `0` (false) or `1` (true). The result is `a` when
/// `mask == 1` and `b` when `mask == 0`, computed without branching on
/// `mask`. This is the building block underneath constant-time scalar
/// multiplication in P-256, P-384, secp256k1, and ed25519's planned
/// const-time field-arithmetic rewrite.
///
/// The bitmask form `(mask & a) | (~mask & b)` cannot be verified at
/// present because `moon prove` does not yet lower `&` / `|` / `lnot`
/// to a bitvector theory; the arithmetic form below proves trivially in
/// Z3's linear-integer fragment.
pub fn ct_select(
  mask : Int,
  a : Int,
  b : Int,
) -> Int where {
  proof_require: mask == 0 || mask == 1,
  proof_ensure: result => mask == 1 || result == b,
  proof_ensure: result => mask == 0 || result == a,
} {
  b + mask * (a - b)
}

///|
/// Single-step modular reduction. Given an input known to be in `[0, 2*m)`,
/// returns the canonical residue in `[0, m)` with at most one subtraction.
/// This is the `freeze` / `final-reduce` primitive that closes the carry
/// chain in every field-arithmetic backend (P-256, P-384, secp256k1,
/// x25519 10-limb, ed25519 planned const-time port).
pub fn reduce_once(
  a : Int,
  m : Int,
) -> Int where {
  proof_require: m > 0,
  proof_require: 0 <= a,
  proof_require: a < 2 * m,
  proof_ensure: result => 0 <= result,
  proof_ensure: result => result < m,
  proof_ensure: result => result == a || result == a - m,
} {
  if a >= m {
    a - m
  } else {
    a
  }
}
