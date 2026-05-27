// Proof-carrying mnemonic-length helper for `mizchi/bip39`.
//
// BIP-39 §3 fixes five supported entropy strengths:
//   128 / 160 / 192 / 224 / 256 bits.
// The mnemonic appends a checksum of `ent_bits / 32` bits and splits the
// concatenated bit-stream into 11-bit groups. The resulting word counts
// are 12 / 15 / 18 / 21 / 24, respectively.
//
// The arithmetic identity `(ent_bits + ent_bits / 32) / 11` is awkward for
// pure linear-integer SMT because it nests two `div`s. Rather than push
// the divisions through axiomatic lemmas, the proof here enumerates the
// finite supported domain (the `proof_require` `or`-chain) so the SMT
// solver discharges each of the five cases by direct evaluation.

///|
/// BIP-39 §3 mnemonic word count for the requested entropy strength.
/// Domain is restricted to the five RFC-supported entropy bit-widths.
pub fn mnemonic_word_count(
  ent_bits : Int,
) -> Int where {
  proof_require: ent_bits == 128 || ent_bits == 160 || ent_bits == 192 || ent_bits == 224 || ent_bits == 256,
  proof_ensure: result => 12 <= result,
  proof_ensure: result => result <= 24,
  proof_ensure: result => ent_bits != 128 || result == 12,
  proof_ensure: result => ent_bits != 160 || result == 15,
  proof_ensure: result => ent_bits != 192 || result == 18,
  proof_ensure: result => ent_bits != 224 || result == 21,
  proof_ensure: result => ent_bits != 256 || result == 24,
} {
  (ent_bits + ent_bits / 32) / 11
}
