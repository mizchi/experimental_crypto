// BIP-39 mnemonic phrase encoding/decoding and seed derivation.
//
// Spec: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
//
// Scope:
//   - English wordlist only (2048 words; see `wordlist.mbt`).
//   - entropy ↔ mnemonic round-trip (12 / 15 / 18 / 21 / 24 words).
//   - mnemonic → seed (PBKDF2-HMAC-SHA512, 2048 iters, 64-byte output).
//
// Out of scope: language tables other than English, mnemonic normalisation
// (NFKD) for non-ASCII passphrases, key stretching parameter tweaks.
//
// PBKDF2-HMAC-SHA512 is self-implemented here rather than in @pbkdf2 because
// @pbkdf2 today only wires SHA-256 (UnsupportedHash for the other variants);
// rather than rewrite that module's tightly-tuned compression-state reuse
// for the SHA-512 case, this uses the generic HMAC-SHA-512 in @hash.

///|
pub suberror Bip39Error {
  InvalidEntropyLength(Int)
  InvalidMnemonicWordCount(Int)
  UnknownWord(String)
  InvalidChecksum
} derive(Show)

///|
fn entropy_bits_to_word_count(ent_bits : Int) -> Int {
  // ent_bits + checksum (ent_bits/32) bits split into 11-bit groups.
  (ent_bits + ent_bits / 32) / 11
}

///|
fn is_supported_entropy_bytes(n : Int) -> Bool {
  // BIP-39 §Generating the mnemonic: ENT ∈ {128, 160, 192, 224, 256}.
  n == 16 || n == 20 || n == 24 || n == 28 || n == 32
}

///|
/// Convert raw entropy (16/20/24/28/32 bytes) into a BIP-39 mnemonic phrase
/// using the English wordlist. Returns the words joined by single ASCII
/// spaces.
pub fn entropy_to_mnemonic(entropy : Bytes) -> String raise Bip39Error {
  let ent_len = entropy.length()
  if !is_supported_entropy_bytes(ent_len) {
    raise InvalidEntropyLength(ent_len)
  }
  let ent_bits = ent_len * 8
  let word_count = entropy_bits_to_word_count(ent_bits)

  // Build a (ENT||CS) bit buffer. We extract 11-bit groups by walking bits.
  // total_bits = ent_bits + cs_bits, which divides cleanly by 11.
  let cs_byte = @hash.sha256(entropy)[0].to_int()
  // We treat the (ent_bits + cs_bits) stream as an array of bits indexed
  // from MSB of byte 0. Helper below pulls bit i.
  fn get_bit(i : Int) -> Int {
    if i < ent_bits {
      let byte = entropy[i / 8].to_int()
      (byte >> (7 - i % 8)) & 1
    } else {
      let j = i - ent_bits
      // cs_bits ∈ {4,5,6,7,8}, all live in the high bits of cs_byte
      (cs_byte >> (7 - j)) & 1
    }
  }

  let words = FixedArray::make(word_count, "")
  for w = 0; w < word_count; w = w + 1 {
    let mut idx = 0
    for b = 0; b < 11; b = b + 1 {
      idx = (idx << 1) | get_bit(w * 11 + b)
    }
    words[w] = english_wordlist[idx]
  }

  // Join with single ASCII spaces.
  let mut out = words[0]
  for i = 1; i < word_count; i = i + 1 {
    out = out + " " + words[i]
  }
  out
}

///|
/// Decode a BIP-39 mnemonic phrase (English wordlist) back to its raw
/// entropy. Validates the embedded checksum and rejects unknown words.
pub fn mnemonic_to_entropy(mnemonic : String) -> Bytes raise Bip39Error {
  let words = split_ascii_words(mnemonic)
  let word_count = words.length()
  if !(word_count == 12 ||
    word_count == 15 ||
    word_count == 18 ||
    word_count == 21 ||
    word_count == 24) {
    raise InvalidMnemonicWordCount(word_count)
  }
  let total_bits = word_count * 11
  let ent_bits = total_bits * 32 / 33
  let cs_bits = total_bits - ent_bits
  let ent_len = ent_bits / 8

  // Walk each word, look up its 11-bit index, append bits to a flat buffer.
  // We accumulate into a FixedArray[Int] of bits (0 or 1), then re-pack.
  let bits = FixedArray::make(total_bits, 0)
  for i = 0; i < word_count; i = i + 1 {
    let idx = lookup_word(words[i])
    for b = 0; b < 11; b = b + 1 {
      bits[i * 11 + b] = (idx >> (10 - b)) & 1
    }
  }

  // Pack ent_bits into ent_len bytes.
  let ent_buf = FixedArray::make(ent_len, b'\x00')
  for i = 0; i < ent_bits; i = i + 1 {
    if bits[i] == 1 {
      let byte = ent_buf[i / 8].to_int()
      ent_buf[i / 8] = (byte | (1 << (7 - i % 8))).to_byte()
    }
  }
  let entropy = Bytes::makei(ent_len, fn(j) { ent_buf[j] })

  // Recompute checksum and compare against the trailing cs_bits.
  let expected_cs_byte = @hash.sha256(entropy)[0].to_int()
  for j = 0; j < cs_bits; j = j + 1 {
    let bit = (expected_cs_byte >> (7 - j)) & 1
    if bits[ent_bits + j] != bit {
      raise InvalidChecksum
    }
  }
  entropy
}

///|
/// Derive a 64-byte seed from a mnemonic + optional passphrase.
///
/// BIP-39 §From mnemonic to seed: PBKDF2(HMAC-SHA512, password=mnemonic,
/// salt="mnemonic"+passphrase, iterations=2048, dkLen=64).
///
/// `mnemonic` is used verbatim as the password (no NFKD normalisation —
/// works for ASCII English mnemonics, which are the only ones we encode).
/// `passphrase` likewise. Callers handling non-ASCII passphrases need to
/// pre-normalise.
pub fn mnemonic_to_seed(mnemonic : String, passphrase? : String = "") -> Bytes {
  let password = string_to_utf8(mnemonic)
  let salt = string_to_utf8("mnemonic" + passphrase)
  pbkdf2_hmac_sha512(password, salt, 2048, 64)
}

// ─── word lookup ─────────────────────────────────────────────────────────

///|
fn lookup_word(word : String) -> Int raise Bip39Error {
  // Linear scan, 2048 entries, plenty fast for the 12-24 word checks we do.
  for i = 0; i < english_wordlist.length(); i = i + 1 {
    if english_wordlist[i] == word {
      return i
    }
  }
  raise UnknownWord(word)
}

///|
// Splits a String on runs of ASCII whitespace (space / tab / newline).
// Empty runs (consecutive separators, leading/trailing whitespace) are
// dropped so callers can be slightly sloppy with formatting.
fn split_ascii_words(s : String) -> Array[String] {
  let out : Array[String] = []
  let mut buf = ""
  for ch in s {
    let c = ch.to_int()
    if c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d {
      if buf != "" {
        out.push(buf)
        buf = ""
      }
    } else {
      buf = buf + ch.to_string()
    }
  }
  if buf != "" {
    out.push(buf)
  }
  out
}

///|
// UTF-8 encode a String. The BIP-39 wordlist is ASCII so for mnemonics this
// is a pure byte-cast; the passphrase path needs real UTF-8 for non-ASCII
// inputs.
fn string_to_utf8(s : String) -> Bytes {
  let out : Array[Byte] = []
  for ch in s {
    let cp = ch.to_int()
    if cp < 0x80 {
      out.push(cp.to_byte())
    } else if cp < 0x800 {
      out.push((0xc0 | (cp >> 6)).to_byte())
      out.push((0x80 | (cp & 0x3f)).to_byte())
    } else if cp < 0x10000 {
      out.push((0xe0 | (cp >> 12)).to_byte())
      out.push((0x80 | ((cp >> 6) & 0x3f)).to_byte())
      out.push((0x80 | (cp & 0x3f)).to_byte())
    } else {
      out.push((0xf0 | (cp >> 18)).to_byte())
      out.push((0x80 | ((cp >> 12) & 0x3f)).to_byte())
      out.push((0x80 | ((cp >> 6) & 0x3f)).to_byte())
      out.push((0x80 | (cp & 0x3f)).to_byte())
    }
  }
  Bytes::makei(out.length(), fn(j) { out[j] })
}

// ─── PBKDF2-HMAC-SHA-512 (RFC 8018) ──────────────────────────────────────

///|
// Compact PBKDF2-HMAC-SHA-512. Output length is exactly `dk_len` bytes;
// SHA-512's output (64 bytes) is the natural block, and BIP-39 only ever
// asks for a single 64-byte block (dk_len=64, 2048 iters) so the outer
// blocks loop is degenerate but kept for generality.
fn pbkdf2_hmac_sha512(
  password : Bytes,
  salt : Bytes,
  iterations : Int,
  dk_len : Int,
) -> Bytes {
  let h_len = 64
  let num_blocks = (dk_len + h_len - 1) / h_len
  let out = FixedArray::make(num_blocks * h_len, b'\x00')
  let salt_len = salt.length()
  let salted_int = FixedArray::make(salt_len + 4, b'\x00')
  for i = 0; i < salt_len; i = i + 1 {
    salted_int[i] = salt[i]
  }
  for blk = 1; blk <= num_blocks; blk = blk + 1 {
    salted_int[salt_len] = ((blk >> 24) & 0xff).to_byte()
    salted_int[salt_len + 1] = ((blk >> 16) & 0xff).to_byte()
    salted_int[salt_len + 2] = ((blk >> 8) & 0xff).to_byte()
    salted_int[salt_len + 3] = (blk & 0xff).to_byte()
    let salted = Bytes::makei(salt_len + 4, fn(j) { salted_int[j] })
    let mut u = @hash.hmac_sha512(password, salted)
    let t = FixedArray::make(h_len, b'\x00')
    for i = 0; i < h_len; i = i + 1 {
      t[i] = u[i]
    }
    for _ in 1..<iterations {
      u = @hash.hmac_sha512(password, u)
      for i = 0; i < h_len; i = i + 1 {
        t[i] = (t[i].to_int() ^ u[i].to_int()).to_byte()
      }
    }
    let base = (blk - 1) * h_len
    for i = 0; i < h_len; i = i + 1 {
      out[base + i] = t[i]
    }
  }
  Bytes::makei(dk_len, fn(j) { out[j] })
}
