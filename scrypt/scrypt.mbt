// RFC 7914 scrypt key derivation: PBKDF2-HMAC-SHA256 + ROMix + BlockMix +
// Salsa20/8. Memory-hard by construction; N=2^log_n controls the cost.

///|
pub(all) struct Params {
  log_n : Int // log2(N), 14..30 typical. N = 2^log_n
  r : Int // block size factor. usually 8
  p : Int // parallelization factor. usually 1
  dk_len : Int // derived key length in bytes
} derive(Eq, Debug)

///|
/// Interactive baseline: log_n=15, r=8, p=1, dk_len=32.
pub fn Params::recommended_interactive() -> Params {
  { log_n: 15, r: 8, p: 1, dk_len: 32 }
}

///|
/// Sensitive baseline: log_n=20, r=8, p=1, dk_len=32.
pub fn Params::recommended_sensitive() -> Params {
  { log_n: 20, r: 8, p: 1, dk_len: 32 }
}

///|
pub suberror ScryptError {
  InvalidParams(String)
  Pbkdf2Failure
  InvalidEncoded(String)
  VerifyFailed
} derive(Debug)

///|
/// Derives a key of `params.dk_len` bytes from `password` and `salt` using
/// scrypt as specified in RFC 7914.
pub fn derive_key(
  params : Params,
  password : Bytes,
  salt : Bytes,
) -> Bytes raise ScryptError {
  validate_params(params)
  let n = 1 << params.log_n
  let r = params.r
  let p = params.p
  let dk_len = params.dk_len
  let block_size = 128 * r // bytes per ROMix block
  let words_per_block = 32 * r // 32r UInt32 words per ROMix block

  // Step 1: B = PBKDF2-HMAC-SHA256(password, salt, 1, p * 128 * r)
  let b_total = pbkdf2_call(password, salt, 1, p * block_size)

  // Step 2: for each of the p blocks, run ROMix in place.
  // Unpack bytes → words once; pack back once at the end.
  let block_words = FixedArray::make(p * words_per_block, 0U)
  bytes_to_words(b_total, 0, block_words, 0, p * words_per_block)
  for i in 0..<p {
    romix_words(block_words, i * words_per_block, n, r)
  }
  // Step 3: DK = PBKDF2-HMAC-SHA256(password, B, 1, dk_len)
  let new_salt = Bytes::makei(p * block_size, fn(i) {
    let w = block_words[i >> 2]
    ((w >> ((i & 3) * 8)) & 0xFFU).to_byte()
  })
  pbkdf2_call(password, new_salt, 1, dk_len)
}

///|
/// Little-endian byte→UInt32 unpack. Reads `n_words * 4` bytes starting at
/// `src_off` and writes `n_words` UInt32 starting at `dst_off`.
fn bytes_to_words(
  src : Bytes,
  src_off : Int,
  dst : FixedArray[UInt],
  dst_off : Int,
  n_words : Int,
) -> Unit {
  for i in 0..<n_words {
    let off = src_off + i * 4
    dst[dst_off + i] = src[off].to_uint() |
      (src[off + 1].to_uint() << 8) |
      (src[off + 2].to_uint() << 16) |
      (src[off + 3].to_uint() << 24)
  }
}

///|
fn validate_params(params : Params) -> Unit raise ScryptError {
  if params.log_n < 1 || params.log_n > 24 {
    // Default safety cap at log_n = 24 -> N = 2^24, which with r=8 needs
    // 16 GiB of scratch. Anything larger is almost certainly attacker-
    // supplied via verify_encoded. Loosen explicitly per-call if you
    // actually need it.
    raise InvalidParams("log_n out of range (1..24)")
  }
  if params.r < 1 || params.r > 32 {
    raise InvalidParams("r out of range (1..32)")
  }
  if params.p < 1 || params.p > 16 {
    raise InvalidParams("p out of range (1..16)")
  }
  if params.dk_len < 1 || params.dk_len > 1024 {
    raise InvalidParams("dk_len out of range (1..1024)")
  }
  // Even within the per-field caps above, the combined V-buffer size is
  //   n * (32 * r) words = (1 << log_n) * 32 * r u32
  // which at the worst legal combination (log_n=24, r=32) is 2^34 u32 =
  // 64 GiB. That overflows Int (the FixedArray index space) long before
  // we hit OOM. Reject on UInt64 to avoid the wrap.
  let n_words : UInt64 = (1UL << params.log_n) * 32UL * params.r.to_uint64()
  let max_int_words : UInt64 = 0x7FFF_FFFFUL // Int::max_value
  if n_words > max_int_words {
    raise InvalidParams("log_n * r combination overflows Int index space")
  }
}

///|
fn pbkdf2_call(
  password : Bytes,
  salt : Bytes,
  iterations : Int,
  dk_len : Int,
) -> Bytes raise ScryptError {
  @pbkdf2.pbkdf2(Sha256, password, salt, iterations, dk_len) catch {
    _ => raise Pbkdf2Failure
  }
}

// ─── ROMix (word-based) ──────────────────────────────────────────────────

///|
/// ROMix over word-based block. Operates in-place on the slice of
/// `block_words` starting at `block_off` of length `32 * r` UInt32.
fn romix_words(
  block_words : FixedArray[UInt],
  block_off : Int,
  n : Int,
  r : Int,
) -> Unit {
  let words = 32 * r // 32r UInt32 = 128r bytes
  // Allocate V as a single flat n × 32r UInt32 buffer (4 bytes per word).
  let v = FixedArray::make(n * words, 0U)
  let x = FixedArray::make(words, 0U)
  let y = FixedArray::make(words, 0U)
  for i in 0..<words {
    x[i] = block_words[block_off + i]
  }
  // V[i] = X; X = BlockMix(X)
  for i in 0..<n {
    let off = i * words
    for j in 0..<words {
      v[off + j] = x[j]
    }
    block_mix_words(x, y, r)
    // x and y swap roles: after BlockMix, output is in y → copy to x for next iter
    for j in 0..<words {
      x[j] = y[j]
    }
  }
  // for N iterations: j = Integerify(X) mod N; X = BlockMix(X XOR V[j])
  for _ in 0..<n {
    // Integerify: low 64 bits of the last 64-byte block. We only need mod N
    // (n is a power of 2 in our range), but use the same general formula.
    // Last 64-byte block sits at words[(2r - 1) * 16 ..= (2r - 1) * 16 + 15].
    let last_off = (2 * r - 1) * 16
    let lo = x[last_off].to_uint64()
    let hi = x[last_off + 1].to_uint64()
    let j_full = (hi << 32) | lo
    let j_idx = (j_full % n.to_uint64()).to_int()
    let v_off = j_idx * words
    for k in 0..<words {
      x[k] = x[k] ^ v[v_off + k]
    }
    block_mix_words(x, y, r)
    for k in 0..<words {
      x[k] = y[k]
    }
  }
  // Write back.
  for i in 0..<words {
    block_words[block_off + i] = x[i]
  }
}

// ─── BlockMix (word-based) ───────────────────────────────────────────────

///|
/// BlockMix specified by RFC 7914 over UInt32 words. Reads `in_words` of
/// length `32r`, writes the result into `out_words` (same length).
fn block_mix_words(
  in_words : FixedArray[UInt],
  out_words : FixedArray[UInt],
  r : Int,
) -> Unit {
  // B is 2r blocks of 16 words (64 bytes) each.
  let block_count = 2 * r
  // X = B[2r-1] (last 16-word block).
  let x = FixedArray::make(16, 0U)
  let last_off = (block_count - 1) * 16
  for k in 0..<16 {
    x[k] = in_words[last_off + k]
  }
  // For i in 0..2r: X = Salsa(X XOR B[i]); Y[i] = X
  // Reorder mapping at write time: Y[0],Y[2],...,Y[2r-2],Y[1],Y[3],...,Y[2r-1]
  // Index mapping: for input block i, output position is
  //   if i even -> (i/2)
  //   if i odd  -> r + (i-1)/2
  for i in 0..<block_count {
    let in_off = i * 16
    for k in 0..<16 {
      x[k] = x[k] ^ in_words[in_off + k]
    }
    salsa20_8_words(x)
    let out_idx = if (i & 1) == 0 { i >> 1 } else { r + (i >> 1) }
    let out_off = out_idx * 16
    for k in 0..<16 {
      out_words[out_off + k] = x[k]
    }
  }
}

// ─── Salsa20/8 core (in-place, word-based) ───────────────────────────────

///|
/// Salsa20/8 over 16 UInt32 words, in place. Mutates `x`.
fn salsa20_8_words(x : FixedArray[UInt]) -> Unit {
  let x0 = x[0]
  let x1 = x[1]
  let x2 = x[2]
  let x3 = x[3]
  let x4 = x[4]
  let x5 = x[5]
  let x6 = x[6]
  let x7 = x[7]
  let x8 = x[8]
  let x9 = x[9]
  let x10 = x[10]
  let x11 = x[11]
  let x12 = x[12]
  let x13 = x[13]
  let x14 = x[14]
  let x15 = x[15]
  let mut v0 = x0
  let mut v1 = x1
  let mut v2 = x2
  let mut v3 = x3
  let mut v4 = x4
  let mut v5 = x5
  let mut v6 = x6
  let mut v7 = x7
  let mut v8 = x8
  let mut v9 = x9
  let mut v10 = x10
  let mut v11 = x11
  let mut v12 = x12
  let mut v13 = x13
  let mut v14 = x14
  let mut v15 = x15
  for _ in 0..<4 {
    // Column round
    v4 = v4 ^ rotl(v0 + v12, 7)
    v8 = v8 ^ rotl(v4 + v0, 9)
    v12 = v12 ^ rotl(v8 + v4, 13)
    v0 = v0 ^ rotl(v12 + v8, 18)
    v9 = v9 ^ rotl(v5 + v1, 7)
    v13 = v13 ^ rotl(v9 + v5, 9)
    v1 = v1 ^ rotl(v13 + v9, 13)
    v5 = v5 ^ rotl(v1 + v13, 18)
    v14 = v14 ^ rotl(v10 + v6, 7)
    v2 = v2 ^ rotl(v14 + v10, 9)
    v6 = v6 ^ rotl(v2 + v14, 13)
    v10 = v10 ^ rotl(v6 + v2, 18)
    v3 = v3 ^ rotl(v15 + v11, 7)
    v7 = v7 ^ rotl(v3 + v15, 9)
    v11 = v11 ^ rotl(v7 + v3, 13)
    v15 = v15 ^ rotl(v11 + v7, 18)
    // Row round
    v1 = v1 ^ rotl(v0 + v3, 7)
    v2 = v2 ^ rotl(v1 + v0, 9)
    v3 = v3 ^ rotl(v2 + v1, 13)
    v0 = v0 ^ rotl(v3 + v2, 18)
    v6 = v6 ^ rotl(v5 + v4, 7)
    v7 = v7 ^ rotl(v6 + v5, 9)
    v4 = v4 ^ rotl(v7 + v6, 13)
    v5 = v5 ^ rotl(v4 + v7, 18)
    v11 = v11 ^ rotl(v10 + v9, 7)
    v8 = v8 ^ rotl(v11 + v10, 9)
    v9 = v9 ^ rotl(v8 + v11, 13)
    v10 = v10 ^ rotl(v9 + v8, 18)
    v12 = v12 ^ rotl(v15 + v14, 7)
    v13 = v13 ^ rotl(v12 + v15, 9)
    v14 = v14 ^ rotl(v13 + v12, 13)
    v15 = v15 ^ rotl(v14 + v13, 18)
  }
  x[0] = v0 + x0
  x[1] = v1 + x1
  x[2] = v2 + x2
  x[3] = v3 + x3
  x[4] = v4 + x4
  x[5] = v5 + x5
  x[6] = v6 + x6
  x[7] = v7 + x7
  x[8] = v8 + x8
  x[9] = v9 + x9
  x[10] = v10 + x10
  x[11] = v11 + x11
  x[12] = v12 + x12
  x[13] = v13 + x13
  x[14] = v14 + x14
  x[15] = v15 + x15
}

///|
fn rotl(v : UInt, n : Int) -> UInt {
  (v << n) | (v >> (32 - n))
}

// ─── PHC string format encoder / decoder ─────────────────────────────────

///|
/// Computes a PHC-encoded scrypt hash string of the form
/// `$scrypt$ln=<log_n>,r=<r>,p=<p>$<salt>$<hash>`.
///
/// Salt and hash are base64-encoded without padding. The scrypt PHC string
/// does not carry a version segment (libsodium / passlib convention).
pub fn hash_encoded(
  params : Params,
  password : Bytes,
  salt : Bytes,
) -> String raise ScryptError {
  let hash = derive_key(params, password, salt)
  let salt_b64 = @base64.encode(salt[:], padding=false)
  let hash_b64 = @base64.encode(hash[:], padding=false)
  let buf = StringBuilder::StringBuilder()
  buf.write_string("$scrypt$ln=")
  buf.write_string(params.log_n.to_string())
  buf.write_string(",r=")
  buf.write_string(params.r.to_string())
  buf.write_string(",p=")
  buf.write_string(params.p.to_string())
  buf.write_char('$')
  buf.write_string(salt_b64)
  buf.write_char('$')
  buf.write_string(hash_b64)
  buf.to_string()
}

///|
/// Verifies `password` against a PHC-encoded scrypt string. Raises
/// `VerifyFailed` on mismatch and `InvalidEncoded` on malformed input.
pub fn verify_encoded(
  encoded : String,
  password : Bytes,
) -> Unit raise ScryptError {
  let parsed = parse_phc(encoded)
  let expected = derive_key(parsed.params, password, parsed.salt)
  if !ct_eq_bytes(expected, parsed.hash) {
    raise VerifyFailed
  }
}

///|
priv struct ParsedPhc {
  params : Params
  salt : Bytes
  hash : Bytes
}

///|
/// Parses a PHC-formatted scrypt string. Returns the params plus the decoded
/// salt and hash bytes. Raises `InvalidEncoded` on malformed input.
fn is_canonical_decimal(s : String) -> Bool {
  // Accept "0" exactly, or [1-9][0-9]* with no sign and no leading zero.
  if s.length() == 0 {
    return false
  }
  if s == "0" {
    return true
  }
  for i = 0; i < s.length(); i = i + 1 {
    let c = s.get_char(i).unwrap()
    if i == 0 && (c < '1' || c > '9') {
      return false
    }
    if i > 0 && (c < '0' || c > '9') {
      return false
    }
  }
  true
}

///|
fn parse_phc(encoded : String) -> ParsedPhc raise ScryptError {
  // Split on '$'. A valid scrypt PHC string has the form
  //   $scrypt$ln=<n>,r=<r>,p=<p>$<salt>$<hash>
  // which yields 5 segments after splitting (leading empty + 4 fields).
  let parts = encoded.split("$").to_array()
  if parts.length() != 5 {
    raise InvalidEncoded("expected 5 '$'-separated segments")
  }
  if parts[0].length() != 0 {
    raise InvalidEncoded("string must start with '$'")
  }
  if parts[1] != "scrypt" {
    raise InvalidEncoded("unknown algorithm")
  }
  let mut log_n = -1
  let mut r = -1
  let mut p = -1
  let mut ln_set = false
  let mut r_set = false
  let mut p_set = false
  for kv in parts[2].split(",") {
    match kv.split_once("=") {
      Some((k, v)) => {
        // Strict canonical: only [0-9]+, no leading +, no leading zeros
        // beyond a single 0. PHC string format spec §3.2 calls these
        // "decimal" parameter values; everything else makes verification
        // path-sensitive.
        if !is_canonical_decimal(v.to_owned()) {
          raise InvalidEncoded(
            "non-canonical parameter value (expected unsigned decimal)",
          )
        }
        let num = @string.parse_int(v) catch {
          _ => raise InvalidEncoded("non-integer parameter value")
        }
        if k == "ln" {
          if ln_set {
            raise InvalidEncoded("duplicate 'ln' parameter")
          }
          log_n = num
          ln_set = true
        } else if k == "r" {
          if r_set {
            raise InvalidEncoded("duplicate 'r' parameter")
          }
          r = num
          r_set = true
        } else if k == "p" {
          if p_set {
            raise InvalidEncoded("duplicate 'p' parameter")
          }
          p = num
          p_set = true
        } else {
          raise InvalidEncoded("unknown parameter")
        }
      }
      None => raise InvalidEncoded("malformed parameter pair")
    }
  }
  if log_n < 0 || r < 0 || p < 0 {
    raise InvalidEncoded("missing ln/r/p parameter")
  }
  let salt = @base64.decode(parts[3]) catch {
    _ => raise InvalidEncoded("invalid base64 salt")
  }
  let hash = @base64.decode(parts[4]) catch {
    _ => raise InvalidEncoded("invalid base64 hash")
  }
  let params : Params = { log_n, r, p, dk_len: hash.length() }
  { params, salt, hash }
}

///|
/// Constant-time equality test for two byte sequences. Returns `false` if
/// lengths differ; otherwise compares every byte without short-circuiting.
fn ct_eq_bytes(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0
  for i in 0..<a.length() {
    diff = diff | (a[i].to_int() ^ b[i].to_int())
  }
  diff == 0
}
