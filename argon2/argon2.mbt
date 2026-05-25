// RFC 9106 Argon2 (d / i / id) implementation in pure MoonBit.
//
// Layout of this file:
//   1. Public types: Variant, Params, Argon2Error
//   2. Recommended-params constructors
//   3. Public entry points: hash_raw / hash_raw_with_ad / hash_encoded / verify_encoded
//   4. Argon2 core: H0, lane init, fill_memory, finalize
//   5. Compression function G + permutation P
//   6. Variable-length hash H'
//   7. BLAKE2b (RFC 7693)
//   8. Misc byte helpers
//
// The implementation is bit-exact against RFC 9106 §5 test vectors.

// ─── 1. Public types ─────────────────────────────────────────────────────────

///|
pub(all) enum Variant {
  Argon2d
  Argon2i
  Argon2id
} derive(Eq, Show)

///|
pub(all) struct Params {
  variant : Variant
  m_cost : Int // memory cost in KiB. >= 8 * parallelism
  t_cost : Int // time cost (number of passes). >= 1
  parallelism : Int // 1 .. 2^24 - 1
  output_len : Int // 4 .. 2^32 - 1
} derive(Eq, Show)

// ─── 2. Recommended params ───────────────────────────────────────────────────

///|
/// OWASP 2024 interactive baseline: argon2id, m=19 MiB, t=2, p=1, out=32.
pub fn Params::recommended_interactive() -> Params {
  {
    variant: Argon2id,
    m_cost: 19 * 1024,
    t_cost: 2,
    parallelism: 1,
    output_len: 32,
  }
}

///|
/// Sensitive baseline: argon2id, m=64 MiB, t=3, p=4, out=32.
pub fn Params::recommended_sensitive() -> Params {
  {
    variant: Argon2id,
    m_cost: 64 * 1024,
    t_cost: 3,
    parallelism: 4,
    output_len: 32,
  }
}

///|
/// Default argon2id parameters (alias of `recommended_interactive`).
pub fn Params::default_id() -> Params {
  Params::recommended_interactive()
}

///|
pub suberror Argon2Error {
  InvalidParams(String)
  InvalidOutputLength
  InvalidEncoded(String)
  VerifyFailed
} derive(Show)

// ─── 3. Public entry points ──────────────────────────────────────────────────

///|
/// Computes the raw Argon2 output for `password` and `salt` under `params`.
pub fn hash_raw(
  params : Params,
  password : Bytes,
  salt : Bytes,
) -> Bytes raise Argon2Error {
  hash_raw_with_ad(params, password, salt, b"", b"")
}

///|
/// Computes the raw Argon2 output with optional associated data `ad` and
/// secret key `secret` as defined by RFC 9106.
pub fn hash_raw_with_ad(
  params : Params,
  password : Bytes,
  salt : Bytes,
  ad : Bytes,
  secret : Bytes,
) -> Bytes raise Argon2Error {
  validate_params(params)
  argon2_core(params, password, salt, ad, secret)
}

///|
/// Computes a PHC-encoded Argon2 hash string of the form
/// `$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`.
///
/// Salt and hash are base64-encoded without padding, per the PHC string
/// format spec.
pub fn hash_encoded(
  params : Params,
  password : Bytes,
  salt : Bytes,
) -> String raise Argon2Error {
  let hash = hash_raw(params, password, salt)
  let alg = match params.variant {
    Argon2d => "argon2d"
    Argon2i => "argon2i"
    Argon2id => "argon2id"
  }
  let salt_b64 = @base64.encode(salt[:], padding=false)
  let hash_b64 = @base64.encode(hash[:], padding=false)
  let buf = StringBuilder::StringBuilder()
  buf.write_char('$')
  buf.write_string(alg)
  buf.write_string("$v=19$m=")
  buf.write_string(params.m_cost.to_string())
  buf.write_string(",t=")
  buf.write_string(params.t_cost.to_string())
  buf.write_string(",p=")
  buf.write_string(params.parallelism.to_string())
  buf.write_char('$')
  buf.write_string(salt_b64)
  buf.write_char('$')
  buf.write_string(hash_b64)
  buf.to_string()
}

///|
/// Verifies `password` against a PHC-encoded Argon2 string. Raises
/// `VerifyFailed` on mismatch and `InvalidEncoded` on malformed input.
pub fn verify_encoded(
  encoded : String,
  password : Bytes,
) -> Unit raise Argon2Error {
  let parsed = parse_phc(encoded)
  let expected = hash_raw(parsed.params, password, parsed.salt)
  if not(ct_eq_bytes(expected, parsed.hash)) {
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
/// Parses a PHC-formatted Argon2 string. Returns the params plus the decoded
/// salt and hash bytes. Raises `InvalidEncoded` on malformed input.
fn parse_phc(encoded : String) -> ParsedPhc raise Argon2Error {
  // Split on '$'. A valid Argon2 PHC string has the form
  //   $<alg>$v=<v>$m=<m>,t=<t>,p=<p>$<salt>$<hash>
  // which yields 6 segments after splitting (leading empty + 5 fields).
  let parts = encoded.split("$").to_array()
  if parts.length() != 6 {
    raise InvalidEncoded("expected 6 '$'-separated segments")
  }
  if parts[0].length() != 0 {
    raise InvalidEncoded("string must start with '$'")
  }
  let alg = parts[1]
  let variant = if alg == "argon2d" {
    Argon2d
  } else if alg == "argon2i" {
    Argon2i
  } else if alg == "argon2id" {
    Argon2id
  } else {
    raise InvalidEncoded("unknown algorithm")
  }
  // Version: must be "v=19".
  let ver = parts[2]
  if ver != "v=19" {
    raise InvalidEncoded("unsupported version segment")
  }
  // Parameters: "m=<m>,t=<t>,p=<p>" in this order.
  let mut m_cost = -1
  let mut t_cost = -1
  let mut parallelism = -1
  for kv in parts[3].split(",") {
    match kv.split_once("=") {
      Some((k, v)) => {
        let num = @strconv.parse_int(v) catch {
          _ => raise InvalidEncoded("non-integer parameter value")
        }
        if k == "m" {
          m_cost = num
        } else if k == "t" {
          t_cost = num
        } else if k == "p" {
          parallelism = num
        } else {
          raise InvalidEncoded("unknown parameter")
        }
      }
      None => raise InvalidEncoded("malformed parameter pair")
    }
  }
  if m_cost < 0 || t_cost < 0 || parallelism < 0 {
    raise InvalidEncoded("missing m/t/p parameter")
  }
  let salt = @base64.decode(parts[4]) catch {
    _ => raise InvalidEncoded("invalid base64 salt")
  }
  let hash = @base64.decode(parts[5]) catch {
    _ => raise InvalidEncoded("invalid base64 hash")
  }
  let params : Params = {
    variant,
    m_cost,
    t_cost,
    parallelism,
    output_len: hash.length(),
  }
  { params, salt, hash }
}

///|
/// Constant-time equality test for two byte sequences. Returns `false` if
/// lengths differ; otherwise compares every byte.
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

///|
fn validate_params(params : Params) -> Unit raise Argon2Error {
  if params.parallelism < 1 || params.parallelism > 0xFFFFFF {
    raise InvalidParams("parallelism out of range")
  }
  if params.t_cost < 1 {
    raise InvalidParams("t_cost must be >= 1")
  }
  if params.m_cost < 8 * params.parallelism {
    raise InvalidParams("m_cost must be >= 8 * parallelism")
  }
  if params.output_len < 4 {
    raise InvalidParams("output_len must be >= 4")
  }
}

// ─── 4. Argon2 core ──────────────────────────────────────────────────────────

///|
/// Bytes per Argon2 memory block (RFC 9106 §3.2).
const BLOCK_BYTES : Int = 1024

///|
/// Number of 64-bit words per block: 1024 / 8 = 128.
const BLOCK_WORDS : Int = 128

///|
/// Argon2 version constant (0x13 = v1.3 from RFC 9106).
const ARGON2_VERSION : Int = 0x13

///|
/// SYNC_POINTS = 4 by RFC 9106 §3.4 (segments per pass).
const SYNC_POINTS : Int = 4

///|
fn variant_id(v : Variant) -> Int {
  match v {
    Argon2d => 0
    Argon2i => 1
    Argon2id => 2
  }
}

///|
/// Compute H0 (64 byte) — RFC 9106 §3.2.
fn compute_h0(
  params : Params,
  password : Bytes,
  salt : Bytes,
  secret : Bytes,
  ad : Bytes,
) -> FixedArray[Byte] {
  // H0 = BLAKE2b(parallelism || tagLen || memCost || tCost || version || y
  //              || len(P)||P || len(S)||S || len(K)||K || len(X)||X)
  let buf : Array[Byte] = []
  append_u32_le(buf, params.parallelism)
  append_u32_le(buf, params.output_len)
  append_u32_le(buf, params.m_cost)
  append_u32_le(buf, params.t_cost)
  append_u32_le(buf, ARGON2_VERSION)
  append_u32_le(buf, variant_id(params.variant))
  append_u32_le(buf, password.length())
  append_bytes(buf, password)
  append_u32_le(buf, salt.length())
  append_bytes(buf, salt)
  append_u32_le(buf, secret.length())
  append_bytes(buf, secret)
  append_u32_le(buf, ad.length())
  append_bytes(buf, ad)
  let input = array_to_fixed(buf)
  blake2b(input, 64, FixedArray::make(0, b'\x00'))
}

///|
/// Core algorithm: produce `output_len` bytes from validated `params` and inputs.
fn argon2_core(
  params : Params,
  password : Bytes,
  salt : Bytes,
  ad : Bytes,
  secret : Bytes,
) -> Bytes {
  let lanes = params.parallelism
  let h0 = compute_h0(params, password, salt, secret, ad)

  // m' = 4 * p * floor(m / (4p)); column count per lane = m' / p
  let m_prime = SYNC_POINTS * lanes * (params.m_cost / (SYNC_POINTS * lanes))
  let lane_length = m_prime / lanes
  let segment_length = lane_length / SYNC_POINTS

  // Allocate memory: m_prime blocks of 128 u64 words each.
  let memory : FixedArray[FixedArray[UInt64]] = FixedArray::make(
    m_prime,
    FixedArray::make(0, 0UL),
  )
  for i in 0..<m_prime {
    memory[i] = FixedArray::make(BLOCK_WORDS, 0UL)
  }

  // Initialize first two columns of each lane: B[i][0] and B[i][1].
  // h0_with_zero_and_lane = H0 || LE32(0) || LE32(i)
  // h0_with_one_and_lane  = H0 || LE32(1) || LE32(i)
  let prefix0 = FixedArray::make(64 + 8, b'\x00')
  let prefix1 = FixedArray::make(64 + 8, b'\x00')
  for j in 0..<64 {
    prefix0[j] = h0[j]
    prefix1[j] = h0[j]
  }
  // index 1 for prefix1
  prefix1[64] = b'\x01'
  for lane in 0..<lanes {
    // Set lane bytes (4-byte LE) at offset 68.
    write_u32_le_fa(prefix0, 68, lane)
    write_u32_le_fa(prefix1, 68, lane)
    let b0 = h_prime(prefix0, BLOCK_BYTES)
    let b1 = h_prime(prefix1, BLOCK_BYTES)
    bytes_to_block(b0, memory[lane * lane_length])
    bytes_to_block(b1, memory[lane * lane_length + 1])
  }

  // Main fill loop: t_cost passes, SYNC_POINTS slices each, p lanes each.
  for pass in 0..<params.t_cost {
    for slice in 0..<SYNC_POINTS {
      for lane in 0..<lanes {
        fill_segment(
          memory,
          params.variant,
          pass,
          lane,
          slice,
          lanes,
          lane_length,
          segment_length,
          params.t_cost,
        )
      }
    }
  }

  // Finalize: C = B[0][q-1] XOR B[1][q-1] XOR ... XOR B[p-1][q-1]
  let final_block = FixedArray::make(BLOCK_WORDS, 0UL)
  for lane in 0..<lanes {
    let last = memory[lane * lane_length + lane_length - 1]
    for k in 0..<BLOCK_WORDS {
      final_block[k] = final_block[k] ^ last[k]
    }
  }
  let final_bytes = block_to_bytes(final_block)
  let tag = h_prime(final_bytes, params.output_len)
  fixed_to_bytes_view(tag)
}

///|
/// Fill one segment (lane, slice) per RFC 9106 §3.4.
fn fill_segment(
  memory : FixedArray[FixedArray[UInt64]],
  variant : Variant,
  pass : Int,
  lane : Int,
  slice : Int,
  lanes : Int,
  lane_length : Int,
  segment_length : Int,
  t_cost : Int,
) -> Unit {
  // Decide if this segment uses data-independent addressing (Argon2i, or
  // Argon2id pass 0 first half).
  let data_independent = match variant {
    Argon2i => true
    Argon2d => false
    Argon2id => pass == 0 && slice < SYNC_POINTS / 2
  }

  // For data-independent addressing we need 128-pseudorandom-word streams to
  // pick reference (j1, j2). We compute them block-by-block lazily.
  // ──────────────────────────────────────────────────────────────────────────
  // pseudo_rand[k] yields (j1, j2) for the k-th block in this segment.
  // RFC 9106 §3.4.1.1 says we run G with zero block as first input and a
  // block built from (pass, lane, slice, m_prime_total_blocks?, t_cost, type, counter).
  // We compute the address blocks on demand.
  let address_block = FixedArray::make(BLOCK_WORDS, 0UL)
  let input_block = FixedArray::make(BLOCK_WORDS, 0UL)
  let zero_block = FixedArray::make(BLOCK_WORDS, 0UL)
  if data_independent {
    input_block[0] = pass.to_uint64()
    input_block[1] = lane.to_uint64()
    input_block[2] = slice.to_uint64()
    input_block[3] = memory.length().to_uint64()
    input_block[4] = t_cost.to_uint64()
    input_block[5] = variant_id(variant).to_uint64()
    // input_block[6] is the counter, incremented per ARGON2_ADDRESSES_IN_BLOCK = 128 blocks.
  }

  // Starting column inside this lane: previous columns already filled.
  // pass 0, slice 0: cols 0..1 are initial, fill starts at col 2.
  // otherwise: fill starts at col = slice * segment_length.
  let starting_col = if pass == 0 && slice == 0 { 2 } else { 0 }

  // Cache the previous block index (for chained G call).
  // The previous block is the immediately preceding column within the same lane.
  // Wrap to the lane's last column only at pass>0 && slice==0 && starting_col==0.
  let mut prev_offset = lane * lane_length +
    slice * segment_length +
    starting_col -
    1
  if slice == 0 && starting_col == 0 {
    // pass>0 case (since pass==0 && slice==0 has starting_col==2): wrap to lane end.
    prev_offset = lane * lane_length + lane_length - 1
  }
  let mut curr_offset = lane * lane_length +
    slice * segment_length +
    starting_col

  // Pre-compute first address block if needed.
  if data_independent {
    input_block[6] = input_block[6] + 1UL
    compute_address_block(input_block, zero_block, address_block)
  }

  // Iterate fill positions within this segment.
  for i in starting_col..<segment_length {
    // Determine pseudo-random (j1, j2)
    let pseudo_rand : UInt64 = if data_independent {
      let idx = i % 128
      if idx == 0 && i != starting_col {
        input_block[6] = input_block[6] + 1UL
        compute_address_block(input_block, zero_block, address_block)
      }
      address_block[idx]
    } else {
      // Argon2d / second half of Argon2id pass 0: use first word of previous block.
      memory[prev_offset][0]
    }
    let j1 = (pseudo_rand & 0xFFFFFFFFUL).to_uint() // low 32 bits
    let j2 = ((pseudo_rand >> 32) & 0xFFFFFFFFUL).to_uint() // high 32 bits

    // ref_lane: in pass 0, slice 0, must be current lane.
    let ref_lane = if pass == 0 && slice == 0 {
      lane
    } else {
      (j2.to_uint64() % lanes.to_uint64()).to_int()
    }

    // reference area size
    let same_lane = ref_lane == lane
    let ref_area_size = compute_ref_area_size(
      pass, slice, i, segment_length, lane_length, same_lane,
    )

    // Map j1 to absolute index per §3.4.1.2.
    let j1_u64 = j1.to_uint64()
    let rel_pos_part = (j1_u64 * j1_u64) >> 32
    let rel_pos = ref_area_size.to_uint64() -
      1UL -
      ((ref_area_size.to_uint64() * rel_pos_part) >> 32)
    let start_pos = if pass != 0 && slice != SYNC_POINTS - 1 {
      ((slice + 1) * segment_length).to_uint64()
    } else {
      0UL
    }
    let abs_pos = ((start_pos + rel_pos) % lane_length.to_uint64()).to_int()
    let ref_index = ref_lane * lane_length + abs_pos

    // Compute new block.
    let new_block = FixedArray::make(BLOCK_WORDS, 0UL)
    let with_xor = pass != 0
    compress_g(
      memory[prev_offset],
      memory[ref_index],
      new_block,
      with_xor,
      memory[curr_offset],
    )
    // Write back into memory[curr_offset].
    let dest = memory[curr_offset]
    for k in 0..<BLOCK_WORDS {
      dest[k] = new_block[k]
    }
    prev_offset = curr_offset
    curr_offset = curr_offset + 1
  }
}

///|
/// Reference-area size per RFC 9106 §3.4.1.2.
fn compute_ref_area_size(
  pass : Int,
  slice : Int,
  i : Int,
  segment_length : Int,
  lane_length : Int,
  same_lane : Bool,
) -> Int {
  // i is the column offset within current segment.
  if pass == 0 {
    if slice == 0 {
      // same lane only; ref area is blocks 0..(i-1) (positions 0..i-1)
      i - 1
    } else if same_lane {
      slice * segment_length + i - 1
    } else {
      slice * segment_length + (if i == 0 { -1 } else { 0 })
      // Equivalent: slice * segment_length when i>0, else slice*segment_length - 1.
    }
  } else if same_lane {
    lane_length - segment_length + i - 1
  } else {
    lane_length - segment_length + (if i == 0 { -1 } else { 0 })
  }
}

///|
/// Compute one address block for data-independent variants.
/// addr_block[i] = G(zero, G(zero, input_block))[i]
fn compute_address_block(
  input_block : FixedArray[UInt64],
  zero_block : FixedArray[UInt64],
  address_block : FixedArray[UInt64],
) -> Unit {
  let tmp = FixedArray::make(BLOCK_WORDS, 0UL)
  // First: tmp = G(zero, input_block) with no XOR overlay (zero overlay).
  compress_g(zero_block, input_block, tmp, false, zero_block)
  // Then: address_block = G(zero, tmp)
  compress_g(zero_block, tmp, address_block, false, zero_block)
}

// ─── 5. Compression function G + permutation P ───────────────────────────────

///|
/// G(X, Y) → R = X XOR Y; Z = P-shuffled R; output = Z XOR R.
/// If `with_xor` is true, output ⊕= overlay (used for passes > 0).
fn compress_g(
  x : FixedArray[UInt64],
  y : FixedArray[UInt64],
  out : FixedArray[UInt64],
  with_xor : Bool,
  overlay : FixedArray[UInt64],
) -> Unit {
  // R = X XOR Y
  let r = FixedArray::make(BLOCK_WORDS, 0UL)
  for i in 0..<BLOCK_WORDS {
    r[i] = x[i] ^ y[i]
  }
  // Q = R (we'll apply P to Q in place)
  let q = FixedArray::make(BLOCK_WORDS, 0UL)
  for i in 0..<BLOCK_WORDS {
    q[i] = r[i]
  }
  // Apply P row-wise. Each row is 8 consecutive 128-bit pairs = 16 u64.
  // 8 rows of 16 u64 each = 128 u64 = one block.
  for row in 0..<8 {
    let off = row * 16
    permute_p(q, off, 1)
  }
  // Apply P column-wise. Each "column" = 16 u64 with stride 16.
  for col in 0..<8 {
    let off = col * 2
    permute_p_columnwise(q, off)
  }
  // Z = Q
  // out = Z XOR R, possibly XOR overlay
  if with_xor {
    for i in 0..<BLOCK_WORDS {
      out[i] = q[i] ^ r[i] ^ overlay[i]
    }
  } else {
    for i in 0..<BLOCK_WORDS {
      out[i] = q[i] ^ r[i]
    }
  }
}

///|
/// P permutation: BLAKE2b round on 16 64-bit words = 8x16-byte matrix.
/// Operates on q[off..off+16] when stride=1.
fn permute_p(q : FixedArray[UInt64], off : Int, stride : Int) -> Unit {
  // Load 16 words.
  let v = FixedArray::make(16, 0UL)
  for i in 0..<16 {
    v[i] = q[off + i * stride]
  }
  // Apply BLAKE2b-like round (Argon2's modified G with full 64-bit multiply).
  gb(v, 0, 4, 8, 12)
  gb(v, 1, 5, 9, 13)
  gb(v, 2, 6, 10, 14)
  gb(v, 3, 7, 11, 15)
  gb(v, 0, 5, 10, 15)
  gb(v, 1, 6, 11, 12)
  gb(v, 2, 7, 8, 13)
  gb(v, 3, 4, 9, 14)
  for i in 0..<16 {
    q[off + i * stride] = v[i]
  }
}

///|
/// Apply P to a column: 8 pairs of words at indices (col*2, col*2 + 16, col*2 + 32, …)
/// where each "word" is actually a pair (u64, u64). The permutation acts on 16 words
/// taken as the 8 pairs in column order.
fn permute_p_columnwise(q : FixedArray[UInt64], col_off : Int) -> Unit {
  // 16 words at positions col_off + row*16 + k where row in 0..7 and k in {0,1}.
  // Indices: col_off, col_off+1, col_off+16, col_off+17, ..., col_off+7*16, col_off+7*16+1.
  let v = FixedArray::make(16, 0UL)
  for row in 0..<8 {
    v[row * 2] = q[col_off + row * 16]
    v[row * 2 + 1] = q[col_off + row * 16 + 1]
  }
  gb(v, 0, 4, 8, 12)
  gb(v, 1, 5, 9, 13)
  gb(v, 2, 6, 10, 14)
  gb(v, 3, 7, 11, 15)
  gb(v, 0, 5, 10, 15)
  gb(v, 1, 6, 11, 12)
  gb(v, 2, 7, 8, 13)
  gb(v, 3, 4, 9, 14)
  for row in 0..<8 {
    q[col_off + row * 16] = v[row * 2]
    q[col_off + row * 16 + 1] = v[row * 2 + 1]
  }
}

///|
/// BLAKE2b-style G function modified by Argon2 (RFC 9106 §3.5):
///   a = a + b + 2 * lsw(a) * lsw(b)
///   d = rotr(d XOR a, 32)
///   c = c + d + 2 * lsw(c) * lsw(d)
///   b = rotr(b XOR c, 24)
///   a = a + b + 2 * lsw(a) * lsw(b)
///   d = rotr(d XOR a, 16)
///   c = c + d + 2 * lsw(c) * lsw(d)
///   b = rotr(b XOR c, 63)
fn gb(v : FixedArray[UInt64], a : Int, b : Int, c : Int, d : Int) -> Unit {
  let mask32 : UInt64 = 0xFFFFFFFFUL
  v[a] = v[a] + v[b] + 2UL * (v[a] & mask32) * (v[b] & mask32)
  v[d] = rotr64(v[d] ^ v[a], 32)
  v[c] = v[c] + v[d] + 2UL * (v[c] & mask32) * (v[d] & mask32)
  v[b] = rotr64(v[b] ^ v[c], 24)
  v[a] = v[a] + v[b] + 2UL * (v[a] & mask32) * (v[b] & mask32)
  v[d] = rotr64(v[d] ^ v[a], 16)
  v[c] = v[c] + v[d] + 2UL * (v[c] & mask32) * (v[d] & mask32)
  v[b] = rotr64(v[b] ^ v[c], 63)
}

///|
fn rotr64(x : UInt64, n : Int) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

// ─── 6. Variable-length hash H' ──────────────────────────────────────────────

///|
/// H'(input, output_len) per RFC 9106 §3.3:
/// If output_len <= 64: BLAKE2b with output_len bytes.
/// Else: produce output_len bytes by:
///   V_1 = BLAKE2b_64(LE32(output_len) || input)
///   V_2 = BLAKE2b_64(V_1)
///   ...
///   for r = ceil(output_len/32) - 2:
///     output = V_1[0..32] || V_2[0..32] || ... || V_r[0..32] || V_{r+1}[full 64]
fn h_prime(input : FixedArray[Byte], output_len : Int) -> FixedArray[Byte] {
  // Prepend LE32(output_len).
  let with_len = FixedArray::make(4 + input.length(), b'\x00')
  with_len[0] = (output_len & 0xFF).to_byte()
  with_len[1] = ((output_len >> 8) & 0xFF).to_byte()
  with_len[2] = ((output_len >> 16) & 0xFF).to_byte()
  with_len[3] = ((output_len >> 24) & 0xFF).to_byte()
  for i in 0..<input.length() {
    with_len[4 + i] = input[i]
  }
  if output_len <= 64 {
    blake2b(with_len, output_len, FixedArray::make(0, b'\x00'))
  } else {
    let out = FixedArray::make(output_len, b'\x00')
    // r = ceil(output_len / 32) - 2; produce r blocks of 32 bytes (low half of each V_i),
    // then 64-byte final block.
    let mut v = blake2b(with_len, 64, FixedArray::make(0, b'\x00'))
    // Write low 32 bytes of v.
    for i in 0..<32 {
      out[i] = v[i]
    }
    let mut written = 32
    while output_len - written > 64 {
      // V_{i+1} = BLAKE2b_64(V_i)
      v = blake2b(v, 64, FixedArray::make(0, b'\x00'))
      for i in 0..<32 {
        out[written + i] = v[i]
      }
      written = written + 32
    }
    // Final block: full BLAKE2b output of length (output_len - written).
    let final_len = output_len - written
    let last = blake2b(v, final_len, FixedArray::make(0, b'\x00'))
    for i in 0..<final_len {
      out[written + i] = last[i]
    }
    out
  }
}

// ─── 7. BLAKE2b (RFC 7693) ───────────────────────────────────────────────────

///|
/// BLAKE2b IV (RFC 7693 §2.6).
fn blake2b_iv(i : Int) -> UInt64 {
  // 0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B,
  // 0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
  // 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
  match i {
    0 => 0x6A09E667F3BCC908UL
    1 => 0xBB67AE8584CAA73BUL
    2 => 0x3C6EF372FE94F82BUL
    3 => 0xA54FF53A5F1D36F1UL
    4 => 0x510E527FADE682D1UL
    5 => 0x9B05688C2B3E6C1FUL
    6 => 0x1F83D9ABFB41BD6BUL
    _ => 0x5BE0CD19137E2179UL
  }
}

///|
/// Sigma permutation (RFC 7693 §2.7).
fn blake2b_sigma(round : Int, i : Int) -> Int {
  // 12 rounds × 16 indices. Standard BLAKE2 sigma table.
  let table : FixedArray[FixedArray[Int]] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  ]
  table[round][i]
}

///|
/// BLAKE2b G function for compression.
fn blake2b_g(
  v : FixedArray[UInt64],
  a : Int,
  b : Int,
  c : Int,
  d : Int,
  x : UInt64,
  y : UInt64,
) -> Unit {
  v[a] = v[a] + v[b] + x
  v[d] = rotr64(v[d] ^ v[a], 32)
  v[c] = v[c] + v[d]
  v[b] = rotr64(v[b] ^ v[c], 24)
  v[a] = v[a] + v[b] + y
  v[d] = rotr64(v[d] ^ v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = rotr64(v[b] ^ v[c], 63)
}

///|
/// BLAKE2b compression F (RFC 7693 §3.2).
fn blake2b_compress(
  h : FixedArray[UInt64],
  block : FixedArray[Byte], // 128 bytes
  block_offset : Int,
  t : UInt64,
  t_high : UInt64,
  last : Bool,
) -> Unit {
  // Prepare working vector v[0..16].
  let v = FixedArray::make(16, 0UL)
  for i in 0..<8 {
    v[i] = h[i]
    v[i + 8] = blake2b_iv(i)
  }
  v[12] = v[12] ^ t
  v[13] = v[13] ^ t_high
  if last {
    v[14] = v[14] ^ 0xFFFFFFFFFFFFFFFFUL
  }
  // Load message m[0..16] from block as little-endian u64.
  let m = FixedArray::make(16, 0UL)
  for i in 0..<16 {
    let o = block_offset + i * 8
    m[i] = block[o].to_uint64() |
      (block[o + 1].to_uint64() << 8) |
      (block[o + 2].to_uint64() << 16) |
      (block[o + 3].to_uint64() << 24) |
      (block[o + 4].to_uint64() << 32) |
      (block[o + 5].to_uint64() << 40) |
      (block[o + 6].to_uint64() << 48) |
      (block[o + 7].to_uint64() << 56)
  }
  // 12 rounds.
  for r in 0..<12 {
    blake2b_g(v, 0, 4, 8, 12, m[blake2b_sigma(r, 0)], m[blake2b_sigma(r, 1)])
    blake2b_g(v, 1, 5, 9, 13, m[blake2b_sigma(r, 2)], m[blake2b_sigma(r, 3)])
    blake2b_g(v, 2, 6, 10, 14, m[blake2b_sigma(r, 4)], m[blake2b_sigma(r, 5)])
    blake2b_g(v, 3, 7, 11, 15, m[blake2b_sigma(r, 6)], m[blake2b_sigma(r, 7)])
    blake2b_g(v, 0, 5, 10, 15, m[blake2b_sigma(r, 8)], m[blake2b_sigma(r, 9)])
    blake2b_g(v, 1, 6, 11, 12, m[blake2b_sigma(r, 10)], m[blake2b_sigma(r, 11)])
    blake2b_g(v, 2, 7, 8, 13, m[blake2b_sigma(r, 12)], m[blake2b_sigma(r, 13)])
    blake2b_g(v, 3, 4, 9, 14, m[blake2b_sigma(r, 14)], m[blake2b_sigma(r, 15)])
  }
  for i in 0..<8 {
    h[i] = h[i] ^ v[i] ^ v[i + 8]
  }
}

///|
/// Top-level BLAKE2b: arbitrary-length input → `output_len` bytes (1..64).
/// `key` may be empty (length 0); keyed mode pads the key to a full block as
/// the first block.
fn blake2b(
  input : FixedArray[Byte],
  output_len : Int,
  key : FixedArray[Byte],
) -> FixedArray[Byte] {
  // Initialize state.
  let h = FixedArray::make(8, 0UL)
  for i in 0..<8 {
    h[i] = blake2b_iv(i)
  }
  // Parameter block low word: 0x0101kkll where ll = output_len, kk = key length.
  let key_len = key.length()
  let p0 = 0x01010000UL | (key_len.to_uint64() << 8) | output_len.to_uint64()
  h[0] = h[0] ^ p0

  // Pad message: if key, prepend key padded to 128 bytes.
  let total_len = (if key_len > 0 { 128 } else { 0 }) + input.length()
  // Buffer in 128-byte blocks; if total_len == 0 we still need to process one empty block.
  let buf_len = if total_len == 0 {
    128
  } else if total_len % 128 == 0 {
    total_len
  } else {
    total_len + (128 - total_len % 128)
  }
  let buf = FixedArray::make(buf_len, b'\x00')
  if key_len > 0 {
    for i in 0..<key_len {
      buf[i] = key[i]
    }
  }
  let in_off = if key_len > 0 { 128 } else { 0 }
  for i in 0..<input.length() {
    buf[in_off + i] = input[i]
  }

  // Process all but the last block as non-final, last block as final.
  let num_blocks = buf_len / 128
  let mut processed : UInt64 = 0UL
  for i in 0..<(num_blocks - 1) {
    processed = processed + 128UL
    blake2b_compress(h, buf, i * 128, processed, 0UL, false)
  }
  // Final block — bytes counter = total_len (truncated, no key block content counted? Actually,
  // BLAKE2b counts EVERY byte processed including the key padding block.
  // RFC 7693 §3.3: t = total number of bytes hashed including key block(s).
  let last_count : UInt64 = total_len.to_uint64()
  blake2b_compress(h, buf, (num_blocks - 1) * 128, last_count, 0UL, true)

  // Extract output_len bytes from h as little-endian.
  let out = FixedArray::make(output_len, b'\x00')
  for i in 0..<output_len {
    let word_idx = i / 8
    let byte_idx = i % 8
    out[i] = ((h[word_idx] >> (byte_idx * 8)) & 0xFFUL).to_byte()
  }
  out
}

// ─── 8. Misc helpers ─────────────────────────────────────────────────────────

///|
fn append_u32_le(buf : Array[Byte], v : Int) -> Unit {
  buf.push((v & 0xFF).to_byte())
  buf.push(((v >> 8) & 0xFF).to_byte())
  buf.push(((v >> 16) & 0xFF).to_byte())
  buf.push(((v >> 24) & 0xFF).to_byte())
}

///|
fn append_bytes(buf : Array[Byte], data : Bytes) -> Unit {
  for i in 0..<data.length() {
    buf.push(data[i])
  }
}

///|
fn write_u32_le_fa(buf : FixedArray[Byte], off : Int, v : Int) -> Unit {
  buf[off] = (v & 0xFF).to_byte()
  buf[off + 1] = ((v >> 8) & 0xFF).to_byte()
  buf[off + 2] = ((v >> 16) & 0xFF).to_byte()
  buf[off + 3] = ((v >> 24) & 0xFF).to_byte()
}

///|
fn array_to_fixed(arr : Array[Byte]) -> FixedArray[Byte] {
  let out = FixedArray::make(arr.length(), b'\x00')
  for i in 0..<arr.length() {
    out[i] = arr[i]
  }
  out
}

///|
fn bytes_to_block(src : FixedArray[Byte], dst : FixedArray[UInt64]) -> Unit {
  // src is 1024 bytes; dst is 128 u64 (little-endian).
  for i in 0..<BLOCK_WORDS {
    let o = i * 8
    dst[i] = src[o].to_uint64() |
      (src[o + 1].to_uint64() << 8) |
      (src[o + 2].to_uint64() << 16) |
      (src[o + 3].to_uint64() << 24) |
      (src[o + 4].to_uint64() << 32) |
      (src[o + 5].to_uint64() << 40) |
      (src[o + 6].to_uint64() << 48) |
      (src[o + 7].to_uint64() << 56)
  }
}

///|
fn block_to_bytes(src : FixedArray[UInt64]) -> FixedArray[Byte] {
  let out = FixedArray::make(BLOCK_BYTES, b'\x00')
  for i in 0..<BLOCK_WORDS {
    let v = src[i]
    let o = i * 8
    for k in 0..<8 {
      out[o + k] = ((v >> (k * 8)) & 0xFFUL).to_byte()
    }
  }
  out
}

///|
fn fixed_to_bytes_view(fa : FixedArray[Byte]) -> Bytes {
  Bytes::makei(fa.length(), fn(i) { fa[i] })
}
