// BLAKE3 cryptographic hash (https://github.com/BLAKE3-team/BLAKE3-specs).
//
// Pure MoonBit, self-contained, NOT constant-time. No SIMD, no parallel
// chunk processing — single-thread reference implementation that follows the
// spec's pseudocode in §2 directly.
//
// Internal symbols are prefixed `blake3_` to coexist with the other hash
// files in this module (notably `rotr32` already exists in `sha256.mbt`).
//
// Layout:
//   1. Constants (IV, flags, MSG_PERMUTATION)
//   2. Compression function `blake3_compress` + G mix
//   3. Chunk state (incremental within a single 1024-byte chunk)
//   4. Hasher (chunk merging via cv_stack)
//   5. One-shot helpers: blake3 / blake3_xof / blake3_keyed / blake3_derive_key

// ─── 1. Constants ────────────────────────────────────────────────────────────

///|
/// First 8 SHA-256 IV words (§2.1).
let blake3_iv : FixedArray[UInt] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
  0x5be0cd19,
]

///|
/// Message permutation table applied between rounds (§2.3).
/// Index i of round r+1 reads message word `blake3_msg_permutation[i]` of round r.
let blake3_msg_permutation : FixedArray[Int] = [
  2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
]

// Domain separation flags (§2.4).

///|
let blake3_flag_chunk_start : Int = 1 << 0

///|
let blake3_flag_chunk_end : Int = 1 << 1

///|
let blake3_flag_parent : Int = 1 << 2

///|
let blake3_flag_root : Int = 1 << 3

///|
let blake3_flag_keyed_hash : Int = 1 << 4

///|
let blake3_flag_derive_key_context : Int = 1 << 5

///|
let blake3_flag_derive_key_material : Int = 1 << 6

///|
let blake3_block_len_bytes : Int = 64

///|
let blake3_chunk_len_bytes : Int = 1024

///|
pub suberror Blake3Error {
  InvalidBlake3KeyLength
} derive(Debug)

// ─── 2. Compression function ─────────────────────────────────────────────────

///|
fn blake3_rotr32(x : UInt, n : Int) -> UInt {
  (x >> n) | (x << (32 - n))
}

///|
/// The G mixing function from §2.3. Mutates state cells (a, b, c, d) using two
/// message words `mx` and `my`.
fn blake3_g_mix(
  state : FixedArray[UInt],
  a : Int,
  b : Int,
  c : Int,
  d : Int,
  mx : UInt,
  my : UInt,
) -> Unit {
  let mut va = state.unsafe_get(a)
  let mut vb = state.unsafe_get(b)
  let mut vc = state.unsafe_get(c)
  let mut vd = state.unsafe_get(d)
  va = va + vb + mx
  vd = blake3_rotr32(vd ^ va, 16)
  vc = vc + vd
  vb = blake3_rotr32(vb ^ vc, 12)
  va = va + vb + my
  vd = blake3_rotr32(vd ^ va, 8)
  vc = vc + vd
  vb = blake3_rotr32(vb ^ vc, 7)
  state.unsafe_set(a, va)
  state.unsafe_set(b, vb)
  state.unsafe_set(c, vc)
  state.unsafe_set(d, vd)
}

///|
/// One round: 4 column mixes + 4 diagonal mixes.
fn blake3_round_fn(state : FixedArray[UInt], m : FixedArray[UInt]) -> Unit {
  // Columns
  blake3_g_mix(state, 0, 4, 8, 12, m.unsafe_get(0), m.unsafe_get(1))
  blake3_g_mix(state, 1, 5, 9, 13, m.unsafe_get(2), m.unsafe_get(3))
  blake3_g_mix(state, 2, 6, 10, 14, m.unsafe_get(4), m.unsafe_get(5))
  blake3_g_mix(state, 3, 7, 11, 15, m.unsafe_get(6), m.unsafe_get(7))
  // Diagonals
  blake3_g_mix(state, 0, 5, 10, 15, m.unsafe_get(8), m.unsafe_get(9))
  blake3_g_mix(state, 1, 6, 11, 12, m.unsafe_get(10), m.unsafe_get(11))
  blake3_g_mix(state, 2, 7, 8, 13, m.unsafe_get(12), m.unsafe_get(13))
  blake3_g_mix(state, 3, 4, 9, 14, m.unsafe_get(14), m.unsafe_get(15))
}

///|
/// Apply the fixed message permutation in place: m'[i] = m[blake3_msg_permutation[i]].
fn blake3_permute(m : FixedArray[UInt]) -> Unit {
  let tmp = FixedArray::make(16, 0U)
  for i = 0; i < 16; i = i + 1 {
    tmp.unsafe_set(i, m.unsafe_get(blake3_msg_permutation.unsafe_get(i)))
  }
  for i = 0; i < 16; i = i + 1 {
    m.unsafe_set(i, tmp.unsafe_get(i))
  }
}

///|
/// Compression function `f(h, m, t, b, d)`. Returns the 16-word output
/// (lower 8 words = next chaining value, full 16 words used at the root for
/// XOF output). `out` must be a FixedArray of length 16.
fn blake3_compress(
  cv : FixedArray[UInt], // 8 input chaining words
  block_words : FixedArray[UInt], // 16 message words (one 64-byte block)
  counter : UInt64,
  block_len : Int,
  flags : Int,
  out : FixedArray[UInt], // 16-word output
) -> Unit {
  let state = FixedArray::make(16, 0U)
  for i = 0; i < 8; i = i + 1 {
    state.unsafe_set(i, cv.unsafe_get(i))
  }
  for i = 0; i < 4; i = i + 1 {
    state.unsafe_set(8 + i, blake3_iv.unsafe_get(i))
  }
  state.unsafe_set(12, counter.to_uint())
  state.unsafe_set(13, (counter >> 32).to_uint())
  state.unsafe_set(14, block_len.reinterpret_as_uint())
  state.unsafe_set(15, flags.reinterpret_as_uint())

  // Working message; blake3_round_fn reads from it then blake3_permute is applied between rounds.
  let m = FixedArray::make(16, 0U)
  for i = 0; i < 16; i = i + 1 {
    m.unsafe_set(i, block_words.unsafe_get(i))
  }
  blake3_round_fn(state, m)
  blake3_permute(m)
  blake3_round_fn(state, m)
  blake3_permute(m)
  blake3_round_fn(state, m)
  blake3_permute(m)
  blake3_round_fn(state, m)
  blake3_permute(m)
  blake3_round_fn(state, m)
  blake3_permute(m)
  blake3_round_fn(state, m)
  blake3_permute(m)
  blake3_round_fn(state, m) // 7th round, no permute after

  // Final feedforward: V[0..8] ^= V[8..16]; V[8..16] ^= input CV.
  for i = 0; i < 8; i = i + 1 {
    out.unsafe_set(i, state.unsafe_get(i) ^ state.unsafe_get(i + 8))
    out.unsafe_set(i + 8, state.unsafe_get(i + 8) ^ cv.unsafe_get(i))
  }
}

///|
/// Load 64 bytes (little-endian) into 16 32-bit words.
fn blake3_load_block_le(
  block : FixedArray[Byte],
  offset : Int,
  out : FixedArray[UInt],
) -> Unit {
  for i = 0; i < 16; i = i + 1 {
    let p = offset + i * 4
    let b0 = block.unsafe_get(p).to_uint()
    let b1 = block.unsafe_get(p + 1).to_uint()
    let b2 = block.unsafe_get(p + 2).to_uint()
    let b3 = block.unsafe_get(p + 3).to_uint()
    out.unsafe_set(i, b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
  }
}

///|
fn blake3_copy_cv(src : FixedArray[UInt]) -> FixedArray[UInt] {
  let dst = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    dst.unsafe_set(i, src.unsafe_get(i))
  }
  dst
}

// ─── 3. Blake3ChunkState (incremental within one 1024-byte chunk) ────────────

///|
struct Blake3ChunkState {
  cv : FixedArray[UInt] // 8 words, updated as blocks complete
  chunk_counter : UInt64
  block : FixedArray[Byte] // 64-byte buffer
  mut block_len : Int
  mut blocks_compressed : Int
  flags : Int
}

///|
fn Blake3ChunkState::new(
  key : FixedArray[UInt],
  chunk_counter : UInt64,
  flags : Int,
) -> Blake3ChunkState {
  {
    cv: blake3_copy_cv(key),
    chunk_counter,
    block: FixedArray::make(64, b'\x00'),
    block_len: 0,
    blocks_compressed: 0,
    flags,
  }
}

///|
fn Blake3ChunkState::len(self : Blake3ChunkState) -> Int {
  self.blocks_compressed * blake3_block_len_bytes + self.block_len
}

///|
fn Blake3ChunkState::start_flag(self : Blake3ChunkState) -> Int {
  if self.blocks_compressed == 0 {
    blake3_flag_chunk_start
  } else {
    0
  }
}

///|
/// Compress a full 64-byte block from `self.block`.
fn Blake3ChunkState::compress_full_block(self : Blake3ChunkState) -> Unit {
  let words = FixedArray::make(16, 0U)
  blake3_load_block_le(self.block, 0, words)
  let out = FixedArray::make(16, 0U)
  let f = self.flags | self.start_flag()
  blake3_compress(
    self.cv,
    words,
    self.chunk_counter,
    blake3_block_len_bytes,
    f,
    out,
  )
  for i = 0; i < 8; i = i + 1 {
    self.cv.unsafe_set(i, out.unsafe_get(i))
  }
  self.blocks_compressed += 1
  // Clear buffer for the next block.
  for i = 0; i < 64; i = i + 1 {
    self.block.unsafe_set(i, b'\x00')
  }
  self.block_len = 0
}

///|
fn Blake3ChunkState::update(
  self : Blake3ChunkState,
  data : Bytes,
  start : Int,
  end : Int,
) -> Int {
  // Feed bytes until the chunk is full or input is exhausted. Returns the
  // number of bytes consumed.
  //
  // Important: the *last* block of a chunk MUST stay buffered (with
  // CHUNK_END applied at finalize time). We never call `compress_full_block`
  // on it from here — that block leaves the chunk via `output_words` only.
  let mut pos = start
  while pos < end {
    // Chunk already full → caller must consume the chunk (finalize / push CV)
    // before feeding more bytes.
    if self.len() == blake3_chunk_len_bytes {
      return pos - start
    }
    // The current block buffer is full but the chunk has more capacity; this
    // means we just finished an *intermediate* block. Compress it (no flags
    // beyond CHUNK_START on block 0) and continue.
    if self.block_len == blake3_block_len_bytes {
      self.compress_full_block()
    }
    let remaining_in_block = blake3_block_len_bytes - self.block_len
    let remaining_in_chunk = blake3_chunk_len_bytes - self.len()
    let take = {
      let a = end - pos
      let b = if remaining_in_block < remaining_in_chunk {
        remaining_in_block
      } else {
        remaining_in_chunk
      }
      if a < b {
        a
      } else {
        b
      }
    }
    for i = 0; i < take; i = i + 1 {
      self.block.unsafe_set(self.block_len + i, data[pos + i])
    }
    self.block_len += take
    pos += take
  }
  pos - start
}

///|
/// Finish a chunk and produce its 16-word output. Caller may set `is_root`
/// for the single-chunk case. For multi-chunk, root is decided by the
/// hasher at finalize time.
fn Blake3ChunkState::output_words(
  self : Blake3ChunkState,
  extra_flags : Int,
  out : FixedArray[UInt],
) -> Unit {
  let words = FixedArray::make(16, 0U)
  blake3_load_block_le(self.block, 0, words)
  let f = self.flags | self.start_flag() | blake3_flag_chunk_end | extra_flags
  blake3_compress(self.cv, words, self.chunk_counter, self.block_len, f, out)
}

// ─── 4. Hasher (multi-chunk tree) ────────────────────────────────────────────

///|
pub struct Blake3State {
  // Key words (IV for default mode, derived from key for keyed/derive_key).
  key : FixedArray[UInt]
  flags : Int
  // Current incremental chunk state.
  mut chunk : Blake3ChunkState
  // Stack of pending chaining values whose right sibling has not arrived.
  cv_stack : Array[FixedArray[UInt]]
}

///|
/// New default-mode (unkeyed) BLAKE3 hasher.
pub fn Blake3State::new() -> Blake3State {
  let key = blake3_copy_cv(blake3_iv)
  { key, flags: 0, chunk: Blake3ChunkState::new(key, 0UL, 0), cv_stack: [] }
}

///|
/// New keyed BLAKE3 hasher. `key` must be exactly 32 bytes.
pub fn Blake3State::new_keyed(key : Bytes) -> Blake3State raise Blake3Error {
  if key.length() != 32 {
    raise InvalidBlake3KeyLength
  }
  let key_words = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    let p = i * 4
    let b0 = key[p].to_uint()
    let b1 = key[p + 1].to_uint()
    let b2 = key[p + 2].to_uint()
    let b3 = key[p + 3].to_uint()
    key_words.unsafe_set(i, b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
  }
  {
    key: key_words,
    flags: blake3_flag_keyed_hash,
    chunk: Blake3ChunkState::new(key_words, 0UL, blake3_flag_keyed_hash),
    cv_stack: [],
  }
}

///|
/// New derive_key BLAKE3 hasher. `context` should be a hard-coded UTF-8
/// label per the spec.
pub fn Blake3State::new_derive_key(context : String) -> Blake3State {
  // 1. Hash the context with DERIVE_KEY_CONTEXT flag to produce a 32-byte
  //    pseudo-random key.
  let ctx_bytes = @utf8.encode(context[:])
  let ctx_hasher_key = blake3_copy_cv(blake3_iv)
  let ctx_hasher = {
    key: ctx_hasher_key,
    flags: blake3_flag_derive_key_context,
    chunk: Blake3ChunkState::new(
      ctx_hasher_key, 0UL, blake3_flag_derive_key_context,
    ),
    cv_stack: [],
  }
  ctx_hasher.update(ctx_bytes)
  let ctx_key_bytes = ctx_hasher.finalize(32)
  // 2. Use that 32-byte key with DERIVE_KEY_MATERIAL flag.
  let key_words = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    let p = i * 4
    let b0 = ctx_key_bytes[p].to_uint()
    let b1 = ctx_key_bytes[p + 1].to_uint()
    let b2 = ctx_key_bytes[p + 2].to_uint()
    let b3 = ctx_key_bytes[p + 3].to_uint()
    key_words.unsafe_set(i, b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
  }
  {
    key: key_words,
    flags: blake3_flag_derive_key_material,
    chunk: Blake3ChunkState::new(
      key_words, 0UL, blake3_flag_derive_key_material,
    ),
    cv_stack: [],
  }
}

///|
/// Merge two child CVs into a parent CV (or root output) using the PARENT
/// flag. Counter is 0, block_len is 64.
fn blake3_parent_compress(
  key : FixedArray[UInt],
  flags : Int,
  left : FixedArray[UInt],
  right : FixedArray[UInt],
  extra_flags : Int,
  out : FixedArray[UInt],
) -> Unit {
  let m = FixedArray::make(16, 0U)
  for i = 0; i < 8; i = i + 1 {
    m.unsafe_set(i, left.unsafe_get(i))
    m.unsafe_set(i + 8, right.unsafe_get(i))
  }
  blake3_compress(
    key,
    m,
    0UL,
    blake3_block_len_bytes,
    flags | blake3_flag_parent | extra_flags,
    out,
  )
}

///|
/// Pop CVs off the stack and merge with `new_cv` while the next-chunk-count
/// has a 1 bit at the corresponding depth. Spec §2.2 pseudocode.
fn Blake3State::add_chunk_cv(
  self : Blake3State,
  cv_in : FixedArray[UInt],
  total_chunks : UInt64,
) -> Unit {
  let mut cv = cv_in
  let mut t = total_chunks
  while (t & 1UL) == 0UL {
    // Right child: merge with stack top, demoting it to a parent.
    let left = self.cv_stack.pop().unwrap()
    let out = FixedArray::make(16, 0U)
    blake3_parent_compress(self.key, self.flags, left, cv, 0, out)
    cv = FixedArray::make(8, 0U)
    for i = 0; i < 8; i = i + 1 {
      cv.unsafe_set(i, out.unsafe_get(i))
    }
    t = t >> 1
  }
  self.cv_stack.push(cv)
}

///|
pub fn Blake3State::update(self : Blake3State, data : Bytes) -> Unit {
  let n = data.length()
  let mut pos = 0
  while pos < n {
    // If the current chunk is full, finalize it (non-root), push CV.
    if self.chunk.len() == blake3_chunk_len_bytes {
      let chunk_out = FixedArray::make(16, 0U)
      self.chunk.output_words(0, chunk_out)
      let chunk_cv = FixedArray::make(8, 0U)
      for i = 0; i < 8; i = i + 1 {
        chunk_cv.unsafe_set(i, chunk_out.unsafe_get(i))
      }
      let next_chunk_counter = self.chunk.chunk_counter + 1UL
      self.add_chunk_cv(chunk_cv, next_chunk_counter)
      self.chunk = Blake3ChunkState::new(
        self.key,
        next_chunk_counter,
        self.flags,
      )
    }
    let consumed = self.chunk.update(data, pos, n)
    pos += consumed
  }
}

///|
/// Produce `out_len` bytes from the final root output. XOF: extend by
/// incrementing the output counter and concatenating blake3_compress() blocks.
pub fn Blake3State::finalize(self : Blake3State, out_len : Int) -> Bytes {
  // Build the root output: chain stack pops on the current chunk CV to
  // arrive at the single tree root, then mark it ROOT.
  // Walk the stack from top to bottom, merging with the rightmost CV.
  // The rightmost CV starts as the current chunk's output (non-root,
  // unless the stack is empty).
  if self.cv_stack.length() == 0 {
    // Single chunk in the entire input: the chunk itself is root.
    let root_words = FixedArray::make(16, 0U)
    self.chunk.output_words(blake3_flag_root, root_words)
    return blake3_xof_from_root(
      self.chunk.cv,
      self.flags,
      self.chunk_root_block(),
      self.chunk.block_len,
      self.chunk.chunk_counter,
      self.chunk.flags | self.chunk.start_flag() | blake3_flag_chunk_end,
      false, // not parent
      out_len,
      root_words,
    )
  }
  // Multi-chunk: finalize the current (rightmost) chunk non-root.
  let chunk_out = FixedArray::make(16, 0U)
  self.chunk.output_words(0, chunk_out)
  let mut right_cv = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    right_cv.unsafe_set(i, chunk_out.unsafe_get(i))
  }
  // Pop all but the last; each pop is a non-root parent merge.
  let stack_len = self.cv_stack.length()
  let mut i = stack_len - 1
  while i > 0 {
    let left = self.cv_stack[i]
    let pout = FixedArray::make(16, 0U)
    blake3_parent_compress(self.key, self.flags, left, right_cv, 0, pout)
    right_cv = FixedArray::make(8, 0U)
    for j = 0; j < 8; j = j + 1 {
      right_cv.unsafe_set(j, pout.unsafe_get(j))
    }
    i -= 1
  }
  // Final pop: this is the root parent merge.
  let root_left = self.cv_stack[0]
  // For XOF we need the (key, block_words, counter, block_len, flags) tuple
  // that the *root* compression uses. For a parent root, that is:
  //   cv = self.key, block_words = left || right, counter = 0,
  //   block_len = 64, flags = self.flags | PARENT | ROOT (+ counter increments).
  let root_block_words = FixedArray::make(16, 0U)
  for k = 0; k < 8; k = k + 1 {
    root_block_words.unsafe_set(k, root_left.unsafe_get(k))
    root_block_words.unsafe_set(k + 8, right_cv.unsafe_get(k))
  }
  let dummy = FixedArray::make(16, 0U)
  blake3_xof_from_root(
    self.key,
    self.flags,
    root_block_words,
    blake3_block_len_bytes,
    0UL,
    self.flags | blake3_flag_parent,
    true,
    out_len,
    dummy,
  )
}

///|
/// Helper: snapshot the chunk's current 64-byte block padded with zeros.
fn Blake3State::chunk_root_block(self : Blake3State) -> FixedArray[UInt] {
  let words = FixedArray::make(16, 0U)
  blake3_load_block_le(self.chunk.block, 0, words)
  words
}

///|
/// XOF expansion. `root_extra_flags` should include PARENT if applicable.
/// We re-compress with ROOT flag set and counter = output_counter to emit
/// 64-byte output blocks until out_len bytes are produced.
fn blake3_xof_from_root(
  cv : FixedArray[UInt],
  _hasher_flags : Int,
  block_words : FixedArray[UInt],
  block_len : Int,
  base_counter : UInt64, // chunk counter for chunk-root, 0 for parent-root
  flags_no_root : Int,
  is_parent : Bool,
  out_len : Int,
  _unused : FixedArray[UInt],
) -> Bytes {
  // For chunk-root XOF, counter increments output blocks (per spec).
  // For parent-root XOF, base_counter is 0 and we also increment.
  let _ = is_parent // not needed beyond commentary
  let out_bytes = FixedArray::make(out_len, b'\x00')
  let mut produced = 0
  let mut output_counter = base_counter
  let buf = FixedArray::make(16, 0U)
  while produced < out_len {
    blake3_compress(
      cv,
      block_words,
      output_counter,
      block_len,
      flags_no_root | blake3_flag_root,
      buf,
    )
    let remain = out_len - produced
    let take = if remain < 64 { remain } else { 64 }
    for i = 0; i < take; i = i + 1 {
      let w = buf.unsafe_get(i / 4)
      let shift = i % 4 * 8
      out_bytes.unsafe_set(produced + i, (w >> shift).to_byte())
    }
    produced += take
    output_counter = output_counter + 1UL
  }
  Bytes::makei(out_len, fn(j) { out_bytes.unsafe_get(j) })
}

// ─── 5. One-shot helpers ─────────────────────────────────────────────────────

///|
/// Default BLAKE3: 32-byte digest.
pub fn blake3(data : Bytes) -> Bytes {
  let h = Blake3State::new()
  h.update(data)
  h.finalize(32)
}

///|
/// Extendable output. `out_len` may be any non-negative integer.
pub fn blake3_xof(data : Bytes, out_len : Int) -> Bytes {
  let h = Blake3State::new()
  h.update(data)
  h.finalize(out_len)
}

///|
/// Keyed BLAKE3 (BLAKE3 MAC). `key` must be 32 bytes.
pub fn blake3_keyed(
  key : Bytes,
  data : Bytes,
  out_len : Int,
) -> Bytes raise Blake3Error {
  let h = Blake3State::new_keyed(key)
  h.update(data)
  h.finalize(out_len)
}

///|
/// derive_key: BLAKE3 KDF mode. Returns 32 bytes by default; use the state
/// API for arbitrary lengths.
pub fn blake3_derive_key(context : String, key_material : Bytes) -> Bytes {
  let h = Blake3State::new_derive_key(context)
  h.update(key_material)
  h.finalize(32)
}
