// SHA-3 / SHAKE (FIPS 202) on the Keccak-f[1600] permutation. Pure UInt64;
// the state is 25 lanes indexed `x + 5*y`, lanes are little-endian on the wire.
//
// Provided: sha3_256, sha3_512, shake128(out_len), shake256(out_len). These are
// the primitives ML-KEM (FIPS 203) builds on (G = SHA3-512, H = SHA3-256,
// PRF/XOF = SHAKE256 / SHAKE128).

///|
let keccak_rc : Array[UInt64] = [
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
  0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

///|
// Rotation offsets r[x][y] laid out flat as `x + 5*y`.
let keccak_rho : Array[Int] = [
  0, 1, 62, 28, 27, // y=0
   36, 44, 6, 55, 20, // y=1
   3, 10, 43, 25, 39, // y=2
   41, 45, 15, 21, 8, // y=3
   18, 2, 61, 56, 14, // y=4
]

///|
fn rotl64(x : UInt64, n : Int) -> UInt64 {
  if n == 0 {
    x
  } else {
    (x << n) | (x >> (64 - n))
  }
}

///|
fn keccak_f(a : FixedArray[UInt64]) -> Unit {
  let b = FixedArray::make(25, 0UL)
  let c = FixedArray::make(5, 0UL)
  let d = FixedArray::make(5, 0UL)
  for round in 0..<24 {
    // θ
    for x in 0..<5 {
      c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]
    }
    for x in 0..<5 {
      d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1)
    }
    for x in 0..<5 {
      for y in 0..<5 {
        a[x + 5 * y] = a[x + 5 * y] ^ d[x]
      }
    }
    // ρ and π: B[y, (2x+3y) mod 5] = rotl(A[x,y], rho[x,y])
    for x in 0..<5 {
      for y in 0..<5 {
        let nx = y
        let ny = (2 * x + 3 * y) % 5
        b[nx + 5 * ny] = rotl64(a[x + 5 * y], keccak_rho[x + 5 * y])
      }
    }
    // χ
    for x in 0..<5 {
      for y in 0..<5 {
        a[x + 5 * y] = b[x + 5 * y] ^
          (b[(x + 1) % 5 + 5 * y].lnot() & b[(x + 2) % 5 + 5 * y])
      }
    }
    // ι
    a[0] = a[0] ^ keccak_rc[round]
  }
}

///|
fn load_lane(data : FixedArray[Byte], off : Int) -> UInt64 {
  let mut v = 0UL
  for i in 0..<8 {
    v = v | (data[off + i].to_uint64() << (8 * i))
  }
  v
}

///|
/// Keccak sponge: absorb `input` at `rate_bytes`, append domain `suffix`, then
/// squeeze `out_len` bytes.
fn keccak(
  rate_bytes : Int,
  suffix : Int,
  input : Bytes,
  out_len : Int,
) -> Bytes {
  let state = FixedArray::make(25, 0UL)
  let rate_lanes = rate_bytes / 8
  let block = FixedArray::make(rate_bytes, b'\x00')
  // absorb full blocks
  let mut i = 0
  while i + rate_bytes <= input.length() {
    for j in 0..<rate_bytes {
      block[j] = input[i + j]
    }
    for l in 0..<rate_lanes {
      state[l] = state[l] ^ load_lane(block, l * 8)
    }
    keccak_f(state)
    i = i + rate_bytes
  }
  // final (partial) block with pad10*1 + domain suffix
  let rem = input.length() - i
  for j in 0..<rate_bytes {
    block[j] = b'\x00'
  }
  for j in 0..<rem {
    block[j] = input[i + j]
  }
  block[rem] = suffix.to_byte()
  block[rate_bytes - 1] = (block[rate_bytes - 1].to_int() | 0x80).to_byte()
  for l in 0..<rate_lanes {
    state[l] = state[l] ^ load_lane(block, l * 8)
  }
  keccak_f(state)
  // squeeze
  let out = FixedArray::make(out_len, b'\x00')
  let mut produced = 0
  while produced < out_len {
    let take = if out_len - produced < rate_bytes {
      out_len - produced
    } else {
      rate_bytes
    }
    for k in 0..<take {
      // byte k of the state's little-endian lane view
      let lane = state[k / 8]
      out[produced + k] = ((lane >> (8 * (k % 8))) & 0xffUL).to_int().to_byte()
    }
    produced = produced + take
    if produced < out_len {
      keccak_f(state)
    }
  }
  Bytes::makei(out_len, fn(j) { out[j] })
}

///|
/// SHA3-256 (FIPS 202): 32-byte digest, rate 136, domain suffix 0x06.
pub fn sha3_256(data : Bytes) -> Bytes {
  keccak(136, 0x06, data, 32)
}

///|
/// SHA3-512 (FIPS 202): 64-byte digest, rate 72, domain suffix 0x06.
pub fn sha3_512(data : Bytes) -> Bytes {
  keccak(72, 0x06, data, 64)
}

///|
/// SHAKE128 XOF (FIPS 202): rate 168, domain suffix 0x1f, `out_len` bytes.
pub fn shake128(data : Bytes, out_len : Int) -> Bytes {
  keccak(168, 0x1f, data, out_len)
}

///|
/// SHAKE256 XOF (FIPS 202): rate 136, domain suffix 0x1f, `out_len` bytes.
pub fn shake256(data : Bytes, out_len : Int) -> Bytes {
  keccak(136, 0x1f, data, out_len)
}
