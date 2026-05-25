// X25519 (RFC 7748) ECDH using the Montgomery ladder on Curve25519.
//
// Implementation note: field arithmetic delegates to @bigint, which is NOT
// constant-time. This module's API surface is the right shape for crypto
// callers, but the inner ladder leaks timing through @bigint's variable-time
// multiplication and modular reduction. A radix-2^51 limb representation is
// the natural follow-up.

///|
pub struct PrivateKey {
  bytes : FixedArray[Byte] // 32 bytes, clamped per RFC 7748 §5
} derive(Eq)

///|
pub impl Show for PrivateKey with fn output(self, logger) {
  ignore(self)
  logger.write_string("PrivateKey(<redacted>)")
}

///|
pub struct PublicKey {
  bytes : FixedArray[Byte] // 32 bytes
} derive(Eq, Show)

///|
pub struct SharedSecret {
  bytes : FixedArray[Byte] // 32 bytes
} derive(Eq)

///|
pub impl Show for SharedSecret with fn output(self, logger) {
  ignore(self)
  logger.write_string("SharedSecret(<redacted>)")
}

///|
pub fn SharedSecret::to_bytes(self : SharedSecret) -> Bytes {
  Bytes::makei(32, fn(i) { self.bytes[i] })
}

///|
pub suberror X25519Error {
  InvalidScalarLength(Int)
  InvalidPointLength(Int)
  AllZeroSharedSecret // small-subgroup attack signal
} derive(Show)

///|
fn ensure_32_bytes(
  b : Bytes,
  msg : (Int) -> X25519Error,
) -> FixedArray[Byte] raise X25519Error {
  if b.length() != 32 {
    raise msg(b.length())
  }
  let fa = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    fa[i] = b[i]
  }
  fa
}

///|
fn clamp_scalar(fa : FixedArray[Byte]) -> FixedArray[Byte] {
  let out = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    out[i] = fa[i]
  }
  out[0] = (out[0].to_int() & 248).to_byte()
  out[31] = (out[31].to_int() & 127).to_byte()
  out[31] = (out[31].to_int() | 64).to_byte()
  out
}

///|
pub fn PrivateKey::from_bytes(b : Bytes) -> PrivateKey raise X25519Error {
  let fa = ensure_32_bytes(b, fn(n) { InvalidScalarLength(n) })
  { bytes: clamp_scalar(fa) }
}

///|
pub fn PrivateKey::to_bytes(self : PrivateKey) -> Bytes {
  Bytes::makei(32, fn(i) { self.bytes[i] })
}

///|
pub fn PrivateKey::from_random(
  random_32_bytes : Bytes,
) -> PrivateKey raise X25519Error {
  PrivateKey::from_bytes(random_32_bytes)
}

///|
pub fn PrivateKey::public_key(self : PrivateKey) -> PublicKey {
  // X25519(scalar, base point u=9)
  let base = FixedArray::make(32, b'\x00')
  base[0] = b'\x09'
  let u_bytes = scalarmult_unchecked(self.bytes, base)
  { bytes: u_bytes }
}

///|
pub fn PublicKey::from_bytes(b : Bytes) -> PublicKey raise X25519Error {
  let fa = ensure_32_bytes(b, fn(n) { InvalidPointLength(n) })
  { bytes: fa }
}

///|
pub fn PublicKey::to_bytes(self : PublicKey) -> Bytes {
  Bytes::makei(32, fn(i) { self.bytes[i] })
}

///|
pub fn diffie_hellman(
  sk : PrivateKey,
  pk : PublicKey,
) -> SharedSecret raise X25519Error {
  let out = scalarmult_unchecked(sk.bytes, pk.bytes)
  // RFC 7748 §6.1: an all-zero output indicates a small-subgroup point.
  let mut all_zero = true
  for i in 0..<32 {
    if out[i].to_int() != 0 {
      all_zero = false
      break
    }
  }
  if all_zero {
    raise AllZeroSharedSecret
  }
  { bytes: out }
}

// ─── field arithmetic over GF(2^255 - 19) using @bigint ──────────────────

///|
let prime : BigInt = BigInt::from_int(1).lsl(255) - BigInt::from_int(19)

///|
let a24 : BigInt = BigInt::from_int(121665)

///|
fn fe_from_le_bytes(b : FixedArray[Byte]) -> BigInt {
  // little-endian, mask off the high bit of the last byte per RFC 7748 §5
  let mut v : BigInt = BigInt::from_int(0)
  for i = 31; i >= 0; i = i - 1 {
    let bv = if i == 31 {
      // Clear bit 255 (RFC 7748 §5 step 5).
      b[i].to_int() & 0x7F
    } else {
      b[i].to_int()
    }
    v = v.lsl(8) + BigInt::from_int(bv)
  }
  v
}

///|
fn fe_to_le_bytes(v : BigInt) -> FixedArray[Byte] {
  let out = FixedArray::make(32, b'\x00')
  let mask = BigInt::from_int(0xFF)
  let mut x = (v % prime + prime) % prime
  for i in 0..<32 {
    let byte = (x & mask).to_int() & 0xFF
    out[i] = byte.to_byte()
    x = x.shr(8)
  }
  out
}

///|
fn scalarmult_unchecked(
  scalar : FixedArray[Byte],
  u : FixedArray[Byte],
) -> FixedArray[Byte] {
  let s = clamp_scalar(scalar)
  let u_int = fe_from_le_bytes(u)
  let p = prime
  let x1 = u_int
  let mut x2 : BigInt = BigInt::from_int(1)
  let mut z2 : BigInt = BigInt::from_int(0)
  let mut x3 : BigInt = u_int
  let mut z3 : BigInt = BigInt::from_int(1)
  let mut swap_bit = 0
  for t = 254; t >= 0; t = t - 1 {
    let k_t = (s[t / 8].to_int() >> (t % 8)) & 1
    swap_bit = swap_bit ^ k_t
    if swap_bit == 1 {
      let tmp_x = x2
      x2 = x3
      x3 = tmp_x
      let tmp_z = z2
      z2 = z3
      z3 = tmp_z
    }
    swap_bit = k_t
    let a = mod_p(x2 + z2)
    let aa = mod_p(a * a)
    let b = mod_p(x2 - z2)
    let bb = mod_p(b * b)
    let e = mod_p(aa - bb)
    let c = mod_p(x3 + z3)
    let d = mod_p(x3 - z3)
    let da = mod_p(d * a)
    let cb = mod_p(c * b)
    let sum = mod_p(da + cb)
    let diff = mod_p(da - cb)
    x3 = mod_p(sum * sum)
    z3 = mod_p(x1 * mod_p(diff * diff))
    x2 = mod_p(aa * bb)
    z2 = mod_p(e * mod_p(aa + a24 * e))
    ignore(p)
  }
  if swap_bit == 1 {
    let tmp_x = x2
    x2 = x3
    x3 = tmp_x
    let tmp_z = z2
    z2 = z3
    z3 = tmp_z
  }
  let z_inv = z2.pow(prime - BigInt::from_int(2), modulus=prime)
  let result = mod_p(x2 * z_inv)
  fe_to_le_bytes(result)
}

///|
fn mod_p(x : BigInt) -> BigInt {
  (x % prime + prime) % prime
}
