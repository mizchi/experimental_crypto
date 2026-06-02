// RSA key-pair generation (the RSA half of #24 / SubtleCrypto generateKey).
//
// Two distinct random probable-primes p, q of `bits/2` each (top two bits set
// so n is exactly `bits` long, low bit set so they're odd), with the public
// exponent e = 65537 forced coprime to p-1 and q-1; then n = p·q and
// d = e⁻¹ mod λ(n) where λ = lcm(p-1, q-1) (RFC 8017 / FIPS 186-5). Primality
// is small-prime trial division followed by Miller–Rabin with random bases.
//
// This is NOT constant-time and is not hardened against fault attacks; it is a
// from-scratch generator for test / tooling use. Pure @bigint math makes large
// sizes slow — prefer 2048+ in production, but expect multi-second cost.

///|
fn bi(n : Int) -> BigInt {
  BigInt::from_int(n)
}

///|
// First primes for trial division — cheaply rejects ~80% of odd candidates
// before the expensive Miller–Rabin modexps.
let small_primes : Array[Int] = [
  3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79,
  83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
  173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
]

///|
// A uniform-ish BigInt in [0, limit) from the CSPRNG (a few extra random bytes
// then reduced mod limit — the modulo bias is negligible for our uses).
fn random_below(limit : BigInt) -> BigInt raise KeygenError {
  let byte_len = limit.to_octets().length() + 8
  BigInt::from_octets(draw(byte_len)[:]) % limit
}

///|
// A `bits`-bit odd integer with the top two bits set.
fn random_prime_candidate(bits : Int) -> BigInt raise KeygenError {
  let nbytes = (bits + 7) / 8
  let raw = draw(nbytes)
  let buf = FixedArray::makei(nbytes, fn(i) { raw[i] })
  buf[0] = (buf[0].to_int() | 0xc0).to_byte() // top two bits
  buf[nbytes - 1] = (buf[nbytes - 1].to_int() | 0x01).to_byte() // odd
  BigInt::from_octets(Bytes::makei(nbytes, fn(i) { buf[i] })[:])
}

///|
fn is_even(n : BigInt) -> Bool {
  (n % bi(2)).compare(bi(0)) == 0
}

///|
// Miller–Rabin with `rounds` random bases. Assumes `n` is odd and > 3.
fn miller_rabin(n : BigInt, rounds : Int) -> Bool raise KeygenError {
  let one = bi(1)
  let two = bi(2)
  let n_minus_1 = n - one
  // n - 1 = 2^s · d  with d odd.
  let mut d = n_minus_1
  let mut s = 0
  while is_even(d) {
    d = d / two
    s = s + 1
  }
  for _round in 0..<rounds {
    // base a ∈ [2, n-2]
    let a = two + random_below(n - bi(3))
    let mut x = a.pow(d, modulus=n)
    if x.compare(one) == 0 || x.compare(n_minus_1) == 0 {
      continue
    }
    let mut composite = true
    for _i in 0..<(s - 1) {
      x = x.pow(two, modulus=n)
      if x.compare(n_minus_1) == 0 {
        composite = false
        break
      }
    }
    if composite {
      return false
    }
  }
  true
}

///|
fn is_probable_prime(n : BigInt, rounds : Int) -> Bool raise KeygenError {
  if n.compare(bi(2)) < 0 {
    return false
  }
  for p in small_primes {
    let pb = bi(p)
    if (n % pb).compare(bi(0)) == 0 {
      return n.compare(pb) == 0
    }
  }
  miller_rabin(n, rounds)
}

///|
// gcd via Euclid (inputs non-negative).
fn bigint_gcd(a : BigInt, b : BigInt) -> BigInt {
  let mut x = a
  let mut y = b
  while y.compare(BigInt::from_int(0)) != 0 {
    let r = x % y
    x = y
    y = r
  }
  x
}

///|
// Modular inverse of a mod m via the extended Euclidean algorithm. Aborts only
// if a and m are not coprime (the caller guarantees gcd(e, λ) = 1).
fn mod_inverse(a : BigInt, m : BigInt) -> BigInt {
  let zero = BigInt::from_int(0)
  let one = BigInt::from_int(1)
  let mut old_r = a % m
  let mut r = m
  let mut old_s = one
  let mut s = zero
  while r.compare(zero) != 0 {
    let q = old_r / r
    let new_r = old_r - q * r
    old_r = r
    r = new_r
    let new_s = old_s - q * s
    old_s = s
    s = new_s
  }
  // old_s is the inverse (mod m); normalise into [0, m).
  let mut inv = old_s % m
  if inv.compare(zero) < 0 {
    inv = inv + m
  }
  inv
}

///|
// Generate one probable-prime of `bits` bits such that p-1 is coprime to e.
fn generate_prime(bits : Int, e : BigInt) -> BigInt raise KeygenError {
  let rounds = 40
  for _attempt in 0..<100000 {
    let cand = random_prime_candidate(bits)
    if bigint_gcd(e, cand - bi(1)).compare(bi(1)) != 0 {
      continue
    }
    if is_probable_prime(cand, rounds) {
      return cand
    }
  }
  raise PrimeSearchExhausted
}

///|
/// Generate an RSA key pair with an `bits`-bit modulus (`bits` even, ≥ 512) and
/// public exponent 65537. Returns the private key; the public key is
/// `result.public_key()`.
///
/// Cost grows steeply with `bits` (pure-bigint Miller–Rabin). 512/1024 are fine
/// for tests; 2048+ is correct but slow.
pub fn rsa_keypair(bits : Int) -> @rsa.RsaPrivateKey raise KeygenError {
  if bits < 512 || bits % 2 != 0 {
    raise InvalidBits(bits)
  }
  let e = bi(65537)
  let half = bits / 2
  let p = generate_prime(half, e)
  let mut q = generate_prime(half, e)
  // Ensure p != q (vanishingly unlikely to collide, but be safe).
  while q.compare(p) == 0 {
    q = generate_prime(half, e)
  }
  let n = p * q
  // λ(n) = lcm(p-1, q-1)
  let p1 = p - bi(1)
  let q1 = q - bi(1)
  let lambda = p1 * q1 / bigint_gcd(p1, q1)
  let d = mod_inverse(e, lambda)
  @rsa.RsaPrivateKey::{ n, e, d, n_bytes_len: (n.bit_length() + 7) / 8 }
}
