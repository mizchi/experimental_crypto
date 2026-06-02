// ML-KEM-768 (FIPS 203) — the post-quantum KEM used (hybridised with X25519)
// as the default TLS 1.3 key exchange in current browsers.
//
// Parameters: n=256, q=3329, k=3, η1=η2=2, du=10, dv=4. Hashes/XOFs come from
// the sha3 module (G=SHA3-512, H=SHA3-256, J/PRF=SHAKE256, XOF=SHAKE128).
//
// This is a straightforward (not constant-time, not fault-hardened) reference
// implementation, validated byte-for-byte against the published ML-KEM-768 KAT.
// `Int` stays 32-bit-safe by reducing mod q before every re-multiplication.

///|
let q : Int = 3329

///|
let kk : Int = 3 // module rank (ML-KEM-768)

///|
let eta : Int = 2 // η1 = η2 = 2

///|
let du : Int = 10

///|
let dv : Int = 4

///|
// 17^BitRev7(i) mod q, for the NTT butterflies.
let zetas : Array[Int] = [
  1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569,
  1746, 296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393,
  2879, 1974, 821, 289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513,
  632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647,
  2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100,
  1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952,
  1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037, 3220,
  375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092,
  403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
]

///|
// 17^(2*BitRev7(i)+1) mod q, for base-case multiplication of NTT products.
let gammas : Array[Int] = [
  17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100,
  2229, 1409, 1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015,
  314, 3050, 279, 1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952,
  2377, 1461, 1868, 2687, 642, 939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733,
  2596, 2337, 992, 268, 3061, 641, 2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220,
  109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684, 1063, 2266, 319, 3010, 2773,
  556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735, 2804, 525, 1092, 2237,
  403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 1722, 1607,
  1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
]

///|
fn mq(x : Int) -> Int {
  let r = x % q
  if r < 0 {
    r + q
  } else {
    r
  }
}

///|
fn new_poly() -> FixedArray[Int] {
  FixedArray::make(256, 0)
}

///|
fn poly_copy(p : FixedArray[Int]) -> FixedArray[Int] {
  FixedArray::makei(256, fn(i) { p[i] })
}

// ─── NTT ─────────────────────────────────────────────────────────────────────

///|
fn ntt(f : FixedArray[Int]) -> FixedArray[Int] {
  let a = poly_copy(f)
  let mut i = 1
  let mut len = 128
  while len >= 2 {
    let mut start = 0
    while start < 256 {
      let zeta = zetas[i]
      i = i + 1
      for j in start..<(start + len) {
        let t = mq(zeta * a[j + len])
        a[j + len] = mq(a[j] - t)
        a[j] = mq(a[j] + t)
      }
      start = start + 2 * len
    }
    len = len / 2
  }
  a
}

///|
fn intt(f : FixedArray[Int]) -> FixedArray[Int] {
  let a = poly_copy(f)
  let mut i = 127
  let mut len = 2
  while len <= 128 {
    let mut start = 0
    while start < 256 {
      let zeta = zetas[i]
      i = i - 1
      for j in start..<(start + len) {
        let t = a[j]
        a[j] = mq(t + a[j + len])
        a[j + len] = mq(zeta * (a[j + len] - t))
      }
      start = start + 2 * len
    }
    len = len * 2
  }
  for j in 0..<256 {
    a[j] = mq(a[j] * 3303) // 128^-1 mod q
  }
  a
}

///|
// Base-case multiply of two NTT-domain polynomials (Algorithm 11/12).
fn ntt_mul(f : FixedArray[Int], g : FixedArray[Int]) -> FixedArray[Int] {
  let h = new_poly()
  for i in 0..<128 {
    let a0 = f[2 * i]
    let a1 = f[2 * i + 1]
    let b0 = g[2 * i]
    let b1 = g[2 * i + 1]
    let gamma = gammas[i]
    h[2 * i] = mq(a0 * b0 + mq(a1 * b1) * gamma)
    h[2 * i + 1] = mq(a0 * b1 + a1 * b0)
  }
  h
}

///|
fn poly_add(f : FixedArray[Int], g : FixedArray[Int]) -> FixedArray[Int] {
  FixedArray::makei(256, fn(i) { mq(f[i] + g[i]) })
}

///|
fn poly_sub(f : FixedArray[Int], g : FixedArray[Int]) -> FixedArray[Int] {
  FixedArray::makei(256, fn(i) { mq(f[i] - g[i]) })
}

// ─── compress / decompress ─────────────────────────────────────────────────

///|
fn compress(x : Int, d : Int) -> Int {
  // round(2^d / q * x) mod 2^d
  ((x * (1 << d) + q / 2) / q) & ((1 << d) - 1)
}

///|
fn decompress(y : Int, d : Int) -> Int {
  (q * y + (1 << (d - 1))) >> d
}

// ─── bit-packed byte encode / decode ─────────────────────────────────────────

///|
// ByteEncode_d: 256 integers (each d bits) → 32*d bytes, LSB-first.
fn byte_encode(f : FixedArray[Int], d : Int) -> Bytes {
  let out = FixedArray::make(32 * d, b'\x00')
  let mut bitpos = 0
  for i in 0..<256 {
    let v = f[i]
    for b in 0..<d {
      if ((v >> b) & 1) == 1 {
        let byte_i = bitpos / 8
        out[byte_i] = (out[byte_i].to_int() | (1 << (bitpos % 8))).to_byte()
      }
      bitpos = bitpos + 1
    }
  }
  Bytes::makei(32 * d, fn(i) { out[i] })
}

///|
// ByteDecode_d: inverse. Reduces mod q when d==12, else mod 2^d.
fn byte_decode(data : Bytes, off : Int, d : Int) -> FixedArray[Int] {
  let f = new_poly()
  let m = if d < 12 { 1 << d } else { q }
  let mut bitpos = 0
  for i in 0..<256 {
    let mut v = 0
    for b in 0..<d {
      let abs = off * 8 + bitpos
      let bit = (data[abs / 8].to_int() >> (abs % 8)) & 1
      v = v | (bit << b)
      bitpos = bitpos + 1
    }
    f[i] = v % m
  }
  f
}

///|
fn compress_poly(f : FixedArray[Int], d : Int) -> FixedArray[Int] {
  FixedArray::makei(256, fn(i) { compress(f[i], d) })
}

///|
fn decompress_poly(f : FixedArray[Int], d : Int) -> FixedArray[Int] {
  FixedArray::makei(256, fn(i) { decompress(f[i], d) })
}

// ─── sampling ────────────────────────────────────────────────────────────────

///|
fn concat3(a : Bytes, b : Int, c : Int) -> Bytes {
  Bytes::makei(a.length() + 2, fn(i) {
    if i < a.length() {
      a[i]
    } else if i == a.length() {
      b.to_byte()
    } else {
      c.to_byte()
    }
  })
}

///|
// SampleNTT (Algorithm 7): rejection-sample a NTT-domain poly from a SHAKE128
// stream seeded by rho || j || i.
fn sample_ntt(rho : Bytes, j : Int, i : Int) -> FixedArray[Int] {
  let seed = concat3(rho, j, i)
  // 1344 bytes (8 SHAKE128 blocks) is far beyond what 256 coeffs ever need;
  // squeezing it once is byte-identical to incremental squeezing.
  let stream = @sha3.shake128(seed, 1344)
  let a = new_poly()
  let mut ji = 0
  let mut ci = 0
  while ci < 256 {
    let b0 = stream[ji].to_int()
    let b1 = stream[ji + 1].to_int()
    let b2 = stream[ji + 2].to_int()
    ji = ji + 3
    let d1 = b0 + 256 * (b1 % 16)
    let d2 = b1 / 16 + 16 * b2
    if d1 < q {
      a[ci] = d1
      ci = ci + 1
    }
    if d2 < q && ci < 256 {
      a[ci] = d2
      ci = ci + 1
    }
  }
  a
}

///|
fn prf(s : Bytes, b : Int) -> Bytes {
  let inp = Bytes::makei(s.length() + 1, fn(i) {
    if i < s.length() {
      s[i]
    } else {
      b.to_byte()
    }
  })
  @sha3.shake256(inp, 64 * eta)
}

///|
// SamplePolyCBD_eta (Algorithm 8) for η=2 from a 64η-byte PRF output.
fn sample_cbd(bytes : Bytes) -> FixedArray[Int] {
  let f = new_poly()
  fn bit(idx : Int) -> Int {
    (bytes[idx / 8].to_int() >> (idx % 8)) & 1
  }

  for i in 0..<256 {
    let mut x = 0
    let mut y = 0
    for k in 0..<eta {
      x = x + bit(2 * i * eta + k)
    }
    for k in 0..<eta {
      y = y + bit(2 * i * eta + eta + k)
    }
    f[i] = mq(x - y)
  }
  f
}

// ─── K-PKE ─────────────────────────────────────────────────────────────────

///|
fn g(input : Bytes) -> (Bytes, Bytes) {
  let h = @sha3.sha3_512(input)
  (Bytes::makei(32, fn(i) { h[i] }), Bytes::makei(32, fn(i) { h[32 + i] }))
}

///|
fn cat(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for p in parts {
    total += p.length()
  }
  let out = FixedArray::make(total, b'\x00')
  let mut off = 0
  for p in parts {
    for i in 0..<p.length() {
      out[off + i] = p[i]
    }
    off += p.length()
  }
  Bytes::makei(total, fn(i) { out[i] })
}

///|
// K-PKE.KeyGen(d) -> (ek_pke (1184), dk_pke (1152))
fn kpke_keygen(d : Bytes) -> (Bytes, Bytes) {
  let (rho, sigma) = g(cat([d, Bytes::makei(1, fn(_i) { kk.to_byte() })]))
  // matrix A_hat[i][j] = SampleNTT(XOF(rho, j, i))
  let a_hat : Array[Array[FixedArray[Int]]] = []
  for i in 0..<kk {
    let row : Array[FixedArray[Int]] = []
    for j in 0..<kk {
      row.push(sample_ntt(rho, j, i))
    }
    a_hat.push(row)
  }
  let mut counter = 0
  let s : Array[FixedArray[Int]] = []
  for _i in 0..<kk {
    s.push(sample_cbd(prf(sigma, counter)))
    counter = counter + 1
  }
  let e : Array[FixedArray[Int]] = []
  for _i in 0..<kk {
    e.push(sample_cbd(prf(sigma, counter)))
    counter = counter + 1
  }
  let s_hat = Array::makei(kk, fn(i) { ntt(s[i]) })
  let e_hat = Array::makei(kk, fn(i) { ntt(e[i]) })
  // t_hat = A_hat * s_hat + e_hat
  let t_hat : Array[FixedArray[Int]] = []
  for i in 0..<kk {
    let mut acc = new_poly()
    for j in 0..<kk {
      acc = poly_add(acc, ntt_mul(a_hat[i][j], s_hat[j]))
    }
    t_hat.push(poly_add(acc, e_hat[i]))
  }
  let ek = cat(Array::makei(kk, fn(i) { byte_encode(t_hat[i], 12) }) + [rho])
  let dk = cat(Array::makei(kk, fn(i) { byte_encode(s_hat[i], 12) }))
  (ek, dk)
}

///|
fn kpke_encrypt(ek : Bytes, m : Bytes, r : Bytes) -> Bytes {
  let t_hat = Array::makei(kk, fn(i) { byte_decode(ek, 384 * i, 12) })
  let rho = Bytes::makei(32, fn(i) { ek[384 * kk + i] })
  let a_hat : Array[Array[FixedArray[Int]]] = []
  for i in 0..<kk {
    let row : Array[FixedArray[Int]] = []
    for j in 0..<kk {
      row.push(sample_ntt(rho, j, i))
    }
    a_hat.push(row)
  }
  let mut counter = 0
  let y : Array[FixedArray[Int]] = []
  for _i in 0..<kk {
    y.push(sample_cbd(prf(r, counter)))
    counter = counter + 1
  }
  let e1 : Array[FixedArray[Int]] = []
  for _i in 0..<kk {
    e1.push(sample_cbd(prf(r, counter)))
    counter = counter + 1
  }
  let e2 = sample_cbd(prf(r, counter))
  let y_hat = Array::makei(kk, fn(i) { ntt(y[i]) })
  // u = NTT^-1(A_hat^T * y_hat) + e1
  let u : Array[FixedArray[Int]] = []
  for i in 0..<kk {
    let mut acc = new_poly()
    for j in 0..<kk {
      acc = poly_add(acc, ntt_mul(a_hat[j][i], y_hat[j]))
    }
    u.push(poly_add(intt(acc), e1[i]))
  }
  // v = NTT^-1(t_hat^T * y_hat) + e2 + Decompress1(m)
  let mut tv = new_poly()
  for i in 0..<kk {
    tv = poly_add(tv, ntt_mul(t_hat[i], y_hat[i]))
  }
  let mu = decompress_poly(byte_decode(m, 0, 1), 1)
  let v = poly_add(poly_add(intt(tv), e2), mu)
  let c1 = cat(
    Array::makei(kk, fn(i) { byte_encode(compress_poly(u[i], du), du) }),
  )
  let c2 = byte_encode(compress_poly(v, dv), dv)
  cat([c1, c2])
}

///|
fn kpke_decrypt(dk : Bytes, c : Bytes) -> Bytes {
  let u = Array::makei(kk, fn(i) {
    decompress_poly(byte_decode(c, 32 * du * i, du), du)
  })
  let v = decompress_poly(byte_decode(c, 32 * du * kk, dv), dv)
  let s_hat = Array::makei(kk, fn(i) { byte_decode(dk, 384 * i, 12) })
  // w = v - NTT^-1(s_hat^T * NTT(u))
  let mut acc = new_poly()
  for i in 0..<kk {
    acc = poly_add(acc, ntt_mul(s_hat[i], ntt(u[i])))
  }
  let w = poly_sub(v, intt(acc))
  byte_encode(compress_poly(w, 1), 1)
}

// ─── ML-KEM ───────────────────────────────────────────────────────────────

///|
/// ML-KEM-768 key sizes (bytes).
pub let ek_size : Int = 1184

///|
pub let dk_size : Int = 2400

///|
pub let ct_size : Int = 1088

///|
pub let ss_size : Int = 32

///|
/// ML-KEM.KeyGen_internal(d, z): deterministic key generation from 32-byte `d`
/// and `z`. Returns `(ek, dk)` (encapsulation / decapsulation keys).
pub fn keygen(d : Bytes, z : Bytes) -> (Bytes, Bytes) {
  let (ek, dk_pke) = kpke_keygen(d)
  let dk = cat([dk_pke, ek, @sha3.sha3_256(ek), z])
  (ek, dk)
}

///|
/// ML-KEM.Encaps_internal(ek, m): deterministic encapsulation with 32-byte
/// message `m`. Returns `(shared_secret(32), ciphertext(1088))`.
pub fn encaps(ek : Bytes, m : Bytes) -> (Bytes, Bytes) {
  let (k, r) = g(cat([m, @sha3.sha3_256(ek)]))
  let c = kpke_encrypt(ek, m, r)
  (k, c)
}

///|
fn ct_eq(a : Bytes, b : Bytes) -> Bool {
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
/// ML-KEM.Decaps_internal(dk, c): decapsulate, with implicit rejection
/// (returns a pseudo-random shared secret on an invalid ciphertext rather than
/// failing). Returns the 32-byte shared secret.
pub fn decaps(dk : Bytes, c : Bytes) -> Bytes {
  let dk_pke = Bytes::makei(384 * kk, fn(i) { dk[i] })
  let ek_pke = Bytes::makei(384 * kk + 32, fn(i) { dk[384 * kk + i] })
  let h = Bytes::makei(32, fn(i) { dk[768 * kk + 32 + i] })
  let z = Bytes::makei(32, fn(i) { dk[768 * kk + 64 + i] })
  let m_prime = kpke_decrypt(dk_pke, c)
  let (k_prime, r_prime) = g(cat([m_prime, h]))
  let k_bar = @sha3.shake256(cat([z, c]), 32)
  let c_prime = kpke_encrypt(ek_pke, m_prime, r_prime)
  if ct_eq(c, c_prime) {
    k_prime
  } else {
    k_bar
  }
}
