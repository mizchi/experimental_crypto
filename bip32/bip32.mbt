// BIP-32 hierarchical deterministic key derivation over secp256k1.
//
// Spec: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//
// Scope:
//   - Master key from a seed (BIP-39 seed bytes; key = HMAC-SHA512("Bitcoin seed", seed)).
//   - CKDpriv: derive child private from parent private (hardened and
//     non-hardened).
//   - CKDpub:  derive child public from parent public (non-hardened only).
//   - `neuter`: turn a private extended key into the matching public one.
//   - BIP-44 / BIP-49 / BIP-84 style path strings ("m/44'/0'/0'/0/0").
//
// Out of scope: serialization to the xprv / xpub Base58Check forms (callers
// can build that on top using the (chain_code, depth, parent_fingerprint,
// child_index, key) tuple), and BIP-340 / Schnorr extensions.
//
// Bitcoin uses HASH160 (RIPEMD-160 ∘ SHA-256) over the compressed pubkey for
// the parent fingerprint; the first 4 bytes go into the child header.

///|
pub(all) struct ExtendedPrivateKey {
  privkey : @secp256k1.PrivateKey
  chain_code : Bytes
  depth : Int
  parent_fingerprint : Bytes
  child_index : UInt
}

///|
pub(all) struct ExtendedPublicKey {
  pubkey : @secp256k1.PublicKey
  chain_code : Bytes
  depth : Int
  parent_fingerprint : Bytes
  child_index : UInt
}

///|
pub suberror Bip32Error {
  InvalidSeedLength(Int)
  DerivationFailed(String)
  HardenedFromPublic(UInt)
  InvalidPath(String)
  Secp256k1(@secp256k1.Secp256k1Error)
} derive(Debug)

///|
// secp256k1 curve order n. We re-declare it here rather than calling into
// @secp256k1 (which keeps `k1_n()` package-private); the value is fixed.
fn k1_n() -> @bigint.BigInt {
  @bigint.BigInt::from_string(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    radix=16,
  )
}

///|
fn hardened_threshold() -> UInt {
  0x80000000U
}

// ─── seed → master key ───────────────────────────────────────────────────

///|
/// Derive the BIP-32 master key from a seed. Returns the extended private
/// key at depth 0 (m).
///
/// BIP-32 § Master key generation:
///   I = HMAC-SHA512(Key = "Bitcoin seed", Data = seed)
///   I_L = I[0..32], I_R = I[32..64]
///   master_priv = I_L  (must be in [1, n-1])
///   master_chain_code = I_R
///
/// Seed length is permitted from 16 to 64 bytes per spec; BIP-39 yields 64.
pub fn master_from_seed(seed : Bytes) -> ExtendedPrivateKey raise Bip32Error {
  let n = seed.length()
  if n < 16 || n > 64 {
    raise InvalidSeedLength(n)
  }
  let i = @hash.hmac_sha512(b"Bitcoin seed", seed)
  let il = Bytes::makei(32, fn(j) { i[j] })
  let ir = Bytes::makei(32, fn(j) { i[j + 32] })
  let privkey = @secp256k1.PrivateKey::from_bytes(il) catch {
    e => raise Secp256k1(e)
  }
  let zero_fp = Bytes::makei(4, fn(_) { b'\x00' })
  {
    privkey,
    chain_code: ir,
    depth: 0,
    parent_fingerprint: zero_fp,
    child_index: 0U,
  }
}

// ─── child key derivation ─────────────────────────────────────────────────

///|
/// CKDpriv: derive a child extended private key from a parent extended
/// private key at the given `index`. Indices `>= 0x80000000` are hardened.
pub fn derive_private(
  parent : ExtendedPrivateKey,
  index : UInt,
) -> ExtendedPrivateKey raise Bip32Error {
  let data = if index >= hardened_threshold() {
    // Hardened: data = 0x00 || ser256(k_par) || ser32(i)
    let k_bytes = scalar_to_bytes32(privkey_scalar(parent.privkey))
    bytes_concat3(b"\x00", k_bytes, ser32(index))
  } else {
    // Non-hardened: data = serP(point(k_par)) || ser32(i)
    let pub_bytes = parent.privkey.public_key().to_compressed()
    bytes_concat2(pub_bytes, ser32(index))
  }
  let i = @hash.hmac_sha512(parent.chain_code, data)
  let il_bytes = Bytes::makei(32, fn(j) { i[j] })
  let ir_bytes = Bytes::makei(32, fn(j) { i[j + 32] })
  let il = @bigint.BigInt::from_octets(il_bytes[:])
  let n = k1_n()
  if il.compare(n) >= 0 {
    raise DerivationFailed("I_L >= n, retry with index+1")
  }
  let parent_scalar = privkey_scalar(parent.privkey)
  let child_scalar_pre = il + parent_scalar
  let child_scalar = child_scalar_pre % n
  if child_scalar.is_zero() {
    raise DerivationFailed("child key is zero, retry with index+1")
  }
  let child_priv_bytes = scalar_to_bytes32(child_scalar)
  let child_privkey = @secp256k1.PrivateKey::from_bytes(child_priv_bytes) catch {
    e => raise Secp256k1(e)
  }
  let parent_pub = parent.privkey.public_key()
  let fp = fingerprint(parent_pub)
  {
    privkey: child_privkey,
    chain_code: ir_bytes,
    depth: parent.depth + 1,
    parent_fingerprint: fp,
    child_index: index,
  }
}

///|
/// CKDpub: derive a child extended public key from a parent extended public
/// key for a non-hardened index. Hardened indices (≥ 2^31) cannot be derived
/// from a public key — the spec rejects this and so do we.
pub fn derive_public(
  parent : ExtendedPublicKey,
  index : UInt,
) -> ExtendedPublicKey raise Bip32Error {
  if index >= hardened_threshold() {
    raise HardenedFromPublic(index)
  }
  let pub_bytes = parent.pubkey.to_compressed()
  let data = bytes_concat2(pub_bytes, ser32(index))
  let i = @hash.hmac_sha512(parent.chain_code, data)
  let il_bytes = Bytes::makei(32, fn(j) { i[j] })
  let ir_bytes = Bytes::makei(32, fn(j) { i[j + 32] })
  let il = @bigint.BigInt::from_octets(il_bytes[:])
  let n = k1_n()
  if il.compare(n) >= 0 {
    raise DerivationFailed("I_L >= n, retry with index+1")
  }
  let child_pubkey = parent.pubkey.add_generator_mul(il_bytes) catch {
    @secp256k1.InvalidPointEncoding(_) =>
      raise DerivationFailed("child public key is infinity, retry with index+1")
    e => raise Secp256k1(e)
  }
  let fp = fingerprint(parent.pubkey)
  {
    pubkey: child_pubkey,
    chain_code: ir_bytes,
    depth: parent.depth + 1,
    parent_fingerprint: fp,
    child_index: index,
  }
}

///|
/// Strip the private half off an extended private key, returning the
/// matching extended public key.
pub fn neuter(xpriv : ExtendedPrivateKey) -> ExtendedPublicKey {
  {
    pubkey: xpriv.privkey.public_key(),
    chain_code: xpriv.chain_code,
    depth: xpriv.depth,
    parent_fingerprint: xpriv.parent_fingerprint,
    child_index: xpriv.child_index,
  }
}

///|
/// Derive a child extended private key by walking a BIP-32 path string.
/// Accepts "m" or "m/i" or "m/i'/j/..." (apostrophe = hardened).
pub fn derive_path(
  parent : ExtendedPrivateKey,
  path : String,
) -> ExtendedPrivateKey raise Bip32Error {
  let parts = split_on_slash(path)
  if parts.length() == 0 || parts[0] != "m" {
    raise InvalidPath("path must start with 'm'")
  }
  let mut cur = parent
  for k = 1; k < parts.length(); k = k + 1 {
    let p = parts[k]
    if p == "" {
      raise InvalidPath("empty component")
    }
    let last_ch = p.code_unit_at(p.length() - 1).to_int()
    // 0x27 = "'", 0x68/0x48 = "h"/"H" (some wallets write hardened as 0h).
    let hardened = p.length() > 0 &&
      (last_ch == 0x27 || last_ch == 0x68 || last_ch == 0x48)
    let num_part = if hardened { p[0:p.length() - 1].to_owned() } else { p }
    let idx = parse_uint_decimal(num_part)
    let raw_idx = if hardened { idx + hardened_threshold() } else { idx }
    cur = derive_private(cur, raw_idx)
  }
  cur
}

// ─── helpers ─────────────────────────────────────────────────────────────

///|
fn privkey_scalar(pk : @secp256k1.PrivateKey) -> @bigint.BigInt {
  pk.d
}

///|
fn scalar_to_bytes32(x : @bigint.BigInt) -> Bytes {
  x.to_octets(length=32)
}

///|
fn ser32(index : UInt) -> Bytes {
  let i = index.to_uint64()
  Bytes::makei(4, fn(j) {
    let shift = (3 - j) * 8
    ((i >> shift) & 0xffUL).to_byte()
  })
}

///|
fn fingerprint(pub_key : @secp256k1.PublicKey) -> Bytes {
  let h160 = @hash.hash160(pub_key.to_compressed())
  Bytes::makei(4, fn(j) { h160[j] })
}

///|
fn bytes_concat2(a : Bytes, b : Bytes) -> Bytes {
  Bytes::makei(a.length() + b.length(), fn(i) {
    if i < a.length() {
      a[i]
    } else {
      b[i - a.length()]
    }
  })
}

///|
fn bytes_concat3(a : Bytes, b : Bytes, c : Bytes) -> Bytes {
  let na = a.length()
  let nb = b.length()
  let nc = c.length()
  Bytes::makei(na + nb + nc, fn(i) {
    if i < na {
      a[i]
    } else if i < na + nb {
      b[i - na]
    } else {
      c[i - na - nb]
    }
  })
}

///|
fn split_on_slash(s : String) -> Array[String] {
  let out : Array[String] = []
  let mut buf = ""
  for ch in s {
    if ch.to_int() == 0x2f {
      out.push(buf)
      buf = ""
    } else {
      buf = buf + ch.to_string()
    }
  }
  out.push(buf)
  out
}

///|
fn parse_uint_decimal(s : String) -> UInt raise Bip32Error {
  if s.length() == 0 {
    raise InvalidPath("empty index")
  }
  if s.length() > 1 && s.code_unit_at(0).to_int() == 0x30 {
    raise InvalidPath("non-canonical index with leading zero: " + s)
  }
  let mut v : UInt64 = 0UL
  let max_child_index = 0x7fffffffUL
  for ch in s {
    let c = ch.to_int()
    if c < 0x30 || c > 0x39 {
      raise InvalidPath("non-decimal index: " + s)
    }
    let digit = (c - 0x30).to_uint64()
    if v > (max_child_index - digit) / 10UL {
      raise InvalidPath("index out of range: " + s)
    }
    v = v * 10UL + digit
    if v > max_child_index {
      raise InvalidPath("index out of range: " + s)
    }
  }
  v.to_uint()
}
