// TLS 1.2 pseudo-random function and key schedule (RFC 5246 §5, §6.3, §7.4.9).
//
// TLS 1.2 replaced the TLS 1.0/1.1 MD5+SHA-1 split PRF with a single
// HMAC-<hash> construction, where <hash> is the PRF hash of the negotiated
// cipher suite (SHA-256 for most suites, SHA-384 for the *_SHA384 suites).
//
//   P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
//                          HMAC_hash(secret, A(2) + seed) + ...
//   A(0) = seed
//   A(i) = HMAC_hash(secret, A(i-1))
//
//   PRF(secret, label, seed) = P_hash(secret, label + seed)
//
// truncated to the requested number of output bytes.

///|
/// The PRF hash of a TLS 1.2 cipher suite. Drives both the PRF and the
/// transcript hash fed into Finished.
pub(all) enum PrfHash {
  Sha256
  Sha384
}

///|
fn PrfHash::hmac(self : PrfHash, key : Bytes, msg : Bytes) -> Bytes {
  match self {
    Sha256 => @hash.hmac_sha256(key, msg)
    Sha384 => @hash.hmac_sha384(key, msg)
  }
}

///|
/// Digest length of the PRF hash, in bytes.
pub fn PrfHash::hash_len(self : PrfHash) -> Int {
  match self {
    Sha256 => 32
    Sha384 => 48
  }
}

///|
/// Transcript hash over `data` using the PRF hash (used for the Finished
/// verify_data input and for the extended-master-secret session hash).
pub fn PrfHash::transcript_hash(self : PrfHash, data : Bytes) -> Bytes {
  match self {
    Sha256 => @hash.sha256(data)
    Sha384 => @hash.sha384(data)
  }
}

///|
fn concat(a : Bytes, b : Bytes) -> Bytes {
  Bytes::makei(a.length() + b.length(), fn(i) {
    if i < a.length() {
      a[i]
    } else {
      b[i - a.length()]
    }
  })
}

///|
fn bytes_of_str(s : String) -> Bytes {
  // TLS PRF labels are ASCII; encode each code unit as one byte.
  let buf = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    buf[i] = (s.get_char(i).unwrap().to_int() & 0xff).to_byte()
  }
  Bytes::makei(s.length(), fn(i) { buf[i] })
}

///|
/// P_hash(secret, seed): expand `secret`+`seed` to exactly `out_len` bytes via
/// the iterated-HMAC construction (RFC 5246 §5).
pub fn PrfHash::p_hash(
  self : PrfHash,
  secret : Bytes,
  seed : Bytes,
  out_len : Int,
) -> Bytes {
  let out = FixedArray::make(out_len, b'\x00')
  let mut filled = 0
  // A(0) = seed; A(i) = HMAC(secret, A(i-1)).
  let mut a = seed
  while filled < out_len {
    a = self.hmac(secret, a)
    let block = self.hmac(secret, concat(a, seed))
    let take = if out_len - filled < block.length() {
      out_len - filled
    } else {
      block.length()
    }
    for i = 0; i < take; i = i + 1 {
      out[filled + i] = block[i]
    }
    filled = filled + take
  }
  Bytes::makei(out_len, fn(i) { out[i] })
}

///|
/// PRF(secret, label, seed) = P_hash(secret, label + seed), truncated to
/// `out_len` bytes. `label` is the ASCII string from RFC 5246 (e.g. "master
/// secret", "key expansion", "client finished").
pub fn PrfHash::prf(
  self : PrfHash,
  secret : Bytes,
  label : String,
  seed : Bytes,
  out_len : Int,
) -> Bytes {
  self.p_hash(secret, concat(bytes_of_str(label), seed), out_len)
}
