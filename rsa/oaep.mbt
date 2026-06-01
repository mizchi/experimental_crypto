// RSA-OAEP (RFC 8017 §7.1) — the Web Crypto `RSA-OAEP` primitive and the JOSE
// RSA-OAEP / RSA-OAEP-256 key-management algorithms.
//
// Parameterized over the MGF1 / lHash digest (SHA-1/256/384/512) and an
// optional label. Encryption takes the random seed explicitly (the library
// avoids implicit RNG); callers must pass `hlen` fresh CSPRNG bytes.
//
// Decryption follows RFC 8017 §7.1.2's constant-ish discipline: every failure
// mode (leading byte, lHash mismatch, missing 0x01 separator) folds into a
// single `OaepDecryptionError`, so the error type is not a padding/Manger
// oracle. (Timing is not yet formally leveled; see docs/CONSTANT_TIME.md.)

///|
/// OAEP MGF1 / lHash digest choice.
pub(all) enum OaepHash {
  Sha1
  Sha256
  Sha384
  Sha512
} derive(Eq, Debug)

///|
fn OaepHash::hlen(self : OaepHash) -> Int {
  match self {
    Sha1 => 20
    Sha256 => 32
    Sha384 => 48
    Sha512 => 64
  }
}

///|
fn OaepHash::digest(self : OaepHash, msg : Bytes) -> Bytes {
  match self {
    Sha1 => @hash.sha1(msg)
    Sha256 => @hash.sha256(msg)
    Sha384 => @hash.sha384(msg)
    Sha512 => @hash.sha512(msg)
  }
}

///|
// MGF1 (RFC 8017 §B.2.1) with the given hash.
fn oaep_mgf1(h : OaepHash, seed : Bytes, mask_len : Int) -> Bytes {
  let hlen = h.hlen()
  let iters = (mask_len + hlen - 1) / hlen
  let seed_len = seed.length()
  let chunk = FixedArray::make(seed_len + 4, b'\x00')
  for i in 0..<seed_len {
    chunk[i] = seed[i]
  }
  let out = FixedArray::make(iters * hlen, b'\x00')
  for c in 0..<iters {
    chunk[seed_len] = ((c >> 24) & 0xFF).to_byte()
    chunk[seed_len + 1] = ((c >> 16) & 0xFF).to_byte()
    chunk[seed_len + 2] = ((c >> 8) & 0xFF).to_byte()
    chunk[seed_len + 3] = (c & 0xFF).to_byte()
    let block = h.digest(Bytes::makei(seed_len + 4, fn(i) { chunk[i] }))
    for i in 0..<hlen {
      out[c * hlen + i] = block[i]
    }
  }
  Bytes::makei(mask_len, fn(i) { out[i] })
}

///|
fn oaep_xor(a : Bytes, b : Bytes) -> Bytes {
  Bytes::makei(a.length(), fn(i) { (a[i].to_int() ^ b[i].to_int()).to_byte() })
}

///|
/// RSA-OAEP encrypt `message` to this public key. `seed` must be exactly the
/// hash's digest length (`hlen`) of fresh random bytes; `hash` selects the
/// MGF1/lHash digest (default SHA-256); `label` is the optional OAEP label
/// (default empty). Returns a `k`-byte ciphertext (`k` = modulus byte length).
pub fn RsaPublicKey::encrypt_oaep(
  self : RsaPublicKey,
  message : Bytes,
  seed : Bytes,
  hash? : OaepHash = Sha256,
  label? : Bytes = b"",
) -> Bytes raise RsaError {
  let k = self.n_bytes_len
  let hlen = hash.hlen()
  if seed.length() != hlen {
    raise OaepEncodingError("OAEP seed must be " + hlen.to_string() + " bytes")
  }
  if k < 2 * hlen + 2 {
    raise OaepEncodingError("modulus too small for OAEP with this hash")
  }
  if message.length() > k - 2 * hlen - 2 {
    raise OaepEncodingError("message too long for RSA-OAEP")
  }
  let l_hash = hash.digest(label)
  let db_len = k - hlen - 1
  // DB = lHash || PS(00..) || 0x01 || M
  let ps_len = db_len - hlen - 1 - message.length()
  let db = Bytes::makei(db_len, fn(i) {
    if i < hlen {
      l_hash[i]
    } else if i < hlen + ps_len {
      b'\x00'
    } else if i == hlen + ps_len {
      b'\x01'
    } else {
      message[i - hlen - ps_len - 1]
    }
  })
  let db_mask = oaep_mgf1(hash, seed, db_len)
  let masked_db = oaep_xor(db, db_mask)
  let seed_mask = oaep_mgf1(hash, masked_db, hlen)
  let masked_seed = oaep_xor(seed, seed_mask)
  // EM = 0x00 || maskedSeed || maskedDB
  let em = Bytes::makei(k, fn(i) {
    if i == 0 {
      b'\x00'
    } else if i < 1 + hlen {
      masked_seed[i - 1]
    } else {
      masked_db[i - 1 - hlen]
    }
  })
  let m_int = BigInt::from_octets(em[:])
  m_int.pow(self.e, modulus=self.n).to_octets(length=k)
}

///|
/// RSA-OAEP decrypt `ciphertext` with this private key. `hash` / `label` must
/// match the encrypter. Raises `OaepDecryptionError` for every failure mode
/// (so the error is not a padding oracle).
pub fn RsaPrivateKey::decrypt_oaep(
  self : RsaPrivateKey,
  ciphertext : Bytes,
  hash? : OaepHash = Sha256,
  label? : Bytes = b"",
) -> Bytes raise RsaError {
  let k = self.n_bytes_len
  let hlen = hash.hlen()
  if ciphertext.length() != k || k < 2 * hlen + 2 {
    raise OaepDecryptionError
  }
  let c_int = BigInt::from_octets(ciphertext[:])
  if c_int.compare(self.n) >= 0 {
    raise OaepDecryptionError
  }
  let em = c_int.pow(self.d, modulus=self.n).to_octets(length=k)
  // From here, every check feeds a single `bad` flag (Manger mitigation).
  let mut bad = false
  if em[0] != b'\x00' {
    bad = true
  }
  let masked_seed = Bytes::makei(hlen, fn(i) { em[1 + i] })
  let masked_db = Bytes::makei(k - hlen - 1, fn(i) { em[1 + hlen + i] })
  let seed = oaep_xor(masked_seed, oaep_mgf1(hash, masked_db, hlen))
  let db = oaep_xor(masked_db, oaep_mgf1(hash, seed, k - hlen - 1))
  let expected = hash.digest(label)
  let mut lhash_diff = 0
  for i in 0..<hlen {
    lhash_diff = lhash_diff | (db[i].to_int() ^ expected[i].to_int())
  }
  if lhash_diff != 0 {
    bad = true
  }
  // Locate the 0x01 separator after lHash + zero padding (no early exit).
  let db_len = db.length()
  let mut sep = -1
  for i in hlen..<db_len {
    if sep == -1 {
      if db[i] == b'\x01' {
        sep = i
      } else if db[i] != b'\x00' {
        bad = true
      }
    }
  }
  if sep == -1 {
    bad = true
  }
  if bad {
    raise OaepDecryptionError
  }
  let m_len = db_len - sep - 1
  Bytes::makei(m_len, fn(i) { db[sep + 1 + i] })
}
