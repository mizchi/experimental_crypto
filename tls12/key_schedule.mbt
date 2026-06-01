// TLS 1.2 key derivation built on the PRF (RFC 5246 §8.1, §6.3, §7.4.9;
// RFC 7627 for the extended master secret).

///|
/// master_secret = PRF(pre_master_secret, "master secret",
///                     client_random + server_random)[0..48]   (RFC 5246 §8.1)
///
/// `client_random` / `server_random` are the 32-byte Random values from the
/// ClientHello and ServerHello.
pub fn PrfHash::master_secret(
  self : PrfHash,
  pre_master_secret : Bytes,
  client_random : Bytes,
  server_random : Bytes,
) -> Bytes {
  self.prf(
    pre_master_secret,
    "master secret",
    concat(client_random, server_random),
    48,
  )
}

///|
/// Extended master secret (RFC 7627 §4):
///   master_secret = PRF(pre_master_secret, "extended master secret",
///                       session_hash)[0..48]
/// where `session_hash` is the transcript hash over all handshake messages
/// through the ClientKeyExchange.
pub fn PrfHash::extended_master_secret(
  self : PrfHash,
  pre_master_secret : Bytes,
  session_hash : Bytes,
) -> Bytes {
  self.prf(pre_master_secret, "extended master secret", session_hash, 48)
}

///|
/// key_block = PRF(master_secret, "key expansion",
///                 server_random + client_random)   (RFC 5246 §6.3)
///
/// Note the reversed random order relative to `master_secret`. The caller
/// requests enough bytes to slice out the MAC keys (for CBC suites), the
/// encryption keys, and the fixed IV portions; for an AEAD (GCM) suite the
/// layout per direction is `enc_key (key_len) || fixed_iv (4)` and there are
/// no MAC keys.
pub fn PrfHash::key_block(
  self : PrfHash,
  master_secret : Bytes,
  client_random : Bytes,
  server_random : Bytes,
  out_len : Int,
) -> Bytes {
  self.prf(
    master_secret,
    "key expansion",
    concat(server_random, client_random),
    out_len,
  )
}

///|
/// Finished.verify_data = PRF(master_secret, finished_label,
///                            Hash(handshake_messages))[0..12]  (RFC 5246 §7.4.9)
///
/// `finished_label` is "client finished" or "server finished". `transcript`
/// is the concatenation of all handshake messages exchanged so far (excluding
/// the Finished being computed). verify_data is 12 bytes for all standard
/// TLS 1.2 cipher suites.
pub fn PrfHash::finished_verify_data(
  self : PrfHash,
  master_secret : Bytes,
  finished_label : String,
  transcript : Bytes,
) -> Bytes {
  self.prf(master_secret, finished_label, self.transcript_hash(transcript), 12)
}
