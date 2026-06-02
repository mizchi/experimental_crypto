// X25519MLKEM768 — the hybrid post-quantum / classical key exchange that is the
// default TLS 1.3 key-agreement group in current Chrome / Firefox and at Google
// / Cloudflare (IANA NamedGroup 0x11ec, draft-kwiatkowski-tls-ecdhe-mlkem).
//
// It runs ML-KEM-768 and X25519 in parallel and concatenates their secrets, so
// the session stays secure unless BOTH are broken — defending "harvest now,
// decrypt later" against a future quantum computer while keeping a classical
// fallback. The TLS 1.3 key schedule (mizchi/tls13) consumes the combined
// secret as its (EC)DHE input, exactly like the X25519 / P-256 groups.
//
// Wire layout (0x11ec puts ML-KEM first in both shares and the secret):
//   client key_share = ML-KEM-768 ek (1184) || X25519 client pub (32)  = 1216
//   server key_share = ML-KEM-768 ct (1088) || X25519 server pub (32)  = 1120
//   shared secret    = ML-KEM-768 ss (32)  || X25519 ss (32)           = 64

///|
pub suberror HybridError {
  BadShareLength(Int)
  Curve(String)
  Pq(@mlkem.MlkemError)
} derive(Debug)

///|
pub let client_share_len : Int = 1216

///|
pub let server_share_len : Int = 1120

///|
pub let shared_secret_len : Int = 64

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
fn slice(b : Bytes, off : Int, len : Int) -> Bytes {
  Bytes::makei(len, fn(i) { b[off + i] })
}

///|
/// Client offer: build the `client_share` (ML-KEM ek ‖ X25519 pub). Inputs are
/// the ML-KEM seeds `d`,`z` (32 bytes each) and the X25519 ephemeral private
/// `x25519_sk` (32 bytes). Returns `(client_share, mlkem_dk)`; the caller keeps
/// `mlkem_dk` and `x25519_sk` to finish once the server replies.
pub fn client_offer(
  d : Bytes,
  z : Bytes,
  x25519_sk : Bytes,
) -> (Bytes, Bytes) raise HybridError {
  let (ek, dk) = @mlkem.keygen(d, z) catch { e => raise Pq(e) }
  let xpub = (@x25519.PrivateKey::from_bytes(x25519_sk) catch {
      _ => raise Curve("invalid X25519 key material")
    })
    .public_key()
    .to_bytes()
  (concat(ek, xpub), dk)
}

///|
/// Server response: given the client's `client_share`, the ML-KEM encaps
/// message `m` (32 bytes) and the server's X25519 ephemeral `x25519_sk`,
/// produce `(server_share, shared_secret)`. `shared_secret` (64 bytes) feeds
/// the TLS key schedule.
pub fn server_respond(
  client_share : Bytes,
  m : Bytes,
  x25519_sk : Bytes,
) -> (Bytes, Bytes) raise HybridError {
  if client_share.length() != client_share_len {
    raise BadShareLength(client_share.length())
  }
  let ek = slice(client_share, 0, @mlkem.ek_size)
  let xpub_client = slice(client_share, @mlkem.ek_size, 32)
  let (ss_mlkem, ct) = @mlkem.encaps(ek, m) catch { e => raise Pq(e) }
  let sk = @x25519.PrivateKey::from_bytes(x25519_sk) catch {
    _ => raise Curve("invalid X25519 key material")
  }
  let pk_client = @x25519.PublicKey::from_bytes(xpub_client) catch {
    _ => raise Curve("invalid X25519 key material")
  }
  let ss_x = (@x25519.diffie_hellman(sk, pk_client) catch {
    _ => raise Curve("invalid X25519 key material")
  }).to_bytes()
  let server_share = concat(ct, sk.public_key().to_bytes())
  (server_share, concat(ss_mlkem, ss_x))
}

///|
/// Client finish: given the retained `mlkem_dk` + `x25519_sk` and the server's
/// `server_share`, recover the same 64-byte `shared_secret`.
pub fn client_finish(
  mlkem_dk : Bytes,
  x25519_sk : Bytes,
  server_share : Bytes,
) -> Bytes raise HybridError {
  if server_share.length() != server_share_len {
    raise BadShareLength(server_share.length())
  }
  let ct = slice(server_share, 0, @mlkem.ct_size)
  let xpub_server = slice(server_share, @mlkem.ct_size, 32)
  let ss_mlkem = @mlkem.decaps(mlkem_dk, ct) catch { e => raise Pq(e) }
  let sk = @x25519.PrivateKey::from_bytes(x25519_sk) catch {
    _ => raise Curve("invalid X25519 key material")
  }
  let pk_server = @x25519.PublicKey::from_bytes(xpub_server) catch {
    _ => raise Curve("invalid X25519 key material")
  }
  let ss_x = (@x25519.diffie_hellman(sk, pk_server) catch {
    _ => raise Curve("invalid X25519 key material")
  }).to_bytes()
  concat(ss_mlkem, ss_x)
}
