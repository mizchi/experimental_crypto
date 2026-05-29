///|
fn main {
  let seed = Bytes::makei(32, fn(i) { (i + 3).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed) catch {
    _ => abort("failed to build deterministic Ed25519 key")
  }
  let msg : Bytes = b"PGP sign-side interop\n"
  let pubkey_armor = @pgp.export_ed25519_v4_public_key_armor(
    sk, "MoonBit PGP Interop <pgp@example.invalid>",
  ) catch {
    _ => abort("failed to export public key armor")
  }
  let sig_armor = @pgp.sign_armor(@pgp.PgpPrivateKey::Ed25519(sk), msg) catch {
    _ => abort("failed to sign interop message")
  }
  let v6_msg : Bytes = b"PGP v6 sign-side interop\n"
  let v6_salt : Bytes = b"0123456789abcdefghijklmnopqrstuv"
  let v6_pubkey_armor = @pgp.export_ed25519_v6_public_key_armor(
    sk,
    salt=v6_salt,
  ) catch {
    _ => abort("failed to export v6 public key armor")
  }
  let v6_sig_armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    v6_msg,
    version=6,
    salt=v6_salt,
  ) catch {
    _ => abort("failed to sign v6 interop message")
  }
  println("-----BEGIN PGP INTEROP MESSAGE-----")
  println("PGP sign-side interop")
  println("-----END PGP INTEROP MESSAGE-----")
  println(pubkey_armor)
  println(sig_armor)
  println("-----BEGIN PGP V6 INTEROP MESSAGE-----")
  println("PGP v6 sign-side interop")
  println("-----END PGP V6 INTEROP MESSAGE-----")
  println("-----BEGIN PGP V6 INTEROP PUBLIC KEY-----")
  println(v6_pubkey_armor)
  println("-----END PGP V6 INTEROP PUBLIC KEY-----")
  println("-----BEGIN PGP V6 INTEROP SIGNATURE-----")
  println(v6_sig_armor)
  println("-----END PGP V6 INTEROP SIGNATURE-----")
}
