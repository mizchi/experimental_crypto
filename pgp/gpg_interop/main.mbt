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
  println("-----BEGIN PGP INTEROP MESSAGE-----")
  println("PGP sign-side interop")
  println("-----END PGP INTEROP MESSAGE-----")
  println(pubkey_armor)
  println(sig_armor)
}
