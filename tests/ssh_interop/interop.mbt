// SSHSIG interop shim.
//
// OpenSSH `ssh-keygen -Y sign` produces an SSHSIG armor; this shim hands it to
// MoonBit `ssh.verify_with_allowed_signers` (the equivalent of
// `ssh-keygen -Y verify`) and reports the verdict. The Node driver drives the
// real ssh-keygen for Ed25519 / ECDSA / RSA keys and checks valid + tampered
// cases. The message is passed as hex so arbitrary bytes survive the boundary.

///|
fn hexval(c : Char) -> Int {
  let v = c.to_int()
  if v >= '0'.to_int() && v <= '9'.to_int() {
    v - '0'.to_int()
  } else if v >= 'a'.to_int() && v <= 'f'.to_int() {
    v - 'a'.to_int() + 10
  } else if v >= 'A'.to_int() && v <= 'F'.to_int() {
    v - 'A'.to_int() + 10
  } else {
    abort("non-hex char")
  }
}

///|
fn from_hex(s : String) -> Bytes {
  let n = s.length() / 2
  Bytes::makei(n, fn(i) {
    ((hexval(s.get_char(i * 2).unwrap()) << 4) |
    hexval(s.get_char(i * 2 + 1).unwrap())).to_byte()
  })
}

///|
/// Verify an SSHSIG armor against an allowed_signers list (as `ssh-keygen -Y
/// verify -f allowed_signers -I principal -n namespace` would). Returns 1 if
/// the signature is trusted for `principal` under `namespace`, else 0.
pub fn ssh_verify(
  allowed_signers : String,
  principal : String,
  armor : String,
  message_hex : String,
  sig_namespace : String,
) -> Int {
  let ok = @ssh.verify_with_allowed_signers(
    allowed_signers,
    principal,
    armor,
    from_hex(message_hex),
    sig_namespace~,
  ) catch {
    _ => return 0
  }
  if ok {
    1
  } else {
    0
  }
}
