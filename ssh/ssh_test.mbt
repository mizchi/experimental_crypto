// Blackbox tests against real `ssh-keygen -Y sign -n git` output.

///|
// Real ssh-keygen Ed25519 fixture. Generated locally with:
//   ssh-keygen -t ed25519 -f /tmp/k -N ""
//   echo -n "hello git signing" > /tmp/msg.txt
//   ssh-keygen -Y sign -f /tmp/k -n git /tmp/msg.txt
let pubkey_text : String =
  #|ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV mizchi@misc-test

///|
let armored_signature : String =
  #|-----BEGIN SSH SIGNATURE-----
  #|U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg87IrUjpWCUS3yv0YDR71KNHGm9
  #|9iwaqoezx5rJemVxUAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
  #|AAAAQGjEo2XckzSHCF3KQjzquSFX31V7/93S5QcbtsKB8Kq+fiFubv+cUCdNRsrvJJZ1eW
  #|USS98VvY3CEN8iz/c7vAE=
  #|-----END SSH SIGNATURE-----

///|
fn fixture_message() -> Bytes {
  let s = "hello git signing"
  Bytes::makei(s.length(), fn(i) {
    s.get_char(i).unwrap().to_int().to_byte()
  })
}

///|
test "ssh: parse pubkey text" {
  let parsed = @ssh.parse_ssh_pubkey_text(pubkey_text)
  assert_eq(parsed.algorithm, "ssh-ed25519")
  assert_eq(parsed.comment, Some("mizchi@misc-test"))
  let pk = @ssh.parse_ed25519_pubkey(parsed.blob)
  let rebuilt = @ssh.format_ssh_pubkey_text(pk, comment="mizchi@misc-test")
  assert_eq(
    rebuilt,
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV mizchi@misc-test",
  )
}

///|
test "ssh: verify_armor against real ssh-keygen signature" {
  let parsed = @ssh.parse_ssh_pubkey_text(pubkey_text)
  let pk = @ssh.parse_ed25519_pubkey(parsed.blob)
  assert_true(@ssh.verify_armor(armored_signature, fixture_message(), pk))
}

///|
test "ssh: verify_armor_anonymous returns embedded pubkey" {
  let (pk_from_sig, ns) = @ssh.verify_armor_anonymous(
    armored_signature,
    fixture_message(),
  )
  assert_eq(ns, "git")
  let parsed = @ssh.parse_ssh_pubkey_text(pubkey_text)
  let expected_pk = @ssh.parse_ed25519_pubkey(parsed.blob)
  assert_eq(pk_from_sig.to_bytes(), expected_pk.to_bytes())
}

///|
test "ssh: tampered message fails" {
  let parsed = @ssh.parse_ssh_pubkey_text(pubkey_text)
  let pk = @ssh.parse_ed25519_pubkey(parsed.blob)
  let bad : Bytes = b"hello git signing!"
  assert_false(@ssh.verify_armor(armored_signature, bad, pk))
}

///|
test "ssh: wrong namespace returns false" {
  let parsed = @ssh.parse_ssh_pubkey_text(pubkey_text)
  let pk = @ssh.parse_ed25519_pubkey(parsed.blob)
  assert_false(
    @ssh.verify_armor(armored_signature, fixture_message(), pk, namespace="file"),
  )
}

///|
test "ssh: wrong pubkey returns false" {
  let other_seed = Bytes::makei(32, fn(_) { b'\x00' })
  let other_sk = @ed25519.PrivateKey::from_seed(other_seed)
  assert_false(
    @ssh.verify_armor(armored_signature, fixture_message(), other_sk.public_key()),
  )
}

///|
test "ssh: sign + verify roundtrip" {
  let seed = Bytes::makei(32, fn(i) { (i + 1).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  let msg : Bytes = b"some git commit object bytes"
  let armor = @ssh.sign_armor(sk, msg)
  assert_true(@ssh.verify_armor(armor, msg, pk))
}

///|
test "ssh: sshsig binary decode reveals fields" {
  let blob = @ssh.decode_sshsig_armor(armored_signature)
  let sig = @ssh.decode_sshsig_blob(blob)
  assert_eq(sig.namespace, "git")
  assert_eq(sig.hash_algorithm, "sha512")
  match sig.publickey {
    Ed25519(pk) => assert_eq(pk.to_bytes().length(), 32)
  }
}

///|
test "ssh: encode_sshsig_armor roundtrips through decode" {
  let original_blob = @ssh.decode_sshsig_armor(armored_signature)
  let reencoded = @ssh.encode_sshsig_armor(original_blob)
  let rebuilt_blob = @ssh.decode_sshsig_armor(reencoded)
  assert_eq(original_blob, rebuilt_blob)
}
