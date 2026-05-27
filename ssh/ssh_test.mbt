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
  Bytes::makei(s.length(), fn(i) { s.get_char(i).unwrap().to_int().to_byte() })
}

///|
test "ssh: parse pubkey text" {
  let parsed = @ssh.parse_ssh_pubkey_text(pubkey_text)
  @debug.assert_eq(parsed.algorithm, "ssh-ed25519")
  @debug.assert_eq(parsed.comment, Some("mizchi@misc-test"))
  let pk = @ssh.parse_ed25519_pubkey(parsed.blob)
  let rebuilt = @ssh.format_ssh_pubkey_text(pk, comment="mizchi@misc-test")
  @debug.assert_eq(
    rebuilt, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV mizchi@misc-test",
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
  @debug.assert_eq(ns, "git")
  let parsed = @ssh.parse_ssh_pubkey_text(pubkey_text)
  let expected_pk = @ssh.parse_ed25519_pubkey(parsed.blob)
  match pk_from_sig {
    Ed25519(pk) => @debug.assert_eq(pk.to_bytes(), expected_pk.to_bytes())
    _ => abort("expected Ed25519")
  }
}

///|
test "ssh: tampered message fails" {
  let parsed = @ssh.parse_ssh_pubkey_text(pubkey_text)
  let pk = @ssh.parse_ed25519_pubkey(parsed.blob)
  let bad : Bytes = b"hello git signing!"
  assert_false(@ssh.verify_armor(armored_signature, bad, pk))
}

///|
test "ssh: wrong sig_namespace returns false" {
  let parsed = @ssh.parse_ssh_pubkey_text(pubkey_text)
  let pk = @ssh.parse_ed25519_pubkey(parsed.blob)
  assert_false(
    @ssh.verify_armor(
      armored_signature,
      fixture_message(),
      pk,
      sig_namespace="file",
    ),
  )
}

///|
test "ssh: wrong pubkey returns false" {
  let other_seed = Bytes::makei(32, fn(_) { b'\x00' })
  let other_sk = @ed25519.PrivateKey::from_seed(other_seed)
  assert_false(
    @ssh.verify_armor(
      armored_signature,
      fixture_message(),
      other_sk.public_key(),
    ),
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
  @debug.assert_eq(sig.sig_namespace, "git")
  @debug.assert_eq(sig.hash_algorithm, "sha512")
  match sig.publickey {
    Ed25519(pk) => @debug.assert_eq(pk.to_bytes().length(), 32)
    _ => abort("expected Ed25519")
  }
}

///|
test "ssh: encode_sshsig_armor roundtrips through decode" {
  let original_blob = @ssh.decode_sshsig_armor(armored_signature)
  let reencoded = @ssh.encode_sshsig_armor(original_blob)
  let rebuilt_blob = @ssh.decode_sshsig_armor(reencoded)
  @debug.assert_eq(original_blob, rebuilt_blob)
}

///|
test "ATTACK: trust verification rejects SSHSIG armor with surrounding whitespace" {
  let parsed = @ssh.parse_ssh_pubkey_text(pubkey_text)
  let pk = @ssh.parse_ed25519_pubkey(parsed.blob)
  let padded = " " + armored_signature + "\n"
  @debug.assert_eq(
    @ssh.decode_sshsig_armor(padded),
    @ssh.decode_sshsig_armor(armored_signature),
  )
  let accepted = @ssh.verify_armor(padded, fixture_message(), pk) catch {
    InvalidEncoding(_) => false
    _ => false
  }
  assert_false(accepted)
}

///|
test "ATTACK: allowed_signers verification rejects lax SSHSIG armor" {
  let padded = "\n" + armored_signature
  let accepted = @ssh.verify_with_allowed_signers(
    allowed_signers_text,
    "mizchi@misc-test",
    padded,
    fixture_message(),
  ) catch {
    InvalidEncoding(_) => false
    _ => false
  }
  assert_false(accepted)
}

///|
fn inject_bare_cr_in_first_body_line(armor : String) -> String {
  let sb = StringBuilder::new()
  let mut saw_first_newline = false
  let mut inserted = false
  for c in armor {
    sb.write_char(c)
    if saw_first_newline && !inserted && c != '\n' && c != '\r' {
      sb.write_char('\r')
      inserted = true
    }
    if c == '\n' {
      saw_first_newline = true
    }
  }
  sb.to_string()
}

///|
test "ATTACK: strict SSHSIG armor rejects bare CR inside base64 body" {
  let parsed = @ssh.parse_ssh_pubkey_text(pubkey_text)
  let pk = @ssh.parse_ed25519_pubkey(parsed.blob)
  let injected = inject_bare_cr_in_first_body_line(armored_signature)
  let accepted = @ssh.verify_armor(injected, fixture_message(), pk) catch {
    InvalidEncoding(_) => false
    _ => false
  }
  assert_false(accepted)
}

// -----------------------------------------------------------------------------
// allowed_signers parser + verify integration
// -----------------------------------------------------------------------------

///|
let allowed_signers_text : String =
  #|# Comment line is ignored
  #|mizchi@misc-test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV
  #|
  #|other@example.com namespaces="file" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

///|
test "ssh: parse_allowed_signers reads two entries" {
  let signers = @ssh.parse_allowed_signers(allowed_signers_text)
  @debug.assert_eq(signers.length(), 2)
  @debug.assert_eq(signers[0].principals[0], "mizchi@misc-test")
  @debug.assert_eq(signers[1].principals[0], "other@example.com")
  match signers[1].namespaces {
    Some(ns) => @debug.assert_eq(ns[0], "file")
    None => abort("namespaces option not parsed")
  }
}

///|
test "ssh: find_signers honours glob and literal principals" {
  let signers = @ssh.parse_allowed_signers(allowed_signers_text)
  let found = @ssh.find_signers(signers, "mizchi@misc-test")
  @debug.assert_eq(found.length(), 1)
  let none = @ssh.find_signers(signers, "nobody@elsewhere")
  @debug.assert_eq(none.length(), 0)
  // Glob support: add a wildcard line and re-test.
  let glob_text =
    #|* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV
  let glob_signers = @ssh.parse_allowed_signers(glob_text)
  @debug.assert_eq(@ssh.find_signers(glob_signers, "anyone").length(), 1)
}

///|
test "ssh: verify_with_allowed_signers passes for the real signed message" {
  let ok = @ssh.verify_with_allowed_signers(
    allowed_signers_text,
    "mizchi@misc-test",
    armored_signature,
    fixture_message(),
  )
  assert_true(ok)
}

///|
test "ssh: verify_with_allowed_signers rejects unknown principal" {
  let ok = @ssh.verify_with_allowed_signers(
    allowed_signers_text,
    "attacker@evil.invalid",
    armored_signature,
    fixture_message(),
  )
  assert_false(ok)
}

///|
test "ATTACK: sig_namespace-scoped entry refuses cross-sig_namespace use" {
  // The 'other@example.com' entry restricts to namespaces="file". Even if
  // the signer's key matched, a "git"-sig_namespace signature must not satisfy it.
  let restricted_text =
    #|attacker@evil.invalid namespaces="file" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV
  let ok = @ssh.verify_with_allowed_signers(
    restricted_text,
    "attacker@evil.invalid",
    armored_signature,
    fixture_message(),
  )
  assert_false(ok)
}

///|
test "ATTACK: comma-separated allowed_signers options keep sig_namespace restriction" {
  // A preceding option must not hide namespaces="file" and accidentally
  // make the signer valid for every sig_namespace.
  let restricted_text =
    #|attacker@evil.invalid unknown=ignored,namespaces="file" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV
  let ok = @ssh.verify_with_allowed_signers(
    restricted_text,
    "attacker@evil.invalid",
    armored_signature,
    fixture_message(),
  )
  assert_false(ok)
}

///|
test "ATTACK: malformed allowed_signers namespace quotes fail closed" {
  let malformed_text =
    #|attacker@evil.invalid namespaces="file,git ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV
  let signers = @ssh.parse_allowed_signers(malformed_text)
  @debug.assert_eq(signers.length(), 0)
}

///|
test "ATTACK: duplicate allowed_signers namespaces fail closed" {
  let same_token =
    #|attacker@evil.invalid namespaces="file",namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV
  @debug.assert_eq(@ssh.parse_allowed_signers(same_token).length(), 0)
  let split_tokens =
    #|attacker@evil.invalid namespaces="file" namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV
  @debug.assert_eq(@ssh.parse_allowed_signers(split_tokens).length(), 0)
}

///|
test "ssh: parse allowed_signers validity-window options" {
  let time_scoped_text =
    #|time@example.com valid-after="19700101Z",valid-before="20990101Z" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV
  let signers = @ssh.parse_allowed_signers(time_scoped_text)
  @debug.assert_eq(signers.length(), 1)
  @debug.assert_eq(signers[0].valid_after, Some(0L))
  @debug.assert_eq(signers[0].valid_before, Some(4070908800L))
  let seconds_text =
    #|time@example.com valid-before="19700101000001Z" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV
  let seconds_signers = @ssh.parse_allowed_signers(seconds_text)
  @debug.assert_eq(seconds_signers.length(), 1)
  @debug.assert_eq(seconds_signers[0].valid_before, Some(1L))
}

///|
test "ATTACK: malformed validity-window allowed_signers entries fail closed" {
  let malformed_text =
    #|time@example.com valid-before="2099-01-01" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV
  @debug.assert_eq(@ssh.parse_allowed_signers(malformed_text).length(), 0)
}

///|
test "ATTACK: plain allowed_signers API rejects time policy" {
  let time_scoped_text =
    #|mizchi@misc-test valid-after="19700101Z",valid-before="20990101Z" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV
  let ok = @ssh.verify_with_allowed_signers(
    time_scoped_text,
    "mizchi@misc-test",
    armored_signature,
    fixture_message(),
  )
  assert_false(ok)
}

///|
test "ssh: time-aware allowed_signers API honours validity window" {
  let time_scoped_text =
    #|mizchi@misc-test valid-after="19700101Z",valid-before="20990101Z" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV
  assert_true(
    @ssh.verify_with_allowed_signers_at(
      time_scoped_text,
      "mizchi@misc-test",
      armored_signature,
      fixture_message(),
      1_700_000_000L,
    ),
  )
  assert_false(
    @ssh.verify_with_allowed_signers_at(
      time_scoped_text,
      "mizchi@misc-test",
      armored_signature,
      fixture_message(),
      -1L,
    ),
  )
  assert_false(
    @ssh.verify_with_allowed_signers_at(
      time_scoped_text,
      "mizchi@misc-test",
      armored_signature,
      fixture_message(),
      4070908800L,
    ),
  )
}

///|
test "ATTACK: cert-authority allowed_signers entries fail closed" {
  let ca_text =
    #|*@example.com cert-authority ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV
  let signers = @ssh.parse_allowed_signers(ca_text)
  @debug.assert_eq(signers.length(), 0)
}

///|
test "ATTACK: high-level allowed_signers rejects cert-authority policy" {
  let ca_text =
    #|mizchi@misc-test cert-authority ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV
  let ok = @ssh.verify_with_allowed_signers(
    ca_text,
    "mizchi@misc-test",
    armored_signature,
    fixture_message(),
  )
  assert_false(ok)
}

// -----------------------------------------------------------------------------
// ECDSA-SSH (ecdsa-sha2-nistp256) — real ssh-keygen output
// -----------------------------------------------------------------------------

///|
let ecdsa_pubkey_text : String =
  #|ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOjP+LsOqVSQ4wr88Hr5sr3zdBVTn/NGSFwN8X03oCCHRetbuvgvRUqBChu7QlVqf33UeZgYJ6vczR570C5nnG0= ecdsa@test

///|
let ecdsa_armored_signature : String =
  #|-----BEGIN SSH SIGNATURE-----
  #|U1NIU0lHAAAAAQAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAE
  #|EE6M/4uw6pVJDjCvzwevmyvfN0FVOf80ZIXA3xfTegIIdF61u6+C9FSoEKG7tCVWp/fdR5
  #|mBgnq9zNHnvQLmecbQAAAANnaXQAAAAAAAAABnNoYTUxMgAAAGQAAAATZWNkc2Etc2hhMi
  #|1uaXN0cDI1NgAAAEkAAAAhAM1s2V4gqdJJ6xkpRE6vZpxNpBftg+oExy/jEEMjxqdWAAAA
  #|IDUpuGnwmrO9l+3gqROm2ZuUW+hEtzeIzlIOj0bgp6WN
  #|-----END SSH SIGNATURE-----

///|
test "ssh: verify_armor_with verifies a real ECDSA-SSH signature" {
  let parsed = @ssh.parse_ssh_pubkey_text(ecdsa_pubkey_text)
  let pk = @ssh.parse_ecdsa_pubkey(parsed.blob)
  assert_true(
    @ssh.verify_armor_with(ecdsa_armored_signature, fixture_message(), pk),
  )
}

///|
test "ssh: ECDSA-SSH tampered message fails" {
  let parsed = @ssh.parse_ssh_pubkey_text(ecdsa_pubkey_text)
  let pk = @ssh.parse_ecdsa_pubkey(parsed.blob)
  let bad : Bytes = b"different"
  assert_false(@ssh.verify_armor_with(ecdsa_armored_signature, bad, pk))
}

// -----------------------------------------------------------------------------
// RSA-SSH (rsa-sha2-512) — real ssh-keygen output
// -----------------------------------------------------------------------------

///|
let rsa_pubkey_text : String =
  #|ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDD/GxR+DEacbYlagrS8fM7FOKgSbou4x6a08Mtn2US0G1ECV5Y1XDho7N4GgZe9OMggMWrrt4+PyjddTljwdMF876Kpv9osrnkTlFHCYvjHgCl0a6pn1wJw1KRrXXTSvEXbh3P+bNHd2r3AMX+b5OUt07nyWMuFty4daZ0BdkdPQncP3Oa++3VWLjpXa6UmeEBDlekiVjtbC1E6FCIOnhPTSE+6Bwmzu9B29GgdDctiTQoqw6MLywvMrsMwOhvDEDzIqORNOGUr6K+I9Hp/X/pqKaxtq2UDnoNnriI1+W0cOIv+78x/oU3qtvSEfkCZoob4otqDen4tt42yHMD+OxN rsa@test

///|
let rsa_armored_signature : String =
  #|-----BEGIN SSH SIGNATURE-----
  #|U1NIU0lHAAAAAQAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBAMP8bFH4MRpxtiVqCtLx8z
  #|sU4qBJui7jHprTwy2fZRLQbUQJXljVcOGjs3gaBl704yCAxauu3j4/KN11OWPB0wXzvoqm
  #|/2iyueROUUcJi+MeAKXRrqmfXAnDUpGtddNK8RduHc/5s0d3avcAxf5vk5S3TufJYy4W3L
  #|h1pnQF2R09Cdw/c5r77dVYuOldrpSZ4QEOV6SJWO1sLUToUIg6eE9NIT7oHCbO70Hb0aB0
  #|Ny2JNCirDowvLC8yuwzA6G8MQPMio5E04ZSvor4j0en9f+moprG2rZQOeg2euIjX5bRw4i
  #|/7vzH+hTeq29IR+QJmihvii2oN6fi23jbIcwP47E0AAAADZ2l0AAAAAAAAAAZzaGE1MTIA
  #|AAEUAAAADHJzYS1zaGEyLTUxMgAAAQA4k+HVYxvVmKKim+aRQ2FXvC0r16NUqw4ZpQsMp2
  #|iMFLTD6/UBmH+a/SXWU+4trEDlf/6A1E1+gUorKzGhxiDK+XiD4wJh2jOJj8iZxpcskPSf
  #|EHXHhst/nbGyNoUPGvcvBRDa42q0PZr2B9ioaYIqERtFnDPfoCOMVvZzvIeIPHHebx/E78
  #|gjdkcBol6ElUIYl6RpRAzrQHKH71pNJAWblsPsZPEfr+awbHlj91O/tqaMznE3KxJ98DSK
  #|sOz5GzORLj9BWZ1aHtEqJ+Q05macvn4SVAsHTuE+I9r/I9DAy6yC/uETpt7hEHa6V4uWt9
  #|Yqe7OvM+1jtOWTDnWdAsmr
  #|-----END SSH SIGNATURE-----

///|
test "ssh: verify_armor_with verifies a real RSA-SSH (rsa-sha2-512) signature" {
  let parsed = @ssh.parse_ssh_pubkey_text(rsa_pubkey_text)
  let rsa_pk = @ssh.parse_rsa_pubkey(parsed.blob)
  let pk = @ssh.SshPublicKey::Rsa(rsa_pk)
  assert_true(
    @ssh.verify_armor_with(rsa_armored_signature, fixture_message(), pk),
  )
}

///|
test "ssh: RSA-SSH tampered message fails" {
  let parsed = @ssh.parse_ssh_pubkey_text(rsa_pubkey_text)
  let rsa_pk = @ssh.parse_rsa_pubkey(parsed.blob)
  let pk = @ssh.SshPublicKey::Rsa(rsa_pk)
  let bad : Bytes = b"different"
  assert_false(@ssh.verify_armor_with(rsa_armored_signature, bad, pk))
}

// -----------------------------------------------------------------------------
// allowed_signers with mixed key types
// -----------------------------------------------------------------------------

///|
test "ssh: allowed_signers verifies ECDSA via verify_with_allowed_signers" {
  let allowed =
    #|ecdsa@test ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOjP+LsOqVSQ4wr88Hr5sr3zdBVTn/NGSFwN8X03oCCHRetbuvgvRUqBChu7QlVqf33UeZgYJ6vczR570C5nnG0=
  assert_true(
    @ssh.verify_with_allowed_signers(
      allowed,
      "ecdsa@test",
      ecdsa_armored_signature,
      fixture_message(),
    ),
  )
}

///|
test "ssh: allowed_signers verifies RSA via verify_with_allowed_signers" {
  let allowed =
    #|rsa@test ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDD/GxR+DEacbYlagrS8fM7FOKgSbou4x6a08Mtn2US0G1ECV5Y1XDho7N4GgZe9OMggMWrrt4+PyjddTljwdMF876Kpv9osrnkTlFHCYvjHgCl0a6pn1wJw1KRrXXTSvEXbh3P+bNHd2r3AMX+b5OUt07nyWMuFty4daZ0BdkdPQncP3Oa++3VWLjpXa6UmeEBDlekiVjtbC1E6FCIOnhPTSE+6Bwmzu9B29GgdDctiTQoqw6MLywvMrsMwOhvDEDzIqORNOGUr6K+I9Hp/X/pqKaxtq2UDnoNnriI1+W0cOIv+78x/oU3qtvSEfkCZoob4otqDen4tt42yHMD+OxN
  assert_true(
    @ssh.verify_with_allowed_signers(
      allowed,
      "rsa@test",
      rsa_armored_signature,
      fixture_message(),
    ),
  )
}

// -----------------------------------------------------------------------------
// Multi-algorithm sign roundtrips
// -----------------------------------------------------------------------------

///|
test "ssh: sign_armor_with P-256 roundtrip" {
  let scalar = Bytes::makei(32, fn(i) { (i + 1).to_byte() })
  let sk = @p256.PrivateKey::from_bytes(scalar)
  let pk = @ssh.SshPublicKey::P256(sk.public_key())
  let armor = @ssh.sign_armor_with(
    @ssh.SshPrivateKey::P256(sk),
    b"hello p256 ssh",
  )
  assert_true(@ssh.verify_armor_with(armor, b"hello p256 ssh", pk))
}

///|
test "ssh: sign_armor_with P-384 roundtrip" {
  let scalar = Bytes::makei(48, fn(i) { (i + 1).to_byte() })
  let sk = @p384.PrivateKey::from_bytes(scalar)
  let pk = @ssh.SshPublicKey::P384(sk.public_key())
  let armor = @ssh.sign_armor_with(
    @ssh.SshPrivateKey::P384(sk),
    b"hello p384 ssh",
  )
  assert_true(@ssh.verify_armor_with(armor, b"hello p384 ssh", pk))
}

///|
test "ssh: sign_armor_with Ed25519 (backward compat smoke)" {
  let seed = Bytes::makei(32, fn(i) { (i + 2).to_byte() })
  let edk = @ed25519.PrivateKey::from_seed(seed)
  let armor = @ssh.sign_armor_with(@ssh.SshPrivateKey::Ed25519(edk), b"compat")
  assert_true(
    @ssh.verify_armor_with(
      armor,
      b"compat",
      @ssh.SshPublicKey::Ed25519(edk.public_key()),
    ),
  )
}

///|
test "ATTACK: empty SSHSIG sig_namespace is rejected" {
  let seed = Bytes::makei(32, fn(i) { (i + 3).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let raised = try {
    let _ = @ssh.sign_armor(sk, b"empty sig_namespace", sig_namespace="")
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "ATTACK: SSHSIG sig_namespace rejects control characters" {
  let seed = Bytes::makei(32, fn(i) { (i + 4).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let raised = try {
    let _ = @ssh.sign_armor(sk, b"control namespace", sig_namespace="git\n")
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "ATTACK: SSH mpint rejects redundant leading zeroes" {
  let w = @ssh.WireWriter::new()
  w.write_string_ascii("ssh-rsa")
  w.write_string(b"\x00\x01")
  w.write_string(b"\x01")
  let raised = try {
    let _ = @ssh.parse_rsa_pubkey(w.to_bytes())
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "ATTACK: SSH wire reader rejects negative byte lengths" {
  let r = @ssh.WireReader::new(b"abc")
  let raised = try {
    let _ = r.read_bytes(-1)
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "ATTACK: SSH RSA public key rejects invalid public parameters" {
  fn parse_rsa(e : Bytes, n : Bytes) -> Bool {
    let w = @ssh.WireWriter::new()
    w.write_string_ascii("ssh-rsa")
    w.write_string(e)
    w.write_string(n)
    let rejected = try {
      let _ = @ssh.parse_rsa_pubkey(w.to_bytes())
      false
    } catch {
      InvalidEncoding(_) => true
      _ => false
    }
    rejected
  }
  assert_true(parse_rsa(b"\x01", b"\x01\x01")) // e = 1
  assert_true(parse_rsa(b"\x02", b"\x01\x01")) // e = 2 (even)
  assert_true(parse_rsa(b"\x03", b"\x01\x00")) // even modulus
}
