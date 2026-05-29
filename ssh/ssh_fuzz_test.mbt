// Structured fuzz tests for the SSHSIG-style verifier. Pure random bytes are
// useful for panic checks, but the interesting security boundary is grammar-
// aware: allowed_signers options, SSHSIG envelope fields, and SSH mpint
// canonicality.

///|
let fuzz_pubkey_text : String =
  #|ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV fuzz@example.com

///|
let fuzz_key_field : String =
  #|ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV

///|
let fuzz_armored_signature : String =
  #|-----BEGIN SSH SIGNATURE-----
  #|U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg87IrUjpWCUS3yv0YDR71KNHGm9
  #|9iwaqoezx5rJemVxUAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
  #|AAAAQGjEo2XckzSHCF3KQjzquSFX31V7/93S5QcbtsKB8Kq+fiFubv+cUCdNRsrvJJZ1eW
  #|USS98VvY3CEN8iz/c7vAE=
  #|-----END SSH SIGNATURE-----

///|
fn fuzz_message() -> Bytes {
  let s = "hello git signing"
  Bytes::makei(s.length(), fn(i) { s.get_char(i).unwrap().to_int().to_byte() })
}

///|
fn fuzz_pubkey_blob() -> Bytes {
  let parsed = @ssh.parse_ssh_pubkey_text(fuzz_pubkey_text) catch {
    e => abort("fuzz fixture pubkey failed: " + repr(e) + "")
  }
  parsed.blob
}

///|
fn fuzz_ed25519_pubkey() -> @ed25519.PublicKey {
  @ssh.parse_ed25519_pubkey(fuzz_pubkey_blob()) catch {
    e => abort("fuzz fixture ed25519 pubkey failed: " + repr(e) + "")
  }
}

///|
fn fuzz_signature_blob() -> Bytes {
  let blob = @ssh.decode_sshsig_armor(fuzz_armored_signature) catch {
    e => abort("fuzz fixture armor failed: " + repr(e) + "")
  }
  let sig = @ssh.decode_sshsig_blob(blob) catch {
    e => abort("fuzz fixture sshsig failed: " + repr(e) + "")
  }
  sig.signature_blob
}

///|
fn build_sshsig_blob(
  ns : String,
  reserved : Bytes,
  hash_algorithm : String,
  signature_blob : Bytes,
) -> Bytes {
  let w = @ssh.WireWriter::new()
  w.write_bytes_raw(@ssh.sshsig_magic)
  w.write_uint32(@ssh.sshsig_version)
  w.write_string(fuzz_pubkey_blob())
  w.write_string_ascii(ns)
  w.write_string(reserved)
  w.write_string_ascii(hash_algorithm)
  w.write_string(signature_blob)
  w.to_bytes()
}

///|
fn append_byte(b : Bytes, x : Byte) -> Bytes {
  Bytes::makei(b.length() + 1, fn(i) { if i < b.length() { b[i] } else { x } })
}

///|
fn flip_magic(b : Bytes) -> Bytes {
  Bytes::makei(b.length(), fn(i) { if i == 0 { b'X' } else { b[i] } })
}

///|
fn expect_decode_rejects(blob : Bytes) -> Unit {
  let rejected = try {
    let _ = @ssh.decode_sshsig_blob(blob)
    false
  } catch {
    InvalidEncoding(_) => true
    PreambleMismatch => true
    UnsupportedSigVersion(_) => true
    TruncatedInput(_) => true
    _ => false
  }
  if !rejected {
    abort("expected SSHSIG decode to reject mutated blob")
  }
}

///|
test "fuzz sshsig: decode_sshsig_blob never panics on random bytes" {
  for input in (@quickcheck.samples(200) : Array[Bytes]) {
    let _ = try? @ssh.decode_sshsig_blob(input)
  }
}

///|
test "fuzz ssh: text parsers never panic on random strings" {
  for input in (@quickcheck.samples(200) : Array[String]) {
    let _ = try? @ssh.parse_ssh_pubkey_text(input)
    let _ = try? @ssh.parse_allowed_signers(input)
  }
}

///|
test "fuzz allowed_signers: structured options preserve or narrow trust" {
  let options = [
    "namespaces=\"file\"", "namespaces=\"git,file\"", "unknown=ignored,namespaces=\"file\"",
    "valid-before=\"20990101Z\"", "valid-after=\"19700101Z\"", "cert-authority",
    "namespaces=\"\"",
  ]
  for raw in (@quickcheck.samples(80) : Array[UInt]) {
    let idx = (raw % options.length().reinterpret_as_uint()).reinterpret_as_int()
    let opt = options[idx]
    let text = "fuzz@example.com " + opt + " " + fuzz_key_field
    let signers = @ssh.parse_allowed_signers(text)
    if opt == "namespaces=\"file\"" {
      @debug.assert_eq(signers.length(), 1)
      assert_false(
        @ssh.verify_with_allowed_signers(
          text,
          "fuzz@example.com",
          fuzz_armored_signature,
          fuzz_message(),
        ),
      )
    } else if opt == "namespaces=\"git,file\"" {
      @debug.assert_eq(signers.length(), 1)
      assert_true(
        @ssh.verify_with_allowed_signers(
          text,
          "fuzz@example.com",
          fuzz_armored_signature,
          fuzz_message(),
        ),
      )
    } else if opt == "valid-before=\"20990101Z\"" ||
      opt == "valid-after=\"19700101Z\"" {
      @debug.assert_eq(signers.length(), 1)
      assert_false(
        @ssh.verify_with_allowed_signers(
          text,
          "fuzz@example.com",
          fuzz_armored_signature,
          fuzz_message(),
        ),
      )
      assert_true(
        @ssh.verify_with_allowed_signers_at(
          text,
          "fuzz@example.com",
          fuzz_armored_signature,
          fuzz_message(),
          1_700_000_000L,
        ),
      )
    } else if opt == "cert-authority" {
      @debug.assert_eq(signers.length(), 1)
      assert_true(signers[0].cert_authority)
      assert_false(
        @ssh.verify_with_allowed_signers(
          text,
          "fuzz@example.com",
          fuzz_armored_signature,
          fuzz_message(),
        ),
      )
      assert_false(
        @ssh.verify_with_allowed_signers_at(
          text,
          "fuzz@example.com",
          fuzz_armored_signature,
          fuzz_message(),
          1_700_000_000L,
        ),
      )
    } else {
      @debug.assert_eq(signers.length(), 0)
    }
  }
}

///|
test "fuzz sshsig: structured envelope mutations reject before trust" {
  let sig_blob = fuzz_signature_blob()
  let valid_blob = build_sshsig_blob("git", b"", "sha512", sig_blob)
  for raw in (@quickcheck.samples(80) : Array[UInt]) {
    let case_id = raw % 5U
    if case_id == 0U {
      expect_decode_rejects(build_sshsig_blob("", b"", "sha512", sig_blob))
    } else if case_id == 1U {
      expect_decode_rejects(build_sshsig_blob("git", b"x", "sha512", sig_blob))
    } else if case_id == 2U {
      expect_decode_rejects(append_byte(valid_blob, b'\x00'))
    } else if case_id == 3U {
      expect_decode_rejects(flip_magic(valid_blob))
    } else {
      let bad_hash_blob = build_sshsig_blob("git", b"", "sha999", sig_blob)
      let armor = @ssh.encode_sshsig_armor(bad_hash_blob)
      let raised = try {
        let _ = @ssh.verify_armor(armor, fuzz_message(), fuzz_ed25519_pubkey())
        false
      } catch {
        HashAlgorithmMismatch(_) => true
        _ => false
      }
      assert_true(raised)
    }
  }
}

///|
test "fuzz sshsig: inner signature algorithm mismatch rejects" {
  let inner = @ssh.WireWriter::new()
  inner.write_string_ascii("ssh-rsa")
  inner.write_string(Bytes::makei(64, fn(_) { b'\x00' }))
  let blob = build_sshsig_blob("git", b"", "sha512", inner.to_bytes())
  let armor = @ssh.encode_sshsig_armor(blob)
  let raised = try {
    let _ = @ssh.verify_armor(armor, fuzz_message(), fuzz_ed25519_pubkey())
    false
  } catch {
    InvalidEncoding(_) => true
    UnsupportedAlgorithm(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "fuzz ssh pubkey: non-minimal RSA mpint encodings reject" {
  for raw in (@quickcheck.samples(100) : Array[Bytes]) {
    let v = if raw.length() == 0 { 1 } else { raw[0].to_int() & 0x7f }
    let low = if v == 0 { b'\x01' } else { v.to_byte() }
    let non_minimal_positive = Bytes::makei(2, fn(i) {
      if i == 0 {
        b'\x00'
      } else {
        low
      }
    })
    let w = @ssh.WireWriter::new()
    w.write_string_ascii("ssh-rsa")
    w.write_string(non_minimal_positive)
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
}
