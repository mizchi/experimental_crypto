// End-to-end: parse a real ssh-signed git commit object and verify its
// SSH signature against the signer's ed25519 pubkey.

///|
fn hex_to_bytes(s : String) -> Bytes {
  fn nib(c : Char) -> Int {
    let n = c.to_int()
    if n >= 0x30 && n <= 0x39 {
      n - 0x30
    } else if n >= 0x61 && n <= 0x66 {
      n - 0x61 + 10
    } else if n >= 0x41 && n <= 0x46 {
      n - 0x41 + 10
    } else {
      abort("bad hex")
    }
  }

  let len = s.length() / 2
  let out = FixedArray::make(len, b'\x00')
  let mut i = 0
  while i < len {
    let hi = nib(s.get_char(i * 2).unwrap())
    let lo = nib(s.get_char(i * 2 + 1).unwrap())
    out[i] = (hi * 16 + lo).to_byte()
    i = i + 1
  }
  Bytes::makei(len, fn(j) { out[j] })
}

///|
// Real signed commit object captured via `git cat-file commit HEAD` on a
// repo where the commit was signed with `git config gpg.format ssh` +
// the ed25519 key whose pubkey is also embedded in mizchi/ssh's tests.
fn commit_object_bytes() -> Bytes {
  hex_to_bytes(
    "7472656520656261613639316235353534663239616339643466333738313161316461366632346433373661310a" +
    "617574686f72206d697a636869203c6d697a636869406d6973632d746573743e2031373739373835313839202b303930300a" +
    "636f6d6d6974746572206d697a636869203c6d697a636869406d6973632d746573743e2031373739373835313839202b303930300a" +
    "677067736967202d2d2d2d2d424547494e20535348205349474e41545552452d2d2d2d2d0a" +
    "2055314e4955306c48414141414151414141444d414141414c63334e6f4c57566b4d6a55314d546b414141416738374972556a70574355533379763059445237314b4e48476d390a" +
    "2039697761716f657a7835724a656d56785541414141445a326c30414141414141414141415a7a614745314d544941414142544141414143334e7a6143316c5a4449314e5445350a" +
    "2041414141514f495a5a7145676b5857706d5774652b345545376c634d2b57506e7152766f3451526b30575765453967626642644869316a695a437938504a447a774d683267500a" +
    "2042413877526c327767374d71664e647047625251673d0a" +
    "202d2d2d2d2d454e4420535348205349474e41545552452d2d2d2d2d0a" +
    "0a696e697469616c20636f6d6d69740a",
  )
}

///|
fn signer_pubkey() -> @ed25519.PublicKey raise {
  // Same key as mizchi/ssh's fixture.
  let text = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOyK1I6VglEt8r9GA0e9SjRxpvfYsGqqHs8eayXplcV mizchi@misc-test"
  let parsed = @ssh.parse_ssh_pubkey_text(text)
  @ssh.parse_ed25519_pubkey(parsed.blob)
}

///|
test "git_object: split signed content + armor from real commit" {
  let signed = @git_object.parse_signed_commit(commit_object_bytes())
  // The armor must begin with the BEGIN line.
  assert_true(
    signed.signature_armor.length() >= 30 &&
    signed.signature_armor.get_char(0).unwrap() == '-',
  )
  // Signed content keeps tree / author / committer + body, but NO gpgsig.
  let s = bytes_to_string(signed.signed_content)
  assert_true(contains(s, "tree ebaa691b5554f29ac9d4f37811a1da6f24d376a1"))
  assert_true(contains(s, "initial commit"))
  assert_false(contains(s, "gpgsig"))
  assert_false(contains(s, "BEGIN SSH SIGNATURE"))
}

///|
test "git_object: end-to-end verify a real SSH-signed commit" {
  let signed = @git_object.parse_signed_commit(commit_object_bytes())
  let pk = signer_pubkey()
  assert_true(
    @ssh.verify_armor(signed.signature_armor, signed.signed_content, pk),
  )
}

///|
test "git_object: tampering the signed content breaks verification" {
  let signed = @git_object.parse_signed_commit(commit_object_bytes())
  let pk = signer_pubkey()
  // Flip one byte of the signed content.
  let bad = Bytes::makei(signed.signed_content.length(), fn(i) {
    if i == 0 {
      (signed.signed_content[i].to_int() ^ 0x01).to_byte()
    } else {
      signed.signed_content[i]
    }
  })
  assert_false(@ssh.verify_armor(signed.signature_armor, bad, pk))
}

///|
test "git_object: unsigned commit raises NotSigned" {
  // Hand-craft a minimal unsigned commit body.
  let plain : Bytes = b"tree 0000000000000000000000000000000000000000\nauthor x <x@x> 0 +0000\ncommitter x <x@x> 0 +0000\n\nhi\n"
  match (try? @git_object.parse_signed_commit(plain)) {
    Err(NotSigned) => ()
    other => abort("expected NotSigned, got \{other}")
  }
}

// ─── tiny helpers ─────────────────────────────────────────────────────────

///|
fn bytes_to_string(b : Bytes) -> String {
  let sb = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(b[i].to_int().to_char().unwrap())
  }
  sb.to_string()
}

///|
fn contains(s : String, needle : String) -> Bool {
  if needle.length() == 0 {
    return true
  }
  let max = s.length() - needle.length()
  let mut i = 0
  while i <= max {
    let mut matches = true
    for j = 0; j < needle.length(); j = j + 1 {
      if s.get_char(i + j).unwrap() != needle.get_char(j).unwrap() {
        matches = false
        break
      }
    }
    if matches {
      return true
    }
    i = i + 1
  }
  false
}

///|
test "ATTACK: commit object with two gpgsig headers must be rejected" {
  // Two gpgsig lines (one truncated) in a single commit.
  let bad : Bytes = b"tree 0000000000000000000000000000000000000000\nauthor x <x@x> 0 +0000\ncommitter x <x@x> 0 +0000\ngpgsig first\ngpgsig second\n\nhi\n"
  match (try? @git_object.parse_signed_commit(bad)) {
    Err(Malformed(_)) => ()
    other => abort("multi-gpgsig NOT rejected: \{other}")
  }
}
