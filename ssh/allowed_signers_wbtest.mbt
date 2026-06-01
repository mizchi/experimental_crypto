// Whitebox tests for the cert-authority principal policy.

///|
fn dummy_ssh_ed25519_pubkey() -> SshPublicKey {
  let pk = @ed25519.PublicKey::from_bytes(Bytes::makei(32, fn(_) { b'\x01' })) catch {
    _ => abort("unreachable: fixed 32-byte pubkey")
  }
  Ed25519(pk)
}

///|
fn make_test_certificate(principals : Array[String]) -> SshCertificate {
  let dummy = dummy_ssh_ed25519_pubkey()
  {
    algorithm: ed25519_cert_algo,
    subject_key: dummy,
    serial: 0UL,
    cert_type: ssh_cert_type_user,
    key_id: "wbtest",
    valid_principals: principals,
    valid_after: 0UL,
    valid_before: 0xFFFFFFFFFFFFFFFFUL,
    critical_options: b"",
    extensions: b"",
    ca_key: dummy,
    signature_blob: b"",
    signed_data: b"",
  }
}

///|
// Regression guard: OpenSSH's `sshkey_cert_check_authority` rejects a
// certificate whose principal list is empty when a concrete principal is
// requested ("Certificate lacks principal list" / "name is not a listed
// principal"). Treating an empty list as a wildcard would let any CA-issued
// certificate without a principal binding authenticate as any identity.
test "ATTACK: cert-authority rejects certificate with empty principal list" {
  assert_false(
    certificate_principal_allows(
      make_test_certificate([]),
      "anyone@example.com",
    ),
  )
  // A listed principal still matches; an unlisted one does not.
  assert_true(
    certificate_principal_allows(
      make_test_certificate(["alice@example.com"]),
      "alice@example.com",
    ),
  )
  assert_false(
    certificate_principal_allows(
      make_test_certificate(["alice@example.com"]),
      "mallory@example.com",
    ),
  )
}
