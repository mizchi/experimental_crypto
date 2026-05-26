# Git Commit Signing

`mizchi/moonbit-crypto` covers all three formats git supports for
`gpg.format`:

| `gpg.format` | Format | Modules involved |
|---|---|---|
| `ssh` (git 2.34+) | SSHSIG-style armor | `ssh` + `git_object` + `ed25519` / `p256` / `p384` / `rsa` |
| `openpgp` (default) | OpenPGP detached armor | `pgp` + `git_object` + `hash` + signature primitives |
| `x509` (via gpgsm) | CMS SignedData detached | `cms` + `git_object` + `pkix_verify` + `pkix` |

All three flows reuse the same `mizchi/git_object` parser to extract the
signed bytes from a commit/tag.

## SSH-signed commits (most common with modern setups)

```moonbit
let commit_bytes = /* `git cat-file commit HEAD` output */
let signed = @git_object.parse_signed_commit(commit_bytes)

// signed.signature_armor is the -----BEGIN SSH SIGNATURE----- block.
// signed.signed_content is the commit object with the gpgsig header stripped.

// Verify against a single trusted pubkey:
let pubkey_text = /* ssh-ed25519 AAAA... user@host from authorized_keys */
let parsed = @ssh.parse_ssh_pubkey_text(pubkey_text)
let pk = @ssh.parse_ed25519_pubkey(parsed.blob)
@ssh.verify_armor(signed.signature_armor, signed.signed_content, pk)

// OR verify against an allowed_signers file:
let allowed_signers_text = /* contents of ~/.config/git/allowed_signers */
@ssh.verify_with_allowed_signers(
  allowed_signers_text,
  /* committer email */ "alice@example.com",
  signed.signature_armor,
  signed.signed_content,
)
```

Supports Ed25519, ECDSA P-256/P-384, and RSA (`rsa-sha2-256` / `rsa-sha2-512`).
Plain `ssh-rsa` (SHA-1) is deliberately rejected. This module is not a
drop-in replacement for OpenSSH's verifier; it implements a conservative
SSHSIG-style subset used by this workspace.

`mizchi/ssh.sign_armor_with(privkey, message, namespace="git")` produces
the matching armor; use it to back a `git config gpg.program` wrapper.

## OpenPGP-signed commits

```moonbit
let commit_bytes = /* git cat-file commit HEAD */
let signed = @git_object.parse_signed_commit(commit_bytes)

// pubkey block from `gpg --export --armor <fingerprint>`:
let pubkey_armor = /* -----BEGIN PGP PUBLIC KEY BLOCK----- ... */
let pk = @pgp.parse_pubkey_armor(pubkey_armor)

@pgp.verify_armor(signed.signature_armor, signed.signed_content, pk.key)
```

Verify side handles v4 and v6 Signature Packets (RFC 9580), Ed25519
(algo 22 v4 + algo 27 v6), RSA (SHA-256/384/512), ECDSA P-256 + P-384.

`@pgp.sign_armor(privkey, message, creation_time=...)` produces a v4
armor. Pass `version=6` for v6 output (caller-supplied salt API is a
follow-up; current v6 sign uses an empty salt that is RFC-legal but
should not be used in production).

## X.509 / S/MIME-signed commits (gpgsm)

```moonbit
let commit_bytes = /* git cat-file commit HEAD */
let signed = @git_object.parse_signed_commit(commit_bytes)

// The armor for gpg.format=x509 is the base64 of a CMS SignedData DER.
// Strip the armor and decode:
let cms_der = /* base64-decode signed.signature_armor body */
let sd = @cms.parse_signed_data(cms_der)

// Either signature-only (caller pre-verified the cert chain):
@cms.verify_detached(sd, signed.signed_content)

// Or signature + chain in one call:
let trust_anchor_pk = /* extracted from a trusted root cert */
@cms.verify_with_chain(sd, signed.signed_content, trust_anchor_pk, "260601000000Z")
```

`verify_with_chain` walks the CMS-embedded cert chain through
`@pkix_verify.verify_chain`, enforcing:

- validity (not_before ≤ now ≤ not_after, strict format)
- critical extensions all in the recognised set
- intermediate keyUsage.keyCertSign
- pathLenConstraint
- DNS nameConstraints (intersected down the chain)
- DN linkage (byte-compare on the encoded Name)
- outer signature_algorithm cross-check with tbs.signature

## Verifying allowed_signers / authorized keys files

`@ssh.parse_allowed_signers(text)` reads a conservative allowed_signers-style
file into `Array[AllowedSigner]`. `@ssh.find_signers(signers, principal)`
honours `*` / `?` glob matching. The `namespaces="git,file"` option restricts
which SSHSIG namespaces a key is allowed to sign in; if absent the key signs in
any namespace. `cert-authority`, `valid-after`, and `valid-before` entries are
rejected until certificate and time-aware verification are implemented.

## CI gating

Pipe a commit body through verify and refuse to merge on failure:

```moonbit
fn gate_commit(commit_bytes : Bytes, allowed_signers : String, expected : String) -> Bool {
  let signed = @git_object.parse_signed_commit(commit_bytes) catch { _ => return false }
  @ssh.verify_with_allowed_signers(
    allowed_signers,
    expected,
    signed.signature_armor,
    signed.signed_content,
  ) catch { _ => false }
}
```

## Out of scope

- `git verify-tag` for annotated tags works the same way (tag object has
  the same `gpgsig` header convention).
- Mailmap / coauthor verification: each `Co-Authored-By:` does NOT carry
  its own signature; only the committer's signature is on the object.
- Revocation: today we do not consult OCSP / CRL during chain validation.
  `@ocsp` + `@crl` are available but the caller must wire them
  explicitly into the verification pipeline.
