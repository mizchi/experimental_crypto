# x509-limbo path-validation vectors

Trimmed subset of the [C2SP/x509-limbo](https://github.com/C2SP/x509-limbo)
certificate-path-validation corpus (`limbo.json`, schema `version: 1`), pinned
from the `main` branch. The full `limbo.json` is ~40 MB; this file is the
in-scope subset emitted by `scripts/gen_x509_limbo.py`.

The companion BetterTLS name-constraints suite (bundled by x509-limbo under its
`bettertls::` namespace) is generated into `../bettertls/nameconstraints.json`.

## What is included

Only cases whose accept/reject verdict is decided by what
`@pkix_verify.verify_chain` actually enforces: signatures, validity windows,
basicConstraints (`cA`), `pathLenConstraint`, issuer `keyCertSign`,
intermediate dNSName name constraints, critical-extension rejection, duplicate
extensions, signature-algorithm consistency, and DN chaining.

Trust-anchor-level checks (the anchor's own validity, basicConstraints,
keyUsage, critical extensions, and `nameConstraints`) ARE in scope: the harness
calls `verify_chain_with_anchor_cert`, which validates the supplied anchor
certificate, so root-defect and anchor name-constraint cases are exercised.

Excluded as out-of-scope for this verifier (so they cannot produce spurious
discrepancies):

- Hostname / SAN identity matching, EKU policy, certificate policies, and
  authority/subject key-identifier (`aki`/`ski`) chaining.
- Encoding / placement profile rules the verifier does not enforce:
  basicConstraints / nameConstraints criticality, `nameConstraints` only in CA
  certs, and non-canonical dNSName constraints (leading period / wildcard).
- Path building: cases where several supplied certs share a subject DN (the
  "chain of pain" cross-cert, CA key-rollover / self-issued topologies, expired
  sibling intermediates) require trying candidate paths, which `verify_chain`
  does not do (it takes a single pre-ordered intermediate list). The self-issued
  name-constraint exemption itself is covered by a dedicated unit test in
  `pkix_verify_test.mbt`.
- Revocation (CRL/OCSP), verifier-config chain-depth caps, DoS limits, and
  pedantic encoding profiles.

## Consumed by

`pkix_verify/limbo_json_js_test.mbt` (JS target). The hard assertion is the
false-positive guard: no `reject` case may verify.

## Regenerating

```sh
python3 scripts/gen_x509_limbo.py            # downloads limbo.json to /tmp
# or, with a local copy:
python3 scripts/gen_x509_limbo.py path/to/limbo.json
```

## SHA-256

```text
7ac9afefb1cb18207b22461f6bf63370f530648722ec74133499b3b76e068c8e  limbo.json
```
