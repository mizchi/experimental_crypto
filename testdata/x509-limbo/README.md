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

Excluded as out-of-scope for this verifier (so they cannot produce spurious
discrepancies):

- Hostname / SAN identity matching, EKU policy, certificate policies, and
  authority/subject key-identifier (`aki`/`ski`) chaining.
- **Trust-anchor-level defects.** `verify_chain` takes the anchor as a bare
  public key and does not inspect the root's validity, basicConstraints, or
  extensions, so any case keyed on a root defect (ids containing `root`,
  anchor name constraints, etc.) is dropped. Intermediate-level name
  constraints are covered exhaustively by the BetterTLS suite.
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
edb1dc537d7de497c8343ed08c97750997de9c90892b13f04199c3f11b2def6d  limbo.json
```
