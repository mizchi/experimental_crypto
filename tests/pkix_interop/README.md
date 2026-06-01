# pkix interop (X.509 chain validation)

**openssl mints a `root → intermediate → leaf` chain; MoonBit `pkix_verify`
validates it** — exercising the intermediate-handling path (signature linkage,
validity window, basicConstraints / pathlen, anchor linkage, dNSName SAN) that
the `tls13_interop` test (root→leaf, no intermediate) does not cover.

- `interop.mbt` is a JS-export shim: `verify_chain(leaf, intermediates, anchor,
  now, hostname)` returning `1` trusted+name, `0` untrusted, `2` parse error,
  `3` name mismatch.
- `driver.mjs` (Node) builds the chain with `openssl`, then asserts:
  - valid chain + correct hostname → `1`
  - missing intermediate → `0`
  - evaluated in 2099 (expired) / 1971 (not yet valid) → `0`
  - wrong hostname → `3`
  - unrelated anchor → `0`
  - tampered leaf → not `1`

```sh
bash tests/pkix_interop/run.sh
```
