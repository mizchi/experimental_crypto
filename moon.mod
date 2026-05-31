// Single consolidated module. Formerly a moon.work workspace of 50+ separate
// modules (mizchi/asn1, mizchi/pkix, ...); now one module with each crypto /
// PKI / JOSE building block as a sub-package (mizchi/experimental_crypto/asn1,
// .../pkix, ...). Import aliases are unchanged (@asn1, @pkix, ...).

name = "mizchi/experimental_crypto"

version = "0.0.1"

readme = "README.md"

repository = "https://github.com/mizchi/experimental_crypto"

license = "Apache-2.0"

keywords = [ "crypto", "cryptography", "pki", "jose", "experimental" ]

description = "EXPERIMENTAL — pure-MoonBit cryptography / PKI / JOSE building blocks. Educational reference, not production-grade. No warranty."

import {
  "moonbitlang/x@0.4.43",
}
