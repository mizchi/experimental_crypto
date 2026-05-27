// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html

name = "mizchi/ocsp"

version = "0.1.0"

import {
  "mizchi/asn1@0.1.0",
  "mizchi/pkix@0.1.0",
  "mizchi/pkix_verify@0.1.0",
  "mizchi/hash@0.1.0",
  "mizchi/ed25519@0.1.0",
  "mizchi/pem@0.1.0",
}

readme = "README.mbt.md"

repository = ""

license = "Apache-2.0"

keywords = [ ]

description = "EXPERIMENTAL — RFC 6960 OCSP response parser and verifier. Parse-and-verify only."
