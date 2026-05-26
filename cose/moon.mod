// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html

name = "mizchi/cose"

version = "0.1.0"

import {
  "mizchi/cbor@0.1.0",
  "mizchi/hash@0.1.0",
  "mizchi/ed25519@0.1.0",
  "mizchi/p256@0.1.0",
  "mizchi/p384@0.1.0",
  "mizchi/rsa@0.1.0",
  "mizchi/asn1@0.1.0",
}

readme = "README.mbt.md"

repository = ""

license = "Apache-2.0"

keywords = [ ]

description = "Minimum-viable COSE_Sign1 verify + COSE_Key parsing (RFC 9052)."
