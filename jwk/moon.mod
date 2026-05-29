// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html

name = "mizchi/jwk"

version = "0.1.0"

import {
  "mizchi/rsa@0.1.0",
  "mizchi/p256@0.1.0",
  "mizchi/p384@0.1.0",
  "mizchi/p521@0.1.0",
  "mizchi/secp256k1@0.1.0",
  "mizchi/ed25519@0.1.0",
  "mizchi/hash@0.1.0",
}

readme = "README.mbt.md"

repository = ""

license = "Apache-2.0"

keywords = [ ]

description = "EXPERIMENTAL — JSON Web Key (RFC 7517) parse + serialise, bridging JOSE JSON to workspace key types."
