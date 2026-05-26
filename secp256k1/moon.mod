// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html

name = "mizchi/secp256k1"

version = "0.1.0"

import {
  "mizchi/asn1@0.1.0",
  "mizchi/hash@0.1.0",
  "mizchi/pkcs8@0.1.0",
  "mizchi/pem@0.1.0",
  "mizchi/pkix@0.1.0",
}

readme = "README.mbt.md"

repository = ""

license = "Apache-2.0"

keywords = [ ]

description = "secp256k1 (Bitcoin/Ethereum) ECDSA sign + verify with BIP-62 low-s normalisation."
