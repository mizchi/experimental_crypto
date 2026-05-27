// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html

name = "mizchi/jwe"

version = "0.1.0"

import {
  "mizchi/aead@0.1.0",
  "mizchi/crypto_bigint@0.1.0",
  "mizchi/rsa@0.1.0",
  "mizchi/hash@0.1.0",
}

readme = "README.mbt.md"

repository = ""

license = "Apache-2.0"

keywords = [ ]

description = "EXPERIMENTAL — JWE (RFC 7516) Compact Serialization — RSA-OAEP-256 / A256KW / dir + A128GCM / A256GCM."
