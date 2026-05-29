// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "mizchi/p521"

version = "0.1.0"

import {
  "mizchi/asn1@0.1.0",
  "mizchi/crypto_bigint@0.1.0",
  "mizchi/hash@0.1.0",
  "mizchi/pkcs8@0.1.0",
  "mizchi/pem@0.1.0",
  "mizchi/pkix@0.1.0",
}

readme = "README.mbt.md"

repository = ""

license = "Apache-2.0"

keywords = [ ]

description = "EXPERIMENTAL — p521: not production-grade. Audit before use. No warranty."
