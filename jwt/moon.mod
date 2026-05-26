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

name = "mizchi/jwt"

version = "0.1.0"

import {
  "mizchi/ed25519@0.1.0",
  "mizchi/rsa@0.1.0",
  "mizchi/p256@0.1.0",
  "mizchi/p384@0.1.0",
  "mizchi/hash@0.1.0",
}

readme = "README.mbt.md"

repository = ""

license = "Apache-2.0"

keywords = [ ]

description = "EXPERIMENTAL — jwt: not production-grade. Audit before use. No warranty."
