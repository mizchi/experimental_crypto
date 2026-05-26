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

name = "mizchi/hkdf"

version = "0.1.0"

import {
  "mizchi/hkdf/wrap@0.1.0",
  "moonbitlang/x@0.4.43",
}

readme = "README.mbt.md"

repository = ""

license = "Apache-2.0"

keywords = [ ]

description = "EXPERIMENTAL — hkdf: not production-grade. Audit before use. No warranty."
