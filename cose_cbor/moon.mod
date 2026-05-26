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

name = "mizchi/cose_cbor"

version = "0.1.0"

readme = "README.mbt.md"

// Renamed from `mizchi/cbor` to `mizchi/cose_cbor` so the upstream
// `mizchi/cbor` published on mooncakes keeps its namespace. The
// upstream package focuses on type-specific encoders (uint, int, bytes,
// string, double, bool, null) and does not yet ship a CborValue ADT
// with Array / Map / Tag — those are what `@cose` requires.
//
// Long-term: contribute the ADT helpers upstream and retire this
// module entirely.

repository = ""

license = "Apache-2.0"

keywords = [ ]

description = "EXPERIMENTAL — cose_cbor: not production-grade. Audit before use. No warranty."
