// JS-target x509-limbo / BetterTLS path-validation runner.
//
// The JSON fixtures under `testdata/x509-limbo` and `testdata/bettertls` are
// trimmed subsets of the C2SP/x509-limbo corpus (which bundles the Netflix
// BetterTLS name-constraints suite under its `bettertls::` namespace). They are
// produced by `scripts/gen_x509_limbo.py` and loaded at runtime so we can
// exercise thousands of certificate chains without generating huge MoonBit
// sources.
//
// Soundness: the generator keeps only cases whose verdict is decided by what
// `@pkix_verify.verify_chain` actually enforces (signatures, validity,
// basicConstraints, pathLen, keyUsage, dNSName name constraints, critical-
// extension rejection, DN chaining) and NOT by hostname/SAN identity matching,
// EKU policy, certificate policies, or revocation — features the verifier
// deliberately defers to the caller. Each kept case has a leaf SAN equal to the
// requested peer name, so identity always matches and the verdict comes from
// the chain logic alone.
//
// Assertion policy (mirrors the repo's "false positives are unacceptable;
// false negatives are acceptable" rule):
//   * expect == "reject": verify_chain MUST NOT succeed. A success is a hard
//     failure — this is the false-positive guard, the class of the
//     nameConstraints bypass fixed in PR #2.
//   * expect == "accept": verify_chain SHOULD succeed. A rejection caused by an
//     unsupported algorithm or a stricter-than-scope policy (e.g. the leaf
//     digitalSignature requirement, fail-closed handling of IP name
//     constraints, critical-extension rejection) is tolerated as a skip. A
//     rejection for a signature / validity / path / name-constraint reason is a
//     hard failure (real over-rejection or a harness path-ordering mistake).

///|
extern "js" fn limbo_read_text(rel_path : String) -> String =
  #| (relPath) => {
  #|   const fs = globalThis.process.getBuiltinModule("node:fs")
  #|   const path = globalThis.process.getBuiltinModule("node:path")
  #|   let dir = globalThis.process.cwd()
  #|   for (let i = 0; i < 8; i++) {
  #|     const candidate = path.join(dir, relPath)
  #|     if (fs.existsSync(candidate)) {
  #|       return fs.readFileSync(candidate, "utf8")
  #|     }
  #|     const parent = path.dirname(dir)
  #|     if (parent === dir) {
  #|       break
  #|     }
  #|     dir = parent
  #|   }
  #|   throw new Error("missing fixture " + relPath + " from " + globalThis.process.cwd())
  #| }

///|
fn limbo_load_json(rel_path : String) -> Json {
  @json.parse(limbo_read_text(rel_path)[:]) catch {
    e => abort("failed to parse " + rel_path + ": " + repr(e))
  }
}

///|
fn limbo_obj(j : Json, ctx : String) -> Map[String, Json] {
  match j {
    Object(m) => m
    _ => abort(ctx + ": expected object")
  }
}

///|
fn limbo_arr(j : Json, ctx : String) -> Array[Json] {
  match j {
    Array(a) => a
    _ => abort(ctx + ": expected array")
  }
}

///|
fn limbo_field(m : Map[String, Json], key : String, ctx : String) -> Json {
  match m.get(key) {
    Some(v) => v
    None => abort(ctx + ": missing " + key)
  }
}

///|
fn limbo_str(j : Json, ctx : String) -> String {
  match j {
    String(s) => s
    _ => abort(ctx + ": expected string")
  }
}

///|
// Outcome of running one chain through verify_chain.
priv enum LimboOutcome {
  Accepted
  RejectedTolerable(String) // unsupported alg / stricter-than-scope policy
  RejectedHard(String) // signature / validity / path / name-constraint
}

///|
fn limbo_decode_cert(pem_str : String) -> @pkix.Certificate raise {
  @pkix.parse_certificate(@pem.decode(pem_str).data)
}

///|
// Map a verify_chain error to tolerable (false negative we accept) vs hard
// (a rejection that, for an "accept" case, signals over-rejection or a
// harness/path-ordering bug).
fn limbo_classify(e : @pkix_verify.PkixVerifyError) -> LimboOutcome {
  match e {
    UnsupportedSignatureAlgorithm(_) =>
      RejectedTolerable("unsupported signature alg")
    UnsupportedPublicKeyAlgorithm(_) =>
      RejectedTolerable("unsupported public-key alg")
    KeyUsageMissingDigitalSignature =>
      RejectedTolerable("leaf lacks digitalSignature (stricter policy)")
    ExtendedKeyUsageMissing(_) => RejectedTolerable("EKU policy")
    UnknownCriticalExtension(_) =>
      RejectedTolerable("critical extension not processed (fail-closed)")
    MalformedExtension(m) =>
      RejectedTolerable("malformed/unsupported extension: " + m)
    Pkix(_) | Asn1(_) => RejectedTolerable("parser limitation")
    SignatureMismatch => RejectedHard("SignatureMismatch")
    NotYetValid => RejectedHard("NotYetValid")
    Expired => RejectedHard("Expired")
    NotACA => RejectedHard("NotACA")
    PathLengthExceeded => RejectedHard("PathLengthExceeded")
    IssuerSubjectMismatch => RejectedHard("IssuerSubjectMismatch")
    KeyUsageMissingCertSign => RejectedHard("KeyUsageMissingCertSign")
    NameConstraintViolation(n) =>
      RejectedHard("NameConstraintViolation(" + n + ")")
    other => RejectedHard(repr(other))
  }
}

///|
fn limbo_run_case(
  anchor_pem : String,
  leaf_pem : String,
  inter_pems : Array[String],
  now : String,
) -> LimboOutcome {
  // Decode the anchor as a full certificate so its own validity,
  // basicConstraints, keyUsage, critical extensions, and nameConstraints are
  // enforced (verify_chain_with_anchor_cert). Decode failures on the anchor are
  // tolerated: they only ever turn an accept into a skip, and a reject case
  // that cannot even parse its anchor is still "not accepted".
  let anchor = limbo_decode_cert(anchor_pem) catch {
    e => return RejectedTolerable("anchor decode: " + repr(e))
  }
  let leaf = limbo_decode_cert(leaf_pem) catch {
    e => return RejectedTolerable("leaf decode: " + repr(e))
  }
  let inters : Array[@pkix.Certificate] = []
  for p in inter_pems {
    let c = limbo_decode_cert(p) catch {
      e => return RejectedTolerable("intermediate decode: " + repr(e))
    }
    inters.push(c)
  }
  try {
    @pkix_verify.verify_chain_with_anchor_cert(leaf, inters, anchor, now)
    Accepted
  } catch {
    e => limbo_classify(e)
  }
}

///|
fn limbo_run_suite(rel_path : String) -> Unit {
  let root = limbo_obj(limbo_load_json(rel_path), rel_path)
  let cases = limbo_arr(limbo_field(root, "cases", rel_path), rel_path)
  let mut accept_ok = 0
  let mut accept_skip = 0
  let mut reject_ok = 0
  let failures : Array[String] = []
  for jc in cases {
    let m = limbo_obj(jc, rel_path)
    let id = limbo_str(limbo_field(m, "id", rel_path), rel_path)
    let expect = limbo_str(limbo_field(m, "expect", rel_path), rel_path)
    let now = limbo_str(limbo_field(m, "now", rel_path), rel_path)
    let leaf = limbo_str(limbo_field(m, "leaf", rel_path), rel_path)
    let anchor = limbo_str(limbo_field(m, "anchor", rel_path), rel_path)
    let inters : Array[String] = []
    for ij in limbo_arr(limbo_field(m, "intermediates", rel_path), rel_path) {
      inters.push(limbo_str(ij, rel_path))
    }
    let outcome = limbo_run_case(anchor, leaf, inters, now)
    if expect == "reject" {
      match outcome {
        Accepted => failures.push("FALSE POSITIVE: reject-case accepted: " + id)
        _ => reject_ok = reject_ok + 1
      }
    } else {
      match outcome {
        Accepted => accept_ok = accept_ok + 1
        RejectedTolerable(_) => accept_skip = accept_skip + 1
        RejectedHard(why) =>
          failures.push(
            "OVER-REJECTION: accept-case refused: " + id + " (" + why + ")",
          )
      }
    }
  }
  let summary = rel_path +
    ": reject_ok=" +
    reject_ok.to_string() +
    " accept_ok=" +
    accept_ok.to_string() +
    " accept_skip=" +
    accept_skip.to_string() +
    " cases=" +
    cases.length().to_string()
  println(summary)
  if failures.length() > 0 {
    let shown = if failures.length() > 20 { 20 } else { failures.length() }
    println(
      failures.length().to_string() +
      " failures (showing " +
      shown.to_string() +
      "):",
    )
    for i = 0; i < shown; i = i + 1 {
      println("  " + failures[i])
    }
    abort(rel_path + ": " + failures.length().to_string() + " hard failures")
  }
}

///|
test "x509-limbo rfc5280 path validation (no false positives)" {
  limbo_run_suite("testdata/x509-limbo/limbo.json")
}

///|
test "BetterTLS name-constraints path validation (no false positives)" {
  limbo_run_suite("testdata/bettertls/nameconstraints.json")
}
