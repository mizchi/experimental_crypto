// Full-corpus false-positive guard for the path-validation entry points.
//
// `scripts/audit_x509_limbo.py` emits testdata/x509-limbo/audit_reject.json:
// EVERY x509-limbo `reject` case (minus only revocation/online/webpki and
// identity-mismatch cases, whose verdict the verifier never inspects), using a
// best-effort issuer->subject ordering so even the path-building topologies the
// trimmed fixtures skip are exercised. That fixture is ~7.6 MB and is NOT
// committed (.gitignore); this test no-ops when it is absent, and runs the full
// 2200+ case sweep locally after:
//
//   python3 scripts/audit_x509_limbo.py && moon test -p mizchi/pkix_verify --target js
//
// Soundness rule: a `reject` case the verifier ACCEPTS is a candidate false
// positive. Every such case must be *explained* as out-of-scope-by-design,
// otherwise it is a real chain-trust false positive and the test fails:
//
//   * EKU-gated: the case rejects once the caller opts in to required_eku=
//     serverAuth. BetterTLS's pathbuilding reject cases all reduce to EKU
//     nesting (an emailProtection/clientAuth intermediate may not delegate
//     serverAuth); the verifier defers EKU by default and enforces it on
//     opt-in (locked in by the "ATTACK EKU nesting" regression test).
//   * A documented out-of-scope class: extendedKeyUsage / authority+subject key
//     identifiers / SAN identity (caller's job), caller-config chain-depth caps,
//     denial-of-service limits, pedantic encodings, and the handful of RFC-vs-
//     webpki / nameConstraints-profile-placement quirks enumerated below (kept
//     in lockstep with EXPLICIT_SKIP / SKIP_FEATURES / SKIP_SUBNS in
//     scripts/gen_x509_limbo.py).

///|
// Read a fixture, returning "" when the file is absent (the committed/CI state
// for the gitignored audit fixture) instead of throwing an uncaught JS error.
extern "js" fn audit_try_read_text(rel_path : String) -> String =
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
  #|   return ""
  #| }

///|
fn audit_subns(id : String) -> String {
  let parts = id.split("::").collect()
  if parts.length() > 1 {
    parts[1].to_owned()
  } else {
    ""
  }
}

///|
// Re-run an accepted reject-case with required_eku=serverAuth; returns true iff
// it then rejects (i.e. the original acceptance was only because EKU defaults to
// caller-opt-in).
fn audit_eku_gated(
  anchor_pem : String,
  leaf_pem : String,
  inter_pems : Array[String],
  now : String,
) -> Bool {
  let anchor = limbo_decode_cert(anchor_pem) catch { _ => return false }
  let leaf = limbo_decode_cert(leaf_pem) catch { _ => return false }
  let inters : Array[@pkix.Certificate] = []
  for p in inter_pems {
    let c = limbo_decode_cert(p) catch { _ => return false }
    inters.push(c)
  }
  let anchor_pk = @pkix_verify.extract_public_key(
    anchor.tbs.subject_public_key_info,
  ) catch {
    _ => return false
  }
  let server_auth = @asn1.ObjectIdentifier::from_arcs([
    1U, 3, 6, 1, 5, 5, 7, 3, 1,
  ])
  let opts = {
    ..@pkix_verify.VerifyChainOptions::default(),
    required_eku: Some(server_auth),
  }
  try {
    @pkix_verify.verify_chain_with_options(leaf, inters, anchor_pk, now, opts)
    false
  } catch {
    _ => true
  }
}

///|
// Subnamespaces (second `::` component, rfc5280) the verifier deliberately does
// not treat as a trust gate: EKU is caller-opt-in, key identifiers are path-
// building hints, SAN is identity.
fn audit_subns_out_of_scope(subns : String) -> Bool {
  subns == "eku" || subns == "aki" || subns == "ski" || subns == "san"
}

///|
// Specific reject ids whose verdict hinges on a profile rule the verifier does
// not enforce (mirrors EXPLICIT_SKIP + the webpki disagreement in
// scripts/gen_x509_limbo.py).
fn audit_id_out_of_scope(id : String) -> Bool {
  id == "rfc5280::leaf-ku-keycertsign" ||
  id == "rfc5280::root-non-critical-basic-constraints" ||
  id == "rfc5280::nc::invalid-dnsname-leading-period" ||
  id == "rfc5280::nc::not-allowed-in-ee-critical" ||
  id == "rfc5280::nc::not-allowed-in-ee-noncritical" ||
  id == "rfc5280::nc::permitted-dns-match-noncritical"
}

///|
fn audit_feature_out_of_scope(features : Array[String]) -> Bool {
  for f in features {
    if f == "max-chain-depth" ||
      f == "denial-of-service" ||
      f.has_prefix("pedantic") {
      return true
    }
  }
  false
}

///|
test "AUDIT full-corpus reject sweep (no unexplained false positives)" {
  let text = audit_try_read_text("testdata/x509-limbo/audit_reject.json")
  if text == "" {
    println("AUDIT: audit_reject.json absent; skipping full-corpus sweep")
    return
  }
  let root = limbo_obj(
    @json.parse(text[:]) catch {
      e => abort("audit parse: " + repr(e))
    },
    "audit",
  )
  let cases = limbo_arr(limbo_field(root, "cases", "audit"), "audit")
  let mut total = 0
  let mut accepted = 0
  let unexplained : Array[String] = []
  for jc in cases {
    let m = limbo_obj(jc, "audit")
    let id = limbo_str(limbo_field(m, "id", "audit"), "audit")
    let now = limbo_str(limbo_field(m, "now", "audit"), "audit")
    let leaf = limbo_str(limbo_field(m, "leaf", "audit"), "audit")
    let anchor = limbo_str(limbo_field(m, "anchor", "audit"), "audit")
    let inters : Array[String] = []
    for ij in limbo_arr(limbo_field(m, "intermediates", "audit"), "audit") {
      inters.push(limbo_str(ij, "audit"))
    }
    let features : Array[String] = []
    match m.get("features") {
      Some(Array(a)) =>
        for f in a {
          features.push(limbo_str(f, "feat"))
        }
      _ => ()
    }
    total = total + 1
    match limbo_run_case(anchor, leaf, inters, now) {
      Accepted => {
        accepted = accepted + 1
        let explained = audit_subns_out_of_scope(audit_subns(id)) ||
          audit_id_out_of_scope(id) ||
          audit_feature_out_of_scope(features) ||
          audit_eku_gated(anchor, leaf, inters, now)
        if !explained {
          unexplained.push(id)
        }
      }
      _ => ()
    }
  }
  println(
    "AUDIT: total_reject=" +
    total.to_string() +
    " accepted=" +
    accepted.to_string() +
    " unexplained=" +
    unexplained.length().to_string(),
  )
  if unexplained.length() > 0 {
    for s in unexplained {
      println("  NEW FALSE POSITIVE: " + s)
    }
    abort(
      "audit: " +
      unexplained.length().to_string() +
      " unexplained reject-case acceptance(s) (real false positives)",
    )
  }
}
