#!/usr/bin/env python3
"""Generate trimmed x509-limbo / BetterTLS path-validation fixtures.

x509-limbo (https://github.com/C2SP/x509-limbo) bundles the Netflix BetterTLS
name-constraints corpus under its `bettertls::` namespace, so a single download
covers both suites. The full `limbo.json` is ~40 MB, which is far larger than
this repo's other fixtures, so this script downloads it once and emits two
compact, sound subsets that the MoonBit harness in
`pkix_verify/limbo_json_js_test.mbt` can replay against `@pkix_verify`.

Soundness model
---------------
`@pkix_verify.verify_chain` performs RFC 5280 path validation (signatures,
validity, basicConstraints, pathLen, keyUsage, dNSName name constraints,
critical-extension rejection, DN chaining) but deliberately does NOT perform
hostname / SAN identity matching, EKU policy, certificate policies, or
revocation. To avoid flagging those out-of-scope behaviours as bugs we only
keep cases whose verdict is determined by what the library DOES enforce:

  * Drop the `online`, `webpki`, and `crl` namespaces and any case carrying
    CRLs (revocation is out of scope).
  * Keep a case only if the requested peer name (`expected_peer_name`) is one
    of the leaf's SAN entries. Then identity always matches, so a FAILURE can
    only come from the chain / name-constraint logic the library enforces, and
    a SUCCESS is not gated on an identity check the library skips.
  * For the `accept` (SUCCESS) direction we additionally require a clean,
    unambiguous issuer->subject ordering of the intermediates; if no path can
    be built we skip (the library needs pre-ordered intermediates).

The harness then asserts:
  * expect == "reject": the library MUST NOT return success (false-positive
    detector -- this is the class of the nameConstraints bypass fixed in PR #2).
  * expect == "accept": the library SHOULD return success; a rejection is
    reported as a (tolerated) skip when it stems from an unsupported algorithm
    and as a failure otherwise.

Usage: python3 scripts/gen_x509_limbo.py [path-to-limbo.json]
"""

from __future__ import annotations

import collections
import datetime
import json
import os
import sys
import urllib.request

from asn1crypto import pem, x509

LIMBO_URL = "https://raw.githubusercontent.com/C2SP/x509-limbo/main/limbo.json"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Budget: keep each emitted fixture in line with the repo's existing Wycheproof
# fixtures (~100-350 KB each). BetterTLS is sampled deterministically to fit.
BETTERTLS_MAX_REJECT = 150
BETTERTLS_MAX_ACCEPT = 55


def load_limbo(path: str | None) -> dict:
    if path and os.path.exists(path):
        with open(path) as fh:
            return json.load(fh)
    cache = "/tmp/limbo.json"
    if os.path.exists(cache):
        with open(cache) as fh:
            return json.load(fh)
    print(f"downloading {LIMBO_URL} ...", file=sys.stderr)
    urllib.request.urlretrieve(LIMBO_URL, cache)
    with open(cache) as fh:
        return json.load(fh)


def der_of(pem_str: str) -> bytes:
    return pem.unarmor(pem_str.encode())[2]


def cert_of(pem_str: str) -> x509.Certificate:
    return x509.Certificate.load(der_of(pem_str))


def leaf_san_values(cert: x509.Certificate) -> set[str]:
    out: set[str] = set()
    try:
        for ext in cert["tbs_certificate"]["extensions"]:
            if ext["extn_id"].native == "subject_alt_name":
                for gn in ext["extn_value"].parsed:
                    if gn.name == "dns_name":
                        out.add(gn.native)
                    elif gn.name == "ip_address":
                        out.add(str(gn.native))
    except Exception:
        pass
    return out


def rfc3339_to_generalized(ts: str) -> str:
    # "2024-01-01T00:00:00+00:00" -> "20240101000000Z" (UTC, GeneralizedTime).
    dt = datetime.datetime.fromisoformat(ts)
    if dt.tzinfo is not None:
        dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return dt.strftime("%Y%m%d%H%M%S") + "Z"


def order_chain(leaf_pem: str, inter_pems: list[str], trusted_pems: list[str]):
    """Return (ordered_intermediate_pems, anchor_pem, complete).

    Walks issuer->subject links from the leaf up to a trusted anchor. `complete`
    is True iff a full path to a trusted cert was found with each hop's issuer
    matching the next subject. On failure we still return a best-effort ordering
    so reject-cases (which the library must refuse anyway) remain usable.
    """
    inter = {}
    for p in inter_pems:
        try:
            c = cert_of(p)
            inter[c["tbs_certificate"]["subject"].dump()] = (p, c)
        except Exception:
            return inter_pems, (trusted_pems[0] if trusted_pems else None), False
    trusted = {}
    for p in trusted_pems:
        try:
            c = cert_of(p)
            trusted[c["tbs_certificate"]["subject"].dump()] = (p, c)
        except Exception:
            pass

    try:
        cur = cert_of(leaf_pem)
    except Exception:
        return inter_pems, (trusted_pems[0] if trusted_pems else None), False

    ordered: list[str] = []
    seen: set[str] = set()
    while True:
        issuer = cur["tbs_certificate"]["issuer"].dump()
        if issuer in trusted:
            return ordered, trusted[issuer][0], True
        if issuer in inter and issuer not in seen:
            seen.add(issuer)
            p, c = inter[issuer]
            ordered.append(p)
            cur = c
            continue
        # No further link: best-effort (used only by reject-cases).
        leftover = [p for p in inter_pems if p not in ordered]
        anchor = trusted_pems[0] if trusted_pems else None
        return ordered + leftover, anchor, False


# x509-limbo "proper" (non-bettertls) sub-namespaces whose verdict depends on
# features verify_chain deliberately does not implement, so they cannot be used
# as a sound accept/reject oracle here:
#   nc  -> these put nameConstraints on the *trust anchor* (root); the verifier
#          treats the anchor as an unconstrained key, so anchor-level NC is not
#          enforced. Intermediate-level NC is covered exhaustively by the
#          bettertls suite instead.
#   eku/aki/ski -> extendedKeyUsage / authority+subject key identifiers are not
#          part of the chain-trust decision (EKU is caller-opt-in).
#   pc  -> policy constraints / certificate policies. The verifier does not run
#          the §6.1 policy tree, but it DOES reject `policyConstraints`
#          fail-closed, so the `pc` reject-cases are a valid false-positive
#          oracle. The single `ica-noncritical-pc` case is emitted separately
#          into testdata/x509-limbo/policy.json (see emit_policy below); it is
#          not folded into the main rfc5280 fixture.
# Sub-namespaces the verifier does not implement as a trust gate: extendedKeyUsage
# is caller-opt-in, authority/subject key identifiers are not chained, certificate
# policies are unimplemented, and SAN identity matching is the caller's job. (NC
# is enforced — including on the anchor — via verify_chain_with_anchor_cert.)
SKIP_SUBNS = {"eku", "aki", "ski", "pc", "san"}

# Individual ids that hinge on a rule the verifier deliberately does not enforce,
# even with certificate-anchored validation:
#   *-non-critical-basic-constraints -> basicConstraints criticality is a pedantic
#       profile rule the verifier does not require.
#   ca-empty-subject / ee-empty-issuer -> empty-DN edge cases / top-link DN.
#   leaf-ku-keycertsign -> leaf keyUsage policy, out of scope.
#   nc::invalid-dnsname-* -> dNSName constraint encoding profile rules (no
#       leading period / wildcard); the verifier interprets rather than rejects
#       these, and still applies the constraint, so it is not a bypass.
#   nc::not-allowed-in-ee-* -> "nameConstraints MUST appear only in a CA cert"
#       profile placement rule; the verifier ignores NC on a leaf rather than
#       rejecting its presence.
EXPLICIT_SKIP = {
    "rfc5280::root-non-critical-basic-constraints",
    "rfc5280::ca-empty-subject",
    "rfc5280::ee-empty-issuer",
    "rfc5280::leaf-ku-keycertsign",
    "rfc5280::nc::invalid-dnsname-leading-period",
    "rfc5280::nc::not-allowed-in-ee-noncritical",
    "rfc5280::nc::not-allowed-in-ee-critical",
}

# Features that pull a case out of verify_chain's scope (verifier-config chain
# depth caps, DoS limits, policy constraints, revocation, RFC-vs-webpki profile
# quirks like "nameConstraints must be critical", and pedantic encodings).
SKIP_FEATURES = {
    "max-chain-depth",
    "denial-of-service",
    "has-policy-constraints",
    "rfc5280-incompatible-with-webpki",
    "has-crl",
}


def out_of_scope(t: dict) -> bool:
    parts = t["id"].split("::")
    ns = parts[0]
    if ns == "bettertls":
        # Path-building tests need path discovery (the verifier takes ordered
        # intermediates); keep only the name-constraint suite.
        return len(parts) > 1 and parts[1] != "nameconstraints"
    if len(parts) > 1 and parts[1] in SKIP_SUBNS:
        return True
    if t["id"] in EXPLICIT_SKIP:
        return True
    for f in t["features"]:
        if f in SKIP_FEATURES or f.startswith("pedantic"):
            return True
    return False


def build_case(t: dict):
    if t.get("crls"):
        return None
    if out_of_scope(t):
        return None
    if not t["trusted_certs"]:
        return None
    epn = t.get("expected_peer_name")
    if not epn:
        return None
    leaf_pem = t["peer_certificate"]
    try:
        leaf = cert_of(leaf_pem)
    except Exception:
        return None
    if epn["value"] not in leaf_san_values(leaf):
        return None  # identity does not match -> verdict not determined by us

    # Path building is out of scope: verify_chain takes a single pre-ordered
    # intermediate list, so it cannot choose among candidates that share a
    # subject DN. This covers the "chain of pain" (a cross-cert sharing the
    # root's DN) and CA key-rollover / self-issued topologies, where picking
    # the validating path requires trying signatures. Skip when any subject DN
    # is shared across the supplied intermediates and trust anchors.
    subjects = []
    for p in t["untrusted_intermediates"] + t["trusted_certs"]:
        try:
            subjects.append(cert_of(p)["tbs_certificate"]["subject"].dump())
        except Exception:
            return None
    if len(subjects) != len(set(subjects)):
        return None

    expect = "accept" if t["expected_result"] == "SUCCESS" else "reject"
    ordered, anchor, complete = order_chain(
        leaf_pem, t["untrusted_intermediates"], t["trusted_certs"]
    )
    if anchor is None:
        return None
    if expect == "accept" and not complete:
        return None  # cannot pre-order a path the library would accept

    # A null validation_time means the case is time-independent; limbo emits
    # such certs with a 1970..2969 validity window, so a fixed in-range epoch
    # is safe and reproducible.
    vt = t["validation_time"]
    try:
        now = "20240101000000Z" if vt is None else rfc3339_to_generalized(vt)
    except Exception:
        return None

    return {
        "id": t["id"],
        "expect": expect,
        "now": now,
        "leaf": leaf_pem,
        "intermediates": ordered,
        "anchor": anchor,
    }


def build_policy_case(t: dict):
    """Build a fixture case for an rfc5280::pc:: (policy) testcase.

    These are skipped by `build_case` (pc is in SKIP_SUBNS) because the verifier
    does not run the §6.1 policy tree. It DOES, however, reject policyConstraints
    fail-closed, so the pc reject-cases are a valid false-positive oracle. We
    reuse the same ordering / time logic as build_case, minus the scope filter.
    """
    if t.get("crls") or not t["trusted_certs"]:
        return None
    epn = t.get("expected_peer_name")
    if not epn:
        return None
    leaf_pem = t["peer_certificate"]
    try:
        leaf = cert_of(leaf_pem)
    except Exception:
        return None
    if epn["value"] not in leaf_san_values(leaf):
        return None
    expect = "accept" if t["expected_result"] == "SUCCESS" else "reject"
    ordered, anchor, complete = order_chain(
        leaf_pem, t["untrusted_intermediates"], t["trusted_certs"]
    )
    if anchor is None or (expect == "accept" and not complete):
        return None
    vt = t["validation_time"]
    try:
        now = "20240101000000Z" if vt is None else rfc3339_to_generalized(vt)
    except Exception:
        return None
    return {
        "id": t["id"],
        "expect": expect,
        "now": now,
        "leaf": leaf_pem,
        "intermediates": ordered,
        "anchor": anchor,
    }


def write_fixture(path: str, version: str, source: str, cases: list[dict]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(
            {"limbo_version": version, "source": source, "cases": cases},
            fh,
            separators=(",", ":"),
        )
    size = os.path.getsize(path)
    counts = collections.Counter(c["expect"] for c in cases)
    print(
        f"wrote {path}: {len(cases)} cases "
        f"(accept={counts['accept']}, reject={counts['reject']}, {size/1024:.0f} KB)"
    )


def main() -> int:
    src = sys.argv[1] if len(sys.argv) > 1 else None
    limbo = load_limbo(src)
    version = str(limbo.get("version", "?"))

    rfc5280, bettertls, policy = [], [], []
    for t in limbo["testcases"]:
        ns = t["id"].split("::")[0]
        if ns in ("online", "webpki", "crl"):
            continue
        parts = t["id"].split("::")
        if ns == "rfc5280" and len(parts) > 1 and parts[1] == "pc":
            # Policy / policyConstraints cases — emitted to policy.json.
            pc = build_policy_case(t)
            if pc is not None:
                policy.append(pc)
            continue
        case = build_case(t)
        if case is None:
            continue
        if ns == "bettertls":
            bettertls.append(case)
        else:
            rfc5280.append(case)
    policy.sort(key=lambda c: c["id"])

    # Deterministic sampling of the large BetterTLS suite, keeping the
    # reject/accept split and spanning the combinatorial space evenly.
    def sample(cases, expect, cap):
        sel = [c for c in cases if c["expect"] == expect]
        if len(sel) <= cap:
            return sel
        step = len(sel) / cap
        return [sel[int(i * step)] for i in range(cap)]

    bettertls_sampled = sample(bettertls, "reject", BETTERTLS_MAX_REJECT) + sample(
        bettertls, "accept", BETTERTLS_MAX_ACCEPT
    )
    bettertls_sampled.sort(key=lambda c: c["id"])

    write_fixture(
        os.path.join(REPO_ROOT, "testdata", "x509-limbo", "limbo.json"),
        version,
        "C2SP/x509-limbo rfc5280/pathlen/pathological/cve namespaces",
        rfc5280,
    )
    write_fixture(
        os.path.join(REPO_ROOT, "testdata", "bettertls", "nameconstraints.json"),
        version,
        "C2SP/x509-limbo bettertls:: namespace (Netflix BetterTLS corpus), sampled",
        bettertls_sampled,
    )
    write_fixture(
        os.path.join(REPO_ROOT, "testdata", "x509-limbo", "policy.json"),
        version,
        "C2SP/x509-limbo rfc5280::pc namespace (certificate policy / policyConstraints)",
        policy,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
