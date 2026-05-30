#!/usr/bin/env python3
"""Differential false-positive audit for @pkix_verify.verify_chain_with_anchor_cert.

Emit EVERY reject testcase from x509-limbo (minus only the truly untestable
ones: revocation/online/webpki namespaces and cases whose requested identity
does not match the leaf SAN -- those reject for a reason the verifier never
inspects) into a single audit fixture, using a best-effort issuer->subject
ordering even when path-building would normally be required.

The MoonBit harness then runs each through verify_chain_with_anchor_cert and
prints the id of every reject case the verifier ACCEPTS. Each such id is a
candidate false positive to investigate (it may still be out-of-scope-by-design
-- EKU, SAN identity, policy tree -- but every one must be explained).

This is deliberately MORE permissive than gen_x509_limbo.py: it disables the
out_of_scope() scope filter AND the shared-subject path-building drop, so the
path-building reject cases (never exercised by the committed fixtures) are
audited too.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_x509_limbo import (  # noqa: E402
    cert_of,
    leaf_san_values,
    load_limbo,
    order_chain,
    rfc3339_to_generalized,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build_audit_case(t: dict):
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
    # Keep the identity filter: a reject that hinges only on SAN identity is a
    # known out-of-scope, not a chain-logic false positive.
    if epn["value"] not in leaf_san_values(leaf):
        return None
    ordered, anchor, _complete = order_chain(
        leaf_pem, t["untrusted_intermediates"], t["trusted_certs"]
    )
    if anchor is None:
        return None
    vt = t["validation_time"]
    try:
        now = "20240101000000Z" if vt is None else rfc3339_to_generalized(vt)
    except Exception:
        return None
    return {
        "id": t["id"],
        "expect": "reject",
        "now": now,
        "leaf": leaf_pem,
        "intermediates": ordered,
        "anchor": anchor,
        "features": t.get("features", []),
    }


def main() -> int:
    src = sys.argv[1] if len(sys.argv) > 1 else None
    limbo = load_limbo(src)
    cases = []
    for t in limbo["testcases"]:
        ns = t["id"].split("::")[0]
        if ns in ("online", "webpki", "crl"):
            continue
        if t["expected_result"] == "SUCCESS":
            continue  # audit only the reject direction
        c = build_audit_case(t)
        if c is not None:
            cases.append(c)
    cases.sort(key=lambda c: c["id"])
    out = os.path.join(REPO_ROOT, "testdata", "x509-limbo", "audit_reject.json")
    with open(out, "w") as fh:
        json.dump({"cases": cases}, fh, separators=(",", ":"))
    print(f"wrote {out}: {len(cases)} reject cases, {os.path.getsize(out)/1024:.0f} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
