# mizchi/crl

> **Status: experimental.** Built to fill a gap in the MoonBit ecosystem;
> not production-grade. The implementation has not been independently
> audited. If you use it, review the source yourself — the author
> disclaims all liability. Prefer a vetted library where one exists.

X.509 Certificate Revocation List (CRL) parse + verify per RFC 5280 §5.

```moonbit nocheck
@crl.parse(der) -> Crl raise CrlError
@crl.verify(der, issuer_cert, now) -> Crl raise CrlError
@crl.is_revoked(crl, serial) -> Bool
```

Verifies the CRL signature against the issuer's `SubjectPublicKeyInfo`
and checks `thisUpdate <= now < nextUpdate`. `cRLNumber` is accepted only as a
non-critical DER INTEGER. Other CRL and CRL-entry extensions are rejected
rather than ignored, including delta CRLs, issuing distribution points, and
indirect-CRL `certificateIssuer` entry semantics.
