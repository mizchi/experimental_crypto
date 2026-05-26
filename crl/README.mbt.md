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
and checks `thisUpdate <= now < nextUpdate`. Supports RSA-SHA-256 and
ECDSA-SHA-{256,384} CRL signatures. Extensions are parsed but not
validated (delta-CRLs, CRL distribution points, indirect CRLs are not
covered).
