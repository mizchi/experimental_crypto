# mizchi/ocsp

> **Status: experimental.** Built to fill a gap in the MoonBit ecosystem;
> not production-grade. The implementation has not been independently
> audited. If you use it, review the source yourself — the author
> disclaims all liability. Prefer a vetted library where one exists.

OCSP (RFC 6960) response parsing + verification.

```moonbit
@ocsp.parse_response(der) -> OcspResponse raise OcspError
@ocsp.verify(der, cert, issuer_cert, now) -> CertStatus raise OcspError
// CertStatus = Good | Revoked(time, reason) | Unknown
```

Supports direct-signed and delegated-responder OCSP signing paths and
SHA-1 / SHA-256 CertIDs. OCSP request construction, nonce extension,
HTTP transport, `id-pkix-ocsp-nocheck` on delegated responders, and
archive cutoff are out of scope.
