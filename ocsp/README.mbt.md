# mizchi/ocsp

> **Status: experimental.** Built to fill a gap in the MoonBit ecosystem;
> not production-grade. The implementation has not been independently
> audited. If you use it, review the source yourself — the author
> disclaims all liability. Prefer a vetted library where one exists.

OCSP (RFC 6960) response parsing + verification.

```moonbit nocheck
@ocsp.parse_response(der) -> OcspResponse raise OcspError
@ocsp.verify(der, cert, issuer_cert, now) -> CertStatus raise OcspError
@ocsp.verify_with_nonce(der, cert, issuer_cert, now, expected_nonce) -> CertStatus raise OcspError
// CertStatus = Good | Revoked(time, reason) | Unknown
```

Supports direct-signed and delegated-responder OCSP signing paths and
SHA-1 / SHA-256 CertIDs. Delegated responder certs must carry the non-critical
`id-pkix-ocsp-nocheck` extension because this module does not recursively check
responder-certificate revocation. Verified `SingleResponse` entries must carry
a freshness upper bound (`thisUpdate <= now < nextUpdate`).
`verify_with_nonce` requires the signed `id-pkix-ocsp-nonce` response extension
to exactly match the request nonce. The legacy `verify` API rejects
nonce-bearing responses because it cannot bind them to a request. OCSP request
construction, HTTP transport, and archive cutoff are out of scope.
