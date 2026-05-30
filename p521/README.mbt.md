# mizchi/p521

> **Status: experimental.** Built to fill a gap in the MoonBit ecosystem;
> not production-grade. The implementation has not been independently
> audited. If you use it, review the source yourself — the author
> disclaims all liability. Prefer a vetted library where one exists.

P-521 sign-side base-point multiplication and final nonce inversion use
fixed-limb / fixed-iteration paths, but the current implementation still needs
repeated calibrated leakage evidence before any measured constant-time claim.
Public verification remains affine because its inputs are public.

## Security Disclaimer ⚠️

This implementation of these cryptographic algorithms is provided without any
security endorsement or professional certification. The experimental_crypto
project should be considered:

- An educational reference implementation
- Experimental cryptography software
- Not reviewed by third-party security experts
