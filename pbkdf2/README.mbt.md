# mizchi/pbkdf2

> **Status: experimental.** Built to fill a gap in the MoonBit ecosystem;
> not production-grade. The implementation has not been independently
> audited. If you use it, review the source yourself — the author
> disclaims all liability. Prefer a vetted library where one exists.


RFC 8018 PBKDF2 with PRF = HMAC-SHA-256. Other hashes are stubbed
out and raise `UnsupportedHash`.

## Memory hygiene

The PBKDF2 driver makes a best-effort attempt to zero
password-derived intermediates before returning: the precomputed
HMAC ipad / opad SHA-256 states (`HmacSha256Ctx::clear`), the
latest `U_i` block, the accumulated `T_i` block, and the salt ||
INT(blk) scratch buffer are all overwritten in their
`FixedArray[Byte]` / `FixedArray[UInt]` backing storage.

This is best-effort only — MoonBit gives no guarantee against
compiler dead-store elimination, and the GC may have already
relocated copies of the state before the wipe runs. It shortens
the window during which a heap dump could substitute the
ipad/opad state for the password's HMAC key in an offline
dictionary attack.
