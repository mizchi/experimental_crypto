# mizchi/aead

Authenticated encryption with associated data (AEAD) primitives.

Supported algorithms:

- `ChaCha20Poly1305` (RFC 8439)
- `Aes128Gcm` (FIPS 197 + NIST SP 800-38D)
- `Aes256Gcm` (FIPS 197 + NIST SP 800-38D)
- `XChaCha20Poly1305` — currently raises `UnsupportedAlgorithm`

## ⚠ Nonce reuse is catastrophic

Every AEAD construction in this package is **deterministic**: the
ciphertext and the authentication tag are a pure function of
`(key, nonce, aad, plaintext)`. Reusing the same `(key, nonce)` pair
for two different plaintexts is the worst possible failure mode:

- For ChaCha20-Poly1305, the keystream XORs of the two plaintexts
  leak (`c1 XOR c2 == p1 XOR p2`), and the Poly1305 one-time MAC key
  can be recovered, allowing **forgery of arbitrary new messages**
  under that key.
- For AES-GCM, the same reuse leaks the GHASH authentication key,
  which collapses the entire authenticator and lets an attacker
  forge new (aad, ciphertext) pairs at will.

**This library does NOT track nonces.** The caller is fully
responsible for ensuring the nonce is unique per `(key, message)`.
There are two safe patterns:

### Random nonces

Draw the nonce from a real CSPRNG (e.g. `mizchi/getrandom`):

```moonbit nocheck
///|
let nonce = @getrandom.bytes(12) // 12 bytes for all algorithms here

///|
let sealed = @aead.seal(ChaCha20Poly1305, key, nonce, aad, plaintext)
```

The collision probability with random 96-bit nonces is bounded by
the birthday paradox; staying under ~2^32 messages per key gives you
a 2^-32 collision probability, which is the standard "rekey after
2^32 messages" rule for AES-GCM and ChaCha20-Poly1305.

### Counter nonces

A monotonically increasing 96-bit counter, persisted reliably:

```moonbit nocheck
///|
let counter : Int64 = next_counter() // persisted across crashes

///|
let nonce = encode_u96_be(counter)

///|
let sealed = @aead.seal(ChaCha20Poly1305, key, nonce, aad, plaintext)
```

Counter nonces avoid the birthday limit entirely but require that
the counter never resets (no rollover, no replay across forks of
the process state).

XChaCha20-Poly1305, when enabled, is the safer option for
applications that can't guarantee either: its 192-bit nonce makes
random selection collision-safe at any practical scale.

## Other limitations

- `Aes128Gcm` and `Aes256Gcm` use a T-table AES implementation that
  is **not constant-time**. Cache-timing attacks can recover the
  key. Do not use on machines shared with untrusted tenants.
- `ChaCha20Poly1305` is constant-time at the algorithm level, but
  underlying `u64 *` on wasm / JS is not formally constant-time.

## Memory hygiene

The ChaCha20-Poly1305 path makes a best-effort attempt to zero
short-lived secrets before returning: the one-time Poly1305 key
and the per-call ChaCha20 keystream scratch buffer are overwritten
in their `FixedArray[Byte]` backing storage. This is best-effort
only — MoonBit gives no guarantee against compiler dead-store
elimination, and the GC may have already relocated copies before
the wipe runs. It shortens the window during which a heap dump or
cold-boot attack could recover the secret, but is not a substitute
for OS-level memory protection. AES-GCM round keys and GHASH state
are not wiped today.

See the workspace-root `security_review.md` for the full audit.
