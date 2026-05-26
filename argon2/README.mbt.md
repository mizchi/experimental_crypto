# mizchi/argon2

Argon2id PHC-formatted password hashing (RFC 9106).

## Memory hygiene

Argon2 by design allocates `m_cost` KiB of secret-derived blocks,
fills them via the BLAKE2b round function, and reads them back in
a pseudo-random pattern. The intermediate blocks are all
secret-derived (function of the password and salt).

**This module does not zero those blocks.** Argon2's working set
is large (often 64 MiB+ for production parameters), and the
allocation lifetimes are entangled with the GC. Adding a wipe loop
over every block per call has non-trivial cost relative to the
hash itself.

The trade-off is documented but not closed. A heap dump or
cold-boot attack mounted during an Argon2 call, or shortly after,
could recover memory-derived material with no programmatic
defence. Treat Argon2 working memory as confidential at the OS
level (e.g. via process-private memory and `mlock` if available
to the runtime).
