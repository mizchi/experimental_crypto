#include <moonbit.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
  #include <stdlib.h>      /* arc4random_buf */
  #define MZ_USE_ARC4RANDOM 1
#elif defined(__linux__)
  #include <errno.h>
  #include <sys/random.h>  /* getrandom(2) */
  #include <unistd.h>
  #define MZ_USE_GETRANDOM 1
#elif defined(_WIN32)
  #include <windows.h>
  #include <bcrypt.h>
  #define MZ_USE_BCRYPT 1
#endif

/*
 * mz_getrandom_bytes(len) returns a moonbit Bytes filled with `len` CSPRNG
 * bytes from the OS. On failure (which is rare for these APIs but can happen
 * e.g. on systems with no entropy source) we return an empty Bytes; the
 * MoonBit side raises Insufficient in that case.
 */
moonbit_bytes_t mz_getrandom_bytes(int32_t len) {
  if (len <= 0) {
    return moonbit_make_bytes(0, 0);
  }
  moonbit_bytes_t out = moonbit_make_bytes(len, 0);
  unsigned char *buf = (unsigned char *)out;

#if defined(MZ_USE_ARC4RANDOM)
  arc4random_buf(buf, (size_t)len);
  return out;

#elif defined(MZ_USE_GETRANDOM)
  size_t remaining = (size_t)len;
  unsigned char *p = buf;
  while (remaining > 0) {
    ssize_t n = getrandom(p, remaining, 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      /* unrecoverable: return empty so the MoonBit side surfaces an error */
      return moonbit_make_bytes(0, 0);
    }
    p += (size_t)n;
    remaining -= (size_t)n;
  }
  return out;

#elif defined(MZ_USE_BCRYPT)
  NTSTATUS status = BCryptGenRandom(
    NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (status != 0) {
    return moonbit_make_bytes(0, 0);
  }
  return out;

#else
  /* Unknown platform: clear the buffer and return empty to signal failure. */
  memset(buf, 0, (size_t)len);
  return moonbit_make_bytes(0, 0);
#endif
}
