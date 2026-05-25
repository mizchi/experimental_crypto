// Native backend: arc4random_buf on macOS/BSD, getrandom(2) on Linux,
// BCryptGenRandom on Windows. Selection is done at C compile time;
// see getrandom_native.c.

///|
extern "C" fn ffi_random_bytes(len : Int) -> Bytes = "mz_getrandom_bytes"
