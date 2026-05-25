// JS backend: uses globalThis.crypto.getRandomValues, which is available in
// Node 19+ and every modern browser. Throws if no Web Crypto is present.

///|
extern "js" fn ffi_random_bytes(len : Int) -> Bytes =
  #| (len) => {
  #|   const u8 = new Uint8Array(len)
  #|   const g = typeof globalThis !== "undefined" ? globalThis : self
  #|   if (!g.crypto || typeof g.crypto.getRandomValues !== "function") {
  #|     throw new Error("Web Crypto unavailable: globalThis.crypto.getRandomValues is missing")
  #|   }
  #|   g.crypto.getRandomValues(u8)
  #|   return u8
  #| }
