// Benchmarks for ChaCha20-Poly1305 throughput.

///|
let bench_key : Bytes = b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"

///|
let bench_nonce : Bytes = b"\x07\x00\x00\x00\x40\x41\x42\x43\x44\x45\x46\x47"

///|
test "bench aead ChaCha20-Poly1305 seal 1 KiB" (it : @bench.T) {
  let plaintext = Bytes::makei(1024, fn(i) { (i % 251).to_byte() })
  it.bench(name="seal 1KiB", count=200, () => {
    it.keep(
      @aead.seal(ChaCha20Poly1305, bench_key, bench_nonce, b"", plaintext) catch {
        _ => abort("unreachable")
      },
    )
  })
}

///|
test "bench aead ChaCha20-Poly1305 seal 16 KiB" (it : @bench.T) {
  let plaintext = Bytes::makei(16 * 1024, fn(i) { (i % 251).to_byte() })
  it.bench(name="seal 16KiB", count=50, () => {
    it.keep(
      @aead.seal(ChaCha20Poly1305, bench_key, bench_nonce, b"", plaintext) catch {
        _ => abort("unreachable")
      },
    )
  })
}

///|
test "bench aead ChaCha20-Poly1305 open 1 KiB" (it : @bench.T) {
  let plaintext = Bytes::makei(1024, fn(i) { (i % 251).to_byte() })
  let sealed = @aead.seal(
    ChaCha20Poly1305,
    bench_key,
    bench_nonce,
    b"",
    plaintext,
  ) catch {
    _ => abort("unreachable")
  }
  it.bench(name="open 1KiB", count=200, () => {
    it.keep(
      @aead.open(ChaCha20Poly1305, bench_key, bench_nonce, b"", sealed) catch {
        _ => abort("unreachable")
      },
    )
  })
}

///|
let bench_aes128_key : Bytes = b"\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"

///|
let bench_aes256_key : Bytes = b"\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"

///|
let bench_gcm_nonce : Bytes = b"\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88"

///|
test "bench aead AES-128-GCM seal 1 KiB" (it : @bench.T) {
  let plaintext = Bytes::makei(1024, fn(i) { (i % 251).to_byte() })
  it.bench(name="AES-128-GCM seal 1KiB", count=200, () => {
    it.keep(
      @aead.seal(Aes128Gcm, bench_aes128_key, bench_gcm_nonce, b"", plaintext) catch {
        _ => abort("unreachable")
      },
    )
  })
}

///|
test "bench aead AES-128-GCM seal 16 KiB" (it : @bench.T) {
  let plaintext = Bytes::makei(16 * 1024, fn(i) { (i % 251).to_byte() })
  it.bench(name="AES-128-GCM seal 16KiB", count=50, () => {
    it.keep(
      @aead.seal(Aes128Gcm, bench_aes128_key, bench_gcm_nonce, b"", plaintext) catch {
        _ => abort("unreachable")
      },
    )
  })
}

///|
test "bench aead AES-128-GCM open 1 KiB" (it : @bench.T) {
  let plaintext = Bytes::makei(1024, fn(i) { (i % 251).to_byte() })
  let sealed = @aead.seal(
    Aes128Gcm,
    bench_aes128_key,
    bench_gcm_nonce,
    b"",
    plaintext,
  ) catch {
    _ => abort("unreachable")
  }
  it.bench(name="AES-128-GCM open 1KiB", count=200, () => {
    it.keep(
      @aead.open(Aes128Gcm, bench_aes128_key, bench_gcm_nonce, b"", sealed) catch {
        _ => abort("unreachable")
      },
    )
  })
}

///|
test "bench aead AES-256-GCM seal 1 KiB" (it : @bench.T) {
  let plaintext = Bytes::makei(1024, fn(i) { (i % 251).to_byte() })
  it.bench(name="AES-256-GCM seal 1KiB", count=200, () => {
    it.keep(
      @aead.seal(Aes256Gcm, bench_aes256_key, bench_gcm_nonce, b"", plaintext) catch {
        _ => abort("unreachable")
      },
    )
  })
}

///|
test "bench aead AES-256-GCM seal 16 KiB" (it : @bench.T) {
  let plaintext = Bytes::makei(16 * 1024, fn(i) { (i % 251).to_byte() })
  it.bench(name="AES-256-GCM seal 16KiB", count=50, () => {
    it.keep(
      @aead.seal(Aes256Gcm, bench_aes256_key, bench_gcm_nonce, b"", plaintext) catch {
        _ => abort("unreachable")
      },
    )
  })
}

///|
test "bench aead AES-256-GCM open 1 KiB" (it : @bench.T) {
  let plaintext = Bytes::makei(1024, fn(i) { (i % 251).to_byte() })
  let sealed = @aead.seal(
    Aes256Gcm,
    bench_aes256_key,
    bench_gcm_nonce,
    b"",
    plaintext,
  ) catch {
    _ => abort("unreachable")
  }
  it.bench(name="AES-256-GCM open 1KiB", count=200, () => {
    it.keep(
      @aead.open(Aes256Gcm, bench_aes256_key, bench_gcm_nonce, b"", sealed) catch {
        _ => abort("unreachable")
      },
    )
  })
}
