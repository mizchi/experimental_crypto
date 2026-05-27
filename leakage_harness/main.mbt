///|
struct Sink {
  mut acc : Int
}

///|
struct Workload {
  name : String
  sparse : () -> Unit
  dense : () -> Unit
}

///|
fn hex_nibble(c : Int) -> Int {
  if c >= '0'.to_int() && c <= '9'.to_int() {
    c - '0'.to_int()
  } else if c >= 'a'.to_int() && c <= 'f'.to_int() {
    c - 'a'.to_int() + 10
  } else if c >= 'A'.to_int() && c <= 'F'.to_int() {
    c - 'A'.to_int() + 10
  } else {
    abort("non-hex character in fixture")
  }
}

///|
fn hex(s : String) -> Bytes {
  let n = s.length()
  if n % 2 != 0 {
    abort("odd-length hex fixture")
  }
  Bytes::makei(n / 2, fn(i) {
    let hi = hex_nibble(s.code_unit_at(i * 2).to_int())
    let lo = hex_nibble(s.code_unit_at(i * 2 + 1).to_int())
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn sink_bytes(sink : Sink, b : Bytes) -> Unit {
  let mut acc = sink.acc
  acc = (acc << 5) - acc + b.length()
  if b.length() > 0 {
    acc = acc ^ b[0].to_int()
    acc = acc ^ (b[b.length() - 1].to_int() << 1)
  }
  sink.acc = acc
}

///|
fn sink_bool(sink : Sink, b : Bool) -> Unit {
  let v = if b { 1 } else { 0 }
  sink.acc = (sink.acc << 5) - sink.acc + v
}

///|
fn uint_fixture(limb_count : Int, limbs : Array[UInt64]) -> @crypto_bigint.Uint {
  let arr = FixedArray::make(limb_count, 0UL)
  for i in 0..<limbs.length() {
    if i < limb_count {
      arr[i] = limbs[i]
    }
  }
  { limbs: arr }
}

///|
fn p256_order_uint() -> @crypto_bigint.Uint {
  uint_fixture(4, [
    0xf3b9_cac2_fc63_2551UL, 0xbce6_faad_a717_9e84UL, 0xffff_ffff_ffff_ffffUL, 0xffff_ffff_0000_0000UL,
  ])
}

///|
fn bigint_base_uint() -> @crypto_bigint.Uint {
  uint_fixture(4, [
    0x0123_4567_89ab_cdefUL, 0xfedc_ba98_7654_3210UL, 0x0f0e_0d0c_0b0a_0908UL, 0x8070_6050_4030_2010UL,
  ])
}

///|
fn sparse_uint() -> @crypto_bigint.Uint {
  uint_fixture(4, [1UL, 0UL, 0UL, 0x8000_0000_0000_0000UL])
}

///|
fn dense_uint() -> @crypto_bigint.Uint {
  uint_fixture(4, [
    0xffff_ffff_ffff_fffeUL, 0xffff_ffff_ffff_ffffUL, 0xffff_ffff_ffff_ffffUL, 0x7fff_ffff_ffff_ffffUL,
  ])
}

///|
fn fixed_msg32() -> Bytes {
  Bytes::makei(32, fn(i) { i.to_byte() })
}

///|
fn p256_sparse_scalar() -> Bytes {
  hex("0000000000000000000000000000000000000000000000000000000000000001")
}

///|
fn p256_dense_scalar() -> Bytes {
  hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f")
}

///|
fn p384_sparse_scalar() -> Bytes {
  hex(
    "00000000000000000000000000000000" +
    "00000000000000000000000000000000" +
    "00000000000000000000000000000001",
  )
}

///|
fn p384_dense_scalar() -> Bytes {
  hex(
    "ffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffc7634d81f4372ddf" +
    "581a0db248b0a77aecec196accc52971",
  )
}

///|
fn k1_sparse_scalar() -> Bytes {
  p256_sparse_scalar()
}

///|
fn k1_dense_scalar() -> Bytes {
  hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f")
}

///|
fn rsa2048_priv_pkcs1_der() -> Bytes {
  hex(
    "308204a30201000282010100a48f36ef8cfe5dd94faba96b3abf276fde0e82f9ad0b9963955c933413bf300a4dda0287" +
    "48590762459ddb2a4c2b9ce04e4f2d8f37ea0a1379cc9076ea17a97bad91178d7983c9e15a7f30db77268d3be00d85b9" +
    "60db3396d24ac0bf229bbb242c72b2b4d4ae15abc51d72b372b0132e75cf92265cb5e97747e617a69a78384d99dd5136" +
    "7575953c16e32cc45c3fbb28fdbd0064228043e39721e3bf5ee496d3fb9ced6fd4d7a0daf98fb016cfe8da87484765f9" +
    "c35115f12e095585aba390cb27eb03900045575854e0100d19f32fac1981f6c286567c6387791e642a7941096c92e89e" +
    "cc5cf3c934a363c5ca63f633940ce37965bcfe8b86d7ef432f799c2702030100010282010029ab461ae495e887c57fcf" +
    "57a2b992afe607c0ac9e5fe88869e2d63782a48ff29c020f4fd8470af29c743b71fb75b3b4acbfa9e6b11ee74c453442" +
    "848a0451db4a790a00bdfb5c1c5f4103cb1ee1b933a729656a2a9776f9c2e840e4654c0fd83a1515216b1565d168096b" +
    "e8faaa9140db7e2320e9aafaa244a783e7a107be21a856466f50e3d697cc685e221164d83918b8cfd6f3653c9e7748cf" +
    "ade136ed267ebab8433f9a981fd6af49c4edc149aa281fead06947fe52381009a9e6d49d63f8eb1ff94f15170929f3eb" +
    "0d66a3ec72b0fb1f14d54792a9a5c48cb6310d60771a26344f00dcabc959bb5acc9583cd74a744aa3c079c1b7ed1c746" +
    "7aaa115ee102818100d05869008488dbe1b9afa5c851af7f44ca1fd11f2c31ab19b014c194b32a553338c29fba82a384" +
    "0b0735e8b30cba04ef54c0cc74752d2075f93907ba6ba0654f29872cf6fbe82808e6db11fcce997331417600d6298085" +
    "94085d00b21ed3608e65c2d04d212494aad6edd1383c63154d758fd3145ee3e9df1724b47da56d1a1702818100ca32ef" +
    "5ff51a550e7b5f6434f4d04a3d22a18aa89cd4d628c2b3dca129805f02360da47b5dce7cf14932f19bb4a5e368a06462" +
    "912aa755f05913b89f4af5053fb3ecf2fdac49f636a7be5aecdd62f9aaa8b0d61976b31214b534f9d15d5648d1207e34" +
    "78080f96fa1f2112058d22332916cd2266e15c2036aed2bdd9a19ea8710281803277a7ffb31affc03edd7857fcc97917" +
    "adaa655a9ab6f14e48a3ce7c79a5e07b86dd4619c4b95d2bdab44948cde5657a9fda0fec89d1c392302b8b5eb1e16988" +
    "f273470610e11c89837a3f72308d6524e249764c6a433298382a6717be75cf66cee990d18e1cb1526cbbb0b9618f52c2" +
    "af9e862fe2086d4757f0d133ba55a2430281810088174c421ba8438361ca4c99d004b952f8921dcf6aef5dcd456ee59a" +
    "9b624990256d7d3d835fcd7c613626a4142c6b292a7b26546a8f022aa8e9bb238bc1ea6c7bdf8994ef77407e7cdc843a" +
    "54af9f371c1f199b3de73cce2f409ebc29c43f72721a3f9a62628bcd815232dd05a6f5243cb288eb11d77ddf103fcb84" +
    "456192210281803ef388d592aa5e24b930ab2d434f20a41742cee683fca57a59e2bf57fd090e45158c10952e37392381" +
    "312f139a39c3ad9c947b52e21a18bce16e6b8c0ecfec7556e277b8d34734ca3e7b9a1d95408cd976eba53406eb95905b" +
    "a101317dc5c5fd5b21783244e1b8a8bdd5a3e2e4339fb43248e8cc61307ccd278280b058ad9be1",
  )
}

///|
fn fixed_cek32() -> Bytes {
  hex("000102030405060708090a0b0c0d0e0f" + "101112131415161718191a1b1c1d1e1f")
}

///|
fn fixed_iv12() -> Bytes {
  hex("0102030405060708090a0b0c")
}

///|
fn fixed_oaep_seed() -> Bytes {
  hex("aabbccddeeff00112233445566778899" + "aabbccddeeff00112233445566778899")
}

///|
fn rsa_private_keys() -> (
  @rsa.RsaPrivateKey,
  @rsa.RsaPrivateKey,
  @rsa.RsaPrivateKey,
) {
  let real = @rsa.RsaPrivateKey::from_pkcs1_der(rsa2048_priv_pkcs1_der()) catch {
    _ => abort("bad RSA fixture")
  }
  let sparse : @rsa.RsaPrivateKey = {
    n: real.n,
    e: real.e,
    d: @bigint.BigInt::from_int(1),
    n_bytes_len: real.n_bytes_len,
  }
  let dense : @rsa.RsaPrivateKey = {
    n: real.n,
    e: real.e,
    d: real.n - @bigint.BigInt::from_int(2),
    n_bytes_len: real.n_bytes_len,
  }
  (real, sparse, dense)
}

///|
fn jwe_rsa_token(real : @rsa.RsaPrivateKey) -> String {
  @jwe.encrypt(
    b"leakage harness plaintext",
    @jwe.JweAlg::Rsa_oaep_256,
    @jwe.JweEnc::A256gcm,
    @jwe.EncryptionKey::EncRsa(pubkey=real.public_key()),
    cek=fixed_cek32(),
    iv=fixed_iv12(),
    oaep_seed=fixed_oaep_seed(),
  ) catch {
    _ => abort("bad JWE fixture")
  }
}

///|
fn crypto_pow_workload(secret : @crypto_bigint.Uint, sink : Sink) -> () -> Unit {
  let base = bigint_base_uint()
  let modulus = p256_order_uint()
  () => sink_bytes(sink, base.pow_mod(secret, modulus).to_be_bytes())
}

///|
fn crypto_inv_workload(input : @crypto_bigint.Uint, sink : Sink) -> () -> Unit {
  let modulus = p256_order_uint()
  () => {
    let inv = input.inv_mod(modulus) catch {
      _ => abort("inverse fixture must be invertible")
    }
    sink_bytes(sink, inv.to_be_bytes())
  }
}

///|
fn rsa_sign_workload(sk : @rsa.RsaPrivateKey, sink : Sink) -> () -> Unit {
  let msg = fixed_msg32()
  () => {
    let sig = sk.sign(msg, @rsa.HashAlg::Sha256) catch {
      _ => abort("RSA sign fixture failed")
    }
    sink_bytes(sink, sig)
  }
}

///|
fn jwe_decrypt_workload(
  token : String,
  sk : @rsa.RsaPrivateKey,
  sink : Sink,
) -> () -> Unit {
  () => {
    let ok = try? @jwe.decrypt(token, @jwe.DecryptionKey::DecRsa(privkey=sk))
    match ok {
      Ok(pt) => sink_bytes(sink, pt)
      Err(_) => sink_bool(sink, false)
    }
  }
}

///|
fn p256_sign_workload(scalar : Bytes, sink : Sink) -> () -> Unit {
  let sk = @p256.PrivateKey::from_bytes(scalar) catch {
    _ => abort("bad P-256 scalar fixture")
  }
  let msg = fixed_msg32()
  () => sink_bytes(sink, sk.sign(msg))
}

///|
fn p384_sign_workload(scalar : Bytes, sink : Sink) -> () -> Unit {
  let sk = @p384.PrivateKey::from_bytes(scalar) catch {
    _ => abort("bad P-384 scalar fixture")
  }
  let msg = fixed_msg32()
  () => sink_bytes(sink, sk.sign(msg))
}

///|
fn k1_sign_workload(scalar : Bytes, sink : Sink) -> () -> Unit {
  let sk = @secp256k1.PrivateKey::from_bytes(scalar) catch {
    _ => abort("bad secp256k1 scalar fixture")
  }
  let msg = fixed_msg32()
  () => sink_bytes(sink, sk.sign(msg))
}

///|
fn build_workloads(sink : Sink) -> Array[Workload] {
  let (real_rsa, sparse_rsa, dense_rsa) = rsa_private_keys()
  let token = jwe_rsa_token(real_rsa)
  [
    {
      name: "crypto_bigint-pow_mod",
      sparse: crypto_pow_workload(sparse_uint(), sink),
      dense: crypto_pow_workload(dense_uint(), sink),
    },
    {
      name: "crypto_bigint-inv_mod",
      sparse: crypto_inv_workload(sparse_uint(), sink),
      dense: crypto_inv_workload(dense_uint(), sink),
    },
    {
      name: "rsa-pkcs1v15-sign",
      sparse: rsa_sign_workload(sparse_rsa, sink),
      dense: rsa_sign_workload(dense_rsa, sink),
    },
    {
      name: "jwe-rsa-oaep-decrypt",
      sparse: jwe_decrypt_workload(token, sparse_rsa, sink),
      dense: jwe_decrypt_workload(token, dense_rsa, sink),
    },
    {
      name: "p256-sign",
      sparse: p256_sign_workload(p256_sparse_scalar(), sink),
      dense: p256_sign_workload(p256_dense_scalar(), sink),
    },
    {
      name: "p384-sign",
      sparse: p384_sign_workload(p384_sparse_scalar(), sink),
      dense: p384_sign_workload(p384_dense_scalar(), sink),
    },
    {
      name: "secp256k1-sign",
      sparse: k1_sign_workload(k1_sparse_scalar(), sink),
      dense: k1_sign_workload(k1_dense_scalar(), sink),
    },
  ]
}

///|
fn measure(work : () -> Unit, inner : Int) -> Double {
  let start = @bench.monotonic_clock_start()
  for _ in 0..<inner {
    work()
  }
  @bench.monotonic_clock_end(start) / inner.to_double()
}

///|
fn mean(xs : Array[Double]) -> Double {
  let mut sum = 0.0
  for x in xs {
    sum += x
  }
  sum / xs.length().to_double()
}

///|
fn variance(xs : Array[Double], avg : Double) -> Double {
  if xs.length() < 2 {
    return 0.0
  }
  let mut sum = 0.0
  for x in xs {
    let d = x - avg
    sum += d * d
  }
  sum / (xs.length() - 1).to_double()
}

///|
fn absd(x : Double) -> Double {
  if x < 0.0 {
    -x
  } else {
    x
  }
}

///|
fn welch_t(a : Array[Double], b : Array[Double]) -> Double {
  let ma = mean(a)
  let mb = mean(b)
  let va = variance(a, ma)
  let vb = variance(b, mb)
  let denom = (va / a.length().to_double() + vb / b.length().to_double()).sqrt()
  if denom == 0.0 {
    0.0
  } else {
    (ma - mb) / denom
  }
}

///|
fn run_compare_one(w : Workload, samples : Int, inner : Int) -> Double {
  for _ in 0..<4 {
    (w.sparse)()
    (w.dense)()
  }
  let sparse_samples : Array[Double] = []
  let dense_samples : Array[Double] = []
  for i in 0..<samples {
    if i % 2 == 0 {
      sparse_samples.push(measure(w.sparse, inner))
      dense_samples.push(measure(w.dense, inner))
    } else {
      dense_samples.push(measure(w.dense, inner))
      sparse_samples.push(measure(w.sparse, inner))
    }
  }
  let t = welch_t(sparse_samples, dense_samples)
  println(
    w.name +
    " sparse_mean_us=" +
    mean(sparse_samples).to_string() +
    " dense_mean_us=" +
    mean(dense_samples).to_string() +
    " abs_t=" +
    absd(t).to_string(),
  )
  absd(t)
}

///|
fn find_workload(workloads : Array[Workload], name : String) -> Workload? {
  for w in workloads {
    if w.name == name {
      return Some(w)
    }
  }
  None
}

///|
fn parse_int_arg(args : Array[String], idx : Int, default : Int) -> Int {
  if args.length() <= idx {
    return default
  }
  @string.parse_int(args[idx][:]) catch {
    _ => default
  }
}

///|
fn parse_min_int_arg(
  args : Array[String],
  idx : Int,
  default : Int,
  min : Int,
) -> Int {
  let n = parse_int_arg(args, idx, default)
  if n < min {
    default
  } else {
    n
  }
}

///|
fn parse_double_arg(
  args : Array[String],
  idx : Int,
  default : Double,
) -> Double {
  if args.length() <= idx {
    return default
  }
  @string.parse_double(args[idx][:]) catch {
    _ => default
  }
}

///|
fn normalize_args(args : Array[String]) -> Array[String] {
  for i in 0..<args.length() {
    if args[i] == "compare" || args[i] == "list" || args[i] == "run" {
      return Array::makei(args.length() - i, fn(j) { args[i + j] })
    }
  }
  if args.length() > 0 && args[0] == "--" {
    return Array::makei(args.length() - 1, fn(i) { args[i + 1] })
  }
  args
}

///|
fn usage() -> String {
  (
    #|usage:
    #|  moon run --target native ./leakage_harness
    #|  moon run --target native ./leakage_harness -- compare [samples] [inner] [max_abs_t]
    #|  moon run --target native ./leakage_harness -- list
    #|  moon run --target native ./leakage_harness -- run <workload> <sparse|dense> [iters]
  )
}

///|
fn main {
  let args = normalize_args(@sys.get_cli_args())
  let sink : Sink = { acc: 0 }
  let workloads = build_workloads(sink)
  let cmd = if args.length() == 0 { "compare" } else { args[0] }
  if cmd == "list" {
    for w in workloads {
      println(w.name)
    }
    return
  }
  if cmd == "run" {
    if args.length() < 3 {
      println(usage())
      @sys.exit(2)
    }
    let name = args[1]
    let class_name = args[2]
    let iters = parse_int_arg(args, 3, 100)
    let w = match find_workload(workloads, name) {
      Some(w) => w
      None => {
        println("unknown workload: " + name)
        @sys.exit(2)
        return
      }
    }
    let f = if class_name == "sparse" {
      w.sparse
    } else if class_name == "dense" {
      w.dense
    } else {
      println("unknown class: " + class_name)
      @sys.exit(2)
      return
    }
    for _ in 0..<iters {
      f()
    }
    println("sink=" + sink.acc.to_string())
    return
  }
  if cmd != "compare" {
    println(usage())
    @sys.exit(2)
  }
  let samples = parse_min_int_arg(args, 1, 8, 2)
  let inner = parse_min_int_arg(args, 2, 1, 1)
  let threshold = parse_double_arg(args, 3, 1000000.0)
  let mut worst = 0.0
  for w in workloads {
    let t = run_compare_one(w, samples, inner)
    if t > worst {
      worst = t
    }
  }
  println("sink=" + sink.acc.to_string())
  if worst > threshold {
    println("leakage smoke threshold exceeded: " + worst.to_string())
    @sys.exit(1)
  }
}
