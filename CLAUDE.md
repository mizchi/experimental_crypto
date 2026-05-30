# CLAUDE.md — moonbit-crypto

このリポジトリは **moon.work 直下に 13 個の crypto / PKI module** をぶら下げた MoonBit
ワークスペース。Claude Code がここで作業するときに踏みやすい罠と回避策を最小限に絞ってまとめる。
重複した情報はあえて書かない (README.md が「何があるか」、ここが「どう書くか」)。

## Workspace 配線

- メンバー間の path dep は **moon.mod と moon.pkg の両方** に書く必要がある:
  - `moon.mod`: `import { "user/dep@0.1.0" }` (version 制約のため必須。registry に
    publish されていなくても workspace 内 member に解決される)
  - `moon.pkg`: `import { "user/dep" }` (パッケージとしての import)
- **test only** の dep は `moon.pkg` に `import { ... } for "test"` を追加する。
  例: `pkix` が `pem` を fixture テストでのみ使う。
- `moon work init` で `moon.work` を生成。新規 member は `moon work use ./<path>` で追加。
- `moon new --user <u> --name <n> <path>` は library only でも `cmd/main/` を生成するので
  ライブラリ用なら `rm -rf <path>/cmd` する。

## MoonBit のクセ (このリポジトリで実害があったもの)

- **予約語**: `derive` / `priv` / `sealed` は関数名・変数名・let 名で使えない
  (関数を `derive_key` 等にリネームしたケースあり)。
- **`Buffer()` がコンストラクタ**: `Buffer::new` は無い。prelude 経由で `Buffer()`。
- **`pub(all)` でないと外部から構築不可**:
  - `pub enum Foo { A | B }` は read-only。`A` / `B` を別 module から
    構築するには `pub(all) enum`。
  - `pub struct Foo { x : Int }` も `{ x: 1 }` record literal を外部に
    許すには `pub(all) struct`。constructor 関数経由なら `pub` のままで OK。
- **error 型**: `pub suberror Foo { Bar(Int) | Baz(String) } derive(Show)` の
  形。`raise Foo` で投げる。
- **`///|` block separator** が各 top-level 宣言の前に必須 (なくても build は通るが
  `moon fmt` が破壊的に再配置する)。
- **target 別 file 切り分け** は `moon.pkg` の `options(targets: { "<file>.mbt": ["js"], ... })`。
  `supported_targets` は `options(supported_targets: ["native","js"])` 内に置く
  (トップレベル `supported_targets = [...]` は deprecated)。
- **native FFI**: `extern "C" fn name(...) -> Ret = "c_name"` を MoonBit 側に、
  `<name>_native.c` で `#include <moonbit.h>` して
  `moonbit_make_bytes(len, init)` で Bytes を返す。`moon.pkg` に
  `"native-stub": ["<name>_native.c"]` を追加。
- **JS FFI**: `extern "js" fn name(...) -> Ret = #|...JS heredoc...`。
  Bytes と Uint8Array が対応。
- **anonymous fn の raise**: `Bench::bench` などが `() -> Unit` (raise なし) を
  要求する場合、`it.bench(() => it.keep(expr catch { _ => abort("unreachable") }))`
  で握りつぶす。`fn () { ... }` は新文法では deprecated、`() => ...` の arrow が現在形。

## moonbitlang/core / x の制約

- **64×64 → 128-bit mul プリミティブが無い** (`umul128` は `random` 内で private)。
  Curve25519 / Poly1305 などの field arithmetic は **5-limb radix-2^51 は組めず**、
  10-limb radix-2^25.5 (Curve25519) / 5-limb radix-2^26 (Poly1305) で書く。
  ed25519-donna の 32-bit 版が手本。これで x25519 は @bigint 比 14×、
  Poly1305 は 3.7× になった (詳細は README の bench 表)。
- **moonbitlang/x/crypto** は SHA-256 / SHA-224 / MD5 / SM3 / HMAC / ChaCha20 を
  提供するが **SHA-1 / SHA-384 / SHA-512 の incremental 型 (CryptoHasher trait
  impl) が無い**。なので HMAC-SHA-1/384/512 がそのままでは組めない。`hkdf` /
  `pbkdf2` の enum には variant を残しつつ `UnsupportedHash` で reject している。
  Ed25519 は SHA-512 を `ed25519/sha512.mbt` に self-impl してある。

## 外部 fixture / test data の取得

- **WebFetch は GitHub raw URL の test fixture でも "private key" を含む PEM を
  拒否する**ことがある (`RustCrypto/formats/pkcs8/tests/examples/ed25519-priv-pkcs8v1.pem`
  で再現)。`curl -s URL > /tmp/x` で取得する。test fixture は通常公開済みなので
  内容を埋め込んでも問題ないが、本物の鍵を貼らないように毎回確認。
- **NIST / RFC の test vector を subagent に渡すときは桁を確認**。NIST SP 800-38D
  AES-GCM の Test Case 3 を 60-byte PT で渡してしまい、実体は 64-byte PT で、
  subagent が 2 時間 AES / GHASH を疑って debug した。RFC / NIST の一次資料を
  そのまま貼り付けるのが安全。

## bench

- `moon bench --release -p mizchi/<mod>` で **package 単位** に走らせるのが確実。
  ワークスペース root から走らせると全 member の bench が動く。
- bench file は `<mod>_bench_test.mbt`。`@bench` を `for "test"` import する。
- bench closure の中で raise する場合は前述の `catch { _ => abort(...) }` 形。

## module の関係 (依存方向)

```
asn1 ────► pkix ────► pkcs8
  ▲              ▲
  └──────────────┴── pem
                          (pem は asn1 と独立、pkcs8 / pkix-test が依存)

hkdf / pbkdf2 ───► moonbitlang/x/crypto      (pbkdf2 は SHA-256 を内製 — 内ループ最適化)
scrypt ───────► pbkdf2 ───► moonbitlang/x/crypto

hash (SHA-256 / SHA-384 / SHA-512 + HMAC-SHA256 + ct_eq)
  ▲
  ├── rsa, p256, p384  (ECDSA / RSA verify が digest を必要とする)
  └── jwt              (HS256 + ES256/384 + RS256/EdDSA で利用)

ed25519 (sha512 self-impl, @bigint Edwards 曲線)
        (incremental + FixedArray 入力を多用するので @hash には統合せず内製を維持)
x25519  (10-limb field, @bigint dep なし)

p256   (BigInt affine, @hash.sha256 利用)
p384   (BigInt affine, @hash.sha384 利用)

pkix_verify (Ed25519 + RSA-SHA256 + ECDSA-{P-256,P-384}-SHA{256,384} の chain dispatch)
jwt        (HS256 / RS256 / EdDSA / ES256 / ES384)

aead   (ChaCha20-Poly1305 + AES-GCM、moonbitlang/x/crypto, aes.mbt, gcm.mbt)
argon2 (BLAKE2b self-impl、deps なし)
crypto_bigint (@bigint ラッパ、定数時間化は future)
getrandom (target 別 backend、aes/ed25519/x25519 の rng source)
```

## 既知の TODO (頭出しだけ)

- `crypto_bigint` を本物の limb 演算に置き換える (今は @bigint ラッパ)
- `ed25519` を 10-limb field arithmetic に移植 (今は @bigint Edwards 曲線、x25519 と
  同じ手順で大幅に速くなるはず)
- ~~`aead/XChaCha20Poly1305` (HChaCha20 sub-key 派生)~~ → 済。`hchacha20`
  (chacha20.mbt) + `xchacha20_poly1305_seal/open` 実装済みで、draft-irtf-cfrg-
  xchacha §A.1 (HChaCha20 KAT) / §A.3 (AEAD) と fuzz round-trip でテスト済み。
- ~~`asn1` の `Encoder::write_element` double-pass 解消~~ → 済。size-tree を
  一度だけ構築して確定長で直接書く single-pass にし、`finish()` の全バッファ
  再コピーを排除 (encode flat ≒ decode の 2.4×→1.4×、nested 1.5×→1.1×)。
  placeholder+patch 系は whitebox test 用に温存。
- `gcm.mbt` の GHASH を carry-less multiplication 経由に (今は bit-by-bit)

## コミット / push

- 機能単位で commit (`feat(<mod>): ...`, `perf(<mod>): ...`, `test(<mod>, ...): ...`,
  `bench(...): ...`, `docs: ...`)
- `git push` は `origin/main` (https://github.com/mizchi/moonbit-crypto)
- 同名の `mizchi/misc` (古い雑多 repo) とは別物。混同しないこと
