// JS-target Project Wycheproof runner for the pinned x25519_test.json.

///|
extern "js" fn xwp_read_text(rel_path : String) -> String =
  #| (relPath) => {
  #|   const fs = globalThis.process.getBuiltinModule("node:fs")
  #|   const path = globalThis.process.getBuiltinModule("node:path")
  #|   let dir = globalThis.process.cwd()
  #|   for (let i = 0; i < 8; i++) {
  #|     const candidate = path.join(dir, relPath)
  #|     if (fs.existsSync(candidate)) {
  #|       return fs.readFileSync(candidate, "utf8")
  #|     }
  #|     const parent = path.dirname(dir)
  #|     if (parent === dir) {
  #|       break
  #|     }
  #|     dir = parent
  #|   }
  #|   throw new Error("missing fixture " + relPath + " from " + globalThis.process.cwd())
  #| }

///|
fn xwp_load_json(rel_path : String) -> Json {
  @json.parse(xwp_read_text(rel_path)[:]) catch {
    e => abort("failed to parse " + rel_path + ": " + repr(e))
  }
}

///|
fn xwp_object(j : Json, ctx : String) -> Map[String, Json] {
  match j {
    Object(m) => m
    _ => abort(ctx + ": expected object")
  }
}

///|
fn xwp_array(j : Json, ctx : String) -> Array[Json] {
  match j {
    Array(a) => a
    _ => abort(ctx + ": expected array")
  }
}

///|
fn xwp_field(m : Map[String, Json], key : String, ctx : String) -> Json {
  match m.get(key) {
    Some(v) => v
    None => abort(ctx + ": missing " + key)
  }
}

///|
fn xwp_string(j : Json, ctx : String) -> String {
  match j {
    String(s) => s
    _ => abort(ctx + ": expected string")
  }
}

///|
fn xwp_int(j : Json, ctx : String) -> Int {
  match j {
    Number(n, ..) => n.to_int()
    _ => abort(ctx + ": expected int")
  }
}

///|
fn xwp_hex_nibble(c : Int) -> Int {
  if c >= '0'.to_int() && c <= '9'.to_int() {
    c - '0'.to_int()
  } else if c >= 'a'.to_int() && c <= 'f'.to_int() {
    c - 'a'.to_int() + 10
  } else if c >= 'A'.to_int() && c <= 'F'.to_int() {
    c - 'A'.to_int() + 10
  } else {
    abort("non-hex char")
  }
}

///|
fn xwp_hex(s : String) -> Bytes {
  if s.length() % 2 != 0 {
    abort("odd-length hex string")
  }
  Bytes::makei(s.length() / 2, fn(i) {
    let hi = xwp_hex_nibble(s.code_unit_at(i * 2).to_int())
    let lo = xwp_hex_nibble(s.code_unit_at(i * 2 + 1).to_int())
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn xwp_all_zero(b : Bytes) -> Bool {
  let mut acc = 0
  for i in 0..<b.length() {
    acc = acc | b[i].to_int()
  }
  acc == 0
}

///|
fn xwp_assert_bytes_eq(actual : Bytes, expected : Bytes, ctx : String) -> Unit {
  if actual != expected {
    abort(ctx + ": byte mismatch")
  }
}

///|
test "wycheproof json x25519: full computation vectors" {
  let rel_path = "testdata/wycheproof/x25519_test.json"
  let root = xwp_object(xwp_load_json(rel_path), rel_path)
  let groups = xwp_array(xwp_field(root, "testGroups", rel_path), rel_path)
  let mut valid_checked = 0
  let mut acceptable_checked = 0
  for group_json in groups {
    let group = xwp_object(group_json, rel_path + " group")
    let tests = xwp_array(xwp_field(group, "tests", rel_path), rel_path)
    for test_json in tests {
      let test_case = xwp_object(test_json, rel_path + " test")
      let tc_id = xwp_int(xwp_field(test_case, "tcId", rel_path), rel_path)
      let ctx = rel_path + " tcId=\{tc_id}"
      let private_bytes = xwp_hex(
        xwp_string(xwp_field(test_case, "private", ctx), ctx),
      )
      let public_bytes = xwp_hex(
        xwp_string(xwp_field(test_case, "public", ctx), ctx),
      )
      let shared = xwp_hex(xwp_string(xwp_field(test_case, "shared", ctx), ctx))
      let result = xwp_string(xwp_field(test_case, "result", ctx), ctx)
      let sk = @x25519.PrivateKey::from_bytes(private_bytes)
      let pk = @x25519.PublicKey::from_bytes(public_bytes)
      if result == "valid" {
        valid_checked = valid_checked + 1
        let ss = @x25519.diffie_hellman(sk, pk)
        xwp_assert_bytes_eq(ss.to_bytes(), shared, ctx)
      } else if result == "acceptable" {
        acceptable_checked = acceptable_checked + 1
        if xwp_all_zero(shared) {
          try @x25519.diffie_hellman(sk, pk) catch {
            @x25519.AllZeroSharedSecret => ()
            e =>
              abort(
                "expected AllZeroSharedSecret for " + ctx + ", got " + repr(e),
              )
          } noraise {
            _ => abort(ctx + ": zero shared secret was accepted")
          }
        } else {
          let ss = @x25519.diffie_hellman(sk, pk)
          xwp_assert_bytes_eq(ss.to_bytes(), shared, ctx)
        }
      } else {
        abort(ctx + ": unknown result " + result)
      }
    }
  }
  @debug.assert_eq(valid_checked > 0, true)
  @debug.assert_eq(acceptable_checked > 0, true)
}
