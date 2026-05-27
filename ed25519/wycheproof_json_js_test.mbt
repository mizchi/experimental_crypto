// JS-target Project Wycheproof runner for the pinned ed25519_test.json.

///|
extern "js" fn ewp_read_text(rel_path : String) -> String =
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
fn ewp_load_json(rel_path : String) -> Json {
  @json.parse(ewp_read_text(rel_path)[:]) catch {
    e => abort("failed to parse " + rel_path + ": " + repr(e))
  }
}

///|
fn ewp_object(j : Json, ctx : String) -> Map[String, Json] {
  match j {
    Object(m) => m
    _ => abort(ctx + ": expected object")
  }
}

///|
fn ewp_array(j : Json, ctx : String) -> Array[Json] {
  match j {
    Array(a) => a
    _ => abort(ctx + ": expected array")
  }
}

///|
fn ewp_field(m : Map[String, Json], key : String, ctx : String) -> Json {
  match m.get(key) {
    Some(v) => v
    None => abort(ctx + ": missing " + key)
  }
}

///|
fn ewp_string(j : Json, ctx : String) -> String {
  match j {
    String(s) => s
    _ => abort(ctx + ": expected string")
  }
}

///|
fn ewp_int(j : Json, ctx : String) -> Int {
  match j {
    Number(n, ..) => n.to_int()
    _ => abort(ctx + ": expected int")
  }
}

///|
fn ewp_hex_nibble(c : Int) -> Int {
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
fn ewp_hex(s : String) -> Bytes {
  if s.length() % 2 != 0 {
    abort("odd-length hex string")
  }
  Bytes::makei(s.length() / 2, fn(i) {
    let hi = ewp_hex_nibble(s.code_unit_at(i * 2).to_int())
    let lo = ewp_hex_nibble(s.code_unit_at(i * 2 + 1).to_int())
    ((hi << 4) | lo).to_byte()
  })
}

///|
test "wycheproof json ed25519: full verify vectors" {
  let rel_path = "testdata/wycheproof/ed25519_test.json"
  let root = ewp_object(ewp_load_json(rel_path), rel_path)
  let groups = ewp_array(ewp_field(root, "testGroups", rel_path), rel_path)
  let mut valid_checked = 0
  let mut invalid_checked = 0
  for group_json in groups {
    let group = ewp_object(group_json, rel_path + " group")
    let public_key_obj = ewp_object(
      ewp_field(group, "publicKey", rel_path),
      rel_path + " publicKey",
    )
    let pk_bytes = ewp_hex(
      ewp_string(ewp_field(public_key_obj, "pk", rel_path), rel_path),
    )
    let public_key = @ed25519.PublicKey::from_bytes(pk_bytes)
    let tests = ewp_array(ewp_field(group, "tests", rel_path), rel_path)
    for test_json in tests {
      let test_case = ewp_object(test_json, rel_path + " test")
      let tc_id = ewp_int(ewp_field(test_case, "tcId", rel_path), rel_path)
      let ctx = rel_path + " tcId=\{tc_id}"
      let msg = ewp_hex(ewp_string(ewp_field(test_case, "msg", ctx), ctx))
      let sig = ewp_hex(ewp_string(ewp_field(test_case, "sig", ctx), ctx))
      let result = ewp_string(ewp_field(test_case, "result", ctx), ctx)
      let expected = if result == "valid" {
        valid_checked = valid_checked + 1
        true
      } else if result == "invalid" {
        invalid_checked = invalid_checked + 1
        false
      } else {
        abort(ctx + ": unknown result " + result)
      }
      let actual = public_key.verify(msg, sig)
      if actual != expected {
        abort(ctx + ": verify result mismatch")
      }
    }
  }
  @debug.assert_eq(valid_checked > 0, true)
  @debug.assert_eq(invalid_checked > 0, true)
}
