// JS-target Project Wycheproof runner for the pinned
// ecdsa_secp521r1_sha512_p1363_test.json fixture.

///|
extern "js" fn p521_wp_read_text(rel_path : String) -> String =
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
extern "js" fn p521_wp_full_enabled() -> Bool =
  #| () => globalThis.process?.env?.P521_WYCHEPROOF_FULL === "1"

///|
fn p521_wp_load_json(rel_path : String) -> Json {
  @json.parse(p521_wp_read_text(rel_path)[:]) catch {
    e => abort("failed to parse " + rel_path + ": " + repr(e))
  }
}

///|
fn p521_wp_object(j : Json, ctx : String) -> Map[String, Json] {
  match j {
    Object(m) => m
    _ => abort(ctx + ": expected object")
  }
}

///|
fn p521_wp_array(j : Json, ctx : String) -> Array[Json] {
  match j {
    Array(a) => a
    _ => abort(ctx + ": expected array")
  }
}

///|
fn p521_wp_field(m : Map[String, Json], key : String, ctx : String) -> Json {
  match m.get(key) {
    Some(v) => v
    None => abort(ctx + ": missing " + key)
  }
}

///|
fn p521_wp_string(j : Json, ctx : String) -> String {
  match j {
    String(s) => s
    _ => abort(ctx + ": expected string")
  }
}

///|
fn p521_wp_int(j : Json, ctx : String) -> Int {
  match j {
    Number(n, ..) => n.to_int()
    _ => abort(ctx + ": expected int")
  }
}

///|
fn p521_wp_hex_nibble(c : Int) -> Int {
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
fn p521_wp_hex(s : String) -> Bytes {
  if s.length() % 2 != 0 {
    abort("odd-length hex string")
  }
  Bytes::makei(s.length() / 2, fn(i) {
    let hi = p521_wp_hex_nibble(s.code_unit_at(i * 2).to_int())
    let lo = p521_wp_hex_nibble(s.code_unit_at(i * 2 + 1).to_int())
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn p521_wp_selected_tc_id(tc_id : Int) -> Bool {
  let selected = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 25, 27, 29, 31, 39, 41, 51, 59,
    60, 61, 184, 185, 186, 187, 189, 190, 201, 202, 208, 209, 217, 218, 219, 234,
    269, 270,
  ]
  for id in selected {
    if id == tc_id {
      return true
    }
  }
  false
}

///|
test "wycheproof json p-521-sha-512: curated P1363 verify vectors" {
  let rel_path = "testdata/wycheproof/ecdsa_secp521r1_sha512_p1363_test.json"
  let full = p521_wp_full_enabled()
  let root = p521_wp_object(p521_wp_load_json(rel_path), rel_path)
  let groups = p521_wp_array(
    p521_wp_field(root, "testGroups", rel_path),
    rel_path,
  )
  let mut valid_checked = 0
  let mut invalid_checked = 0
  for group_json in groups {
    let group = p521_wp_object(group_json, rel_path + " group")
    let public_key = p521_wp_object(
      p521_wp_field(group, "publicKey", rel_path),
      rel_path + " publicKey",
    )
    let pk_bytes = p521_wp_hex(
      p521_wp_string(
        p521_wp_field(public_key, "uncompressed", rel_path),
        rel_path,
      ),
    )
    let tests = p521_wp_array(p521_wp_field(group, "tests", rel_path), rel_path)
    for test_json in tests {
      let test_case = p521_wp_object(test_json, rel_path + " test")
      let tc_id = p521_wp_int(
        p521_wp_field(test_case, "tcId", rel_path),
        rel_path,
      )
      if !full && !p521_wp_selected_tc_id(tc_id) {
        continue
      }
      let ctx = rel_path + " tcId=\{tc_id}"
      let msg = p521_wp_hex(
        p521_wp_string(p521_wp_field(test_case, "msg", ctx), ctx),
      )
      let sig = p521_wp_hex(
        p521_wp_string(p521_wp_field(test_case, "sig", ctx), ctx),
      )
      let result = p521_wp_string(p521_wp_field(test_case, "result", ctx), ctx)
      let expected = result == "valid"
      let actual = try {
        let pk = @p521.PublicKey::from_uncompressed(pk_bytes)
        @p521.verify(pk, msg, sig, @p521.SignatureFormat::Raw)
      } catch {
        _ => false
      }
      if expected {
        valid_checked = valid_checked + 1
      } else {
        invalid_checked = invalid_checked + 1
      }
      if actual != expected {
        abort(
          ctx +
          " mismatch (expected=" +
          expected.to_string() +
          " actual=" +
          actual.to_string() +
          ")",
        )
      }
    }
  }
  if full {
    @debug.assert_eq(valid_checked, 231)
    @debug.assert_eq(invalid_checked, 87)
  } else {
    @debug.assert_eq(valid_checked, 12)
    @debug.assert_eq(invalid_checked, 28)
  }
}
