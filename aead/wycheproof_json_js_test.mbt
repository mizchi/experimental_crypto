// JS-target Project Wycheproof runner. The JSON fixtures are pinned under
// testdata/wycheproof and loaded at runtime so we can exercise complete
// vector files without generating huge MoonBit sources.

///|
extern "js" fn wpj_read_text(rel_path : String) -> String =
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
fn wpj_load_json(rel_path : String) -> Json {
  @json.parse(wpj_read_text(rel_path)[:]) catch {
    e => abort("failed to parse " + rel_path + ": " + repr(e))
  }
}

///|
fn wpj_object(j : Json, ctx : String) -> Map[String, Json] {
  match j {
    Object(m) => m
    _ => abort(ctx + ": expected object")
  }
}

///|
fn wpj_array(j : Json, ctx : String) -> Array[Json] {
  match j {
    Array(a) => a
    _ => abort(ctx + ": expected array")
  }
}

///|
fn wpj_field(m : Map[String, Json], key : String, ctx : String) -> Json {
  match m.get(key) {
    Some(v) => v
    None => abort(ctx + ": missing " + key)
  }
}

///|
fn wpj_string(j : Json, ctx : String) -> String {
  match j {
    String(s) => s
    _ => abort(ctx + ": expected string")
  }
}

///|
fn wpj_int(j : Json, ctx : String) -> Int {
  match j {
    Number(n, ..) => n.to_int()
    _ => abort(ctx + ": expected int")
  }
}

///|
fn wpj_hex_nibble(c : Int) -> Int {
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
fn wpj_hex(s : String) -> Bytes {
  if s.length() % 2 != 0 {
    abort("odd-length hex string")
  }
  Bytes::makei(s.length() / 2, fn(i) {
    let hi = wpj_hex_nibble(s.code_unit_at(i * 2).to_int())
    let lo = wpj_hex_nibble(s.code_unit_at(i * 2 + 1).to_int())
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn wpj_assert_bytes_eq(actual : Bytes, expected : Bytes, ctx : String) -> Unit {
  if actual != expected {
    abort(ctx + ": byte mismatch")
  }
}

///|
fn wpj_aead_alg(
  algorithm : String,
  key_size : Int,
  iv_size : Int,
  tag_size : Int,
) -> @aead.Algorithm? {
  if tag_size != 128 {
    return None
  }
  if algorithm == "AES-GCM" {
    if iv_size != 96 {
      None
    } else if key_size == 128 {
      Some(@aead.Aes128Gcm)
    } else if key_size == 256 {
      Some(@aead.Aes256Gcm)
    } else {
      None
    }
  } else if algorithm == "CHACHA20-POLY1305" {
    if key_size == 256 && iv_size == 96 {
      Some(@aead.ChaCha20Poly1305)
    } else {
      None
    }
  } else if algorithm == "XCHACHA20-POLY1305" {
    if key_size == 256 && iv_size == 192 {
      Some(@aead.XChaCha20Poly1305)
    } else {
      None
    }
  } else {
    None
  }
}

///|
fn wpj_run_aead_file(rel_path : String) -> (Int, Int, Int) raise {
  let root = wpj_object(wpj_load_json(rel_path), rel_path)
  let algorithm = wpj_string(wpj_field(root, "algorithm", rel_path), rel_path)
  let groups = wpj_array(wpj_field(root, "testGroups", rel_path), rel_path)
  let mut valid_checked = 0
  let mut invalid_checked = 0
  let mut skipped = 0
  for group_json in groups {
    let group = wpj_object(group_json, rel_path + " group")
    let key_size = wpj_int(wpj_field(group, "keySize", rel_path), rel_path)
    let iv_size = wpj_int(wpj_field(group, "ivSize", rel_path), rel_path)
    let tag_size = wpj_int(wpj_field(group, "tagSize", rel_path), rel_path)
    let tests = wpj_array(wpj_field(group, "tests", rel_path), rel_path)
    let alg = match wpj_aead_alg(algorithm, key_size, iv_size, tag_size) {
      Some(a) => a
      None => {
        skipped = skipped + tests.length()
        continue
      }
    }
    for test_json in tests {
      let test_case = wpj_object(test_json, rel_path + " test")
      let tc_id = wpj_int(wpj_field(test_case, "tcId", rel_path), rel_path)
      let ctx = rel_path + " tcId=\{tc_id}"
      let key = wpj_hex(wpj_string(wpj_field(test_case, "key", ctx), ctx))
      let nonce = wpj_hex(wpj_string(wpj_field(test_case, "iv", ctx), ctx))
      let aad = wpj_hex(wpj_string(wpj_field(test_case, "aad", ctx), ctx))
      let msg = wpj_hex(wpj_string(wpj_field(test_case, "msg", ctx), ctx))
      let ct = wpj_hex(wpj_string(wpj_field(test_case, "ct", ctx), ctx))
      let tag = wpj_hex(wpj_string(wpj_field(test_case, "tag", ctx), ctx))
      let result = wpj_string(wpj_field(test_case, "result", ctx), ctx)
      if result == "valid" || result == "acceptable" {
        valid_checked = valid_checked + 1
        let (actual_ct, actual_tag) = @aead.seal_detached(
          alg, key, nonce, aad, msg,
        )
        wpj_assert_bytes_eq(actual_ct, ct, ctx + " seal ct")
        wpj_assert_bytes_eq(actual_tag, tag, ctx + " seal tag")
        let opened = @aead.open_detached(alg, key, nonce, aad, ct, tag)
        wpj_assert_bytes_eq(opened, msg, ctx + " open")
      } else if result == "invalid" {
        invalid_checked = invalid_checked + 1
        let accepted = try
          @aead.open_detached(alg, key, nonce, aad, ct, tag)
        catch {
          _ => false
        } noraise {
          _ => true
        }
        if accepted {
          abort(ctx + ": invalid vector was accepted")
        }
      } else {
        abort(ctx + ": unknown result " + result)
      }
    }
  }
  (valid_checked, invalid_checked, skipped)
}

///|
test "wycheproof json aead: AES-GCM full supported subset" {
  let (valid_checked, invalid_checked, skipped) = wpj_run_aead_file(
    "testdata/wycheproof/aes_gcm_test.json",
  )
  @debug.assert_eq(valid_checked > 0, true)
  @debug.assert_eq(invalid_checked > 0, true)
  @debug.assert_eq(skipped > 0, true)
}

///|
test "wycheproof json aead: ChaCha20-Poly1305 full supported subset" {
  let (valid_checked, invalid_checked, skipped) = wpj_run_aead_file(
    "testdata/wycheproof/chacha20_poly1305_test.json",
  )
  @debug.assert_eq(valid_checked > 0, true)
  @debug.assert_eq(invalid_checked > 0, true)
  @debug.assert_eq(skipped > 0, true)
}

///|
test "wycheproof json aead: XChaCha20-Poly1305 full supported subset" {
  let (valid_checked, invalid_checked, skipped) = wpj_run_aead_file(
    "testdata/wycheproof/xchacha20_poly1305_test.json",
  )
  @debug.assert_eq(valid_checked > 0, true)
  @debug.assert_eq(invalid_checked > 0, true)
  @debug.assert_eq(skipped > 0, true)
}
