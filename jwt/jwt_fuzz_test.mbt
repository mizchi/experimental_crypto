// Structured fuzz tests for JWT / JWKS trust-boundary handling. Pure random
// compact tokens exercise parser robustness; grammar-aware cases cover the
// security-sensitive `kid` selection rules.

///|
let fuzz_hs_secret : Bytes = b"jwt-fuzz-secret"

///|
fn fuzz_b64u_encode(b : Bytes) -> String {
  let s = @base64.encode(b[:], padding=false)
  let buf = StringBuilder::new()
  for c in s {
    let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
    buf.write_char(c2)
  }
  buf.to_string()
}

///|
fn fuzz_sign_hs256_with_header(
  header : Json,
  payload : Json,
  secret : Bytes,
) -> String {
  let header_b64 = fuzz_b64u_encode(@utf8.encode(header.stringify()[:]))
  let payload_b64 = fuzz_b64u_encode(@utf8.encode(payload.stringify()[:]))
  let signing_input = header_b64 + "." + payload_b64
  let sig = @hash.hmac_sha256(secret, @utf8.encode(signing_input[:]))
  signing_input + "." + fuzz_b64u_encode(sig)
}

///|
fn fuzz_safe_kid(raw : Bytes) -> String {
  let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
  let len = if raw.length() == 0 { 1 } else { raw.length() % 32 + 1 }
  let buf = StringBuilder::new()
  for i = 0; i < len; i = i + 1 {
    let b = if raw.length() == 0 { i } else { raw[i % raw.length()].to_int() }
    let idx = b & 63
    buf.write_char(alphabet.get_char(idx).unwrap())
  }
  buf.to_string()
}

///|
fn fuzz_bad_kid(raw : Bytes) -> String {
  if raw.length() % 4 == 0 {
    ""
  } else if raw.length() % 4 == 1 {
    "bad kid"
  } else if raw.length() % 4 == 2 {
    "bad\nkid"
  } else {
    let buf = StringBuilder::new()
    for _i = 0; _i < 257; _i = _i + 1 {
      buf.write_char('A')
    }
    buf.to_string()
  }
}

///|
fn fuzz_bytes(raw : Bytes, len : Int) -> Bytes {
  Bytes::makei(len, fn(i) {
    if raw.length() == 0 {
      ((i * 29 + 11) & 0xff).to_byte()
    } else {
      ((raw[i % raw.length()].to_int() + i * 29) & 0xff).to_byte()
    }
  })
}

///|
let fuzz_compact_b64u_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

///|
fn fuzz_mutate_b64u_char(c : Char, entropy : Int) -> Char {
  let candidate = fuzz_compact_b64u_alphabet.get_char(entropy & 63).unwrap()
  if candidate == c {
    fuzz_compact_b64u_alphabet.get_char((entropy + 1) & 63).unwrap()
  } else {
    candidate
  }
}

///|
fn fuzz_mutate_compact_token(token : String, entropy : Bytes) -> String {
  let mut b64u_chars = 0
  for c in token {
    if c != '.' {
      b64u_chars = b64u_chars + 1
    }
  }
  if b64u_chars == 0 {
    token
  } else {
    let seed = if entropy.length() == 0 { 0 } else { entropy[0].to_int() }
    let tweak = if entropy.length() < 2 {
      seed + 1
    } else {
      entropy[1].to_int()
    }
    let target = seed % b64u_chars
    let out = StringBuilder::new()
    let mut seen = 0
    let mut done = false
    for c in token {
      if c != '.' && seen == target && !done {
        out.write_char(fuzz_mutate_b64u_char(c, tweak))
        done = true
      } else {
        out.write_char(c)
      }
      if c != '.' {
        seen = seen + 1
      }
    }
    out.to_string()
  }
}

///|
fn fuzz_jwks_two_same_kid(kid : String) -> String {
  "{ \"keys\": [ " +
  "{ \"kty\": \"oct\", \"kid\": \"" +
  kid +
  "\", \"alg\": \"HS256\", \"k\": \"YXR0YWNrZXItc2VjcmV0\" }, " +
  "{ \"kty\": \"oct\", \"kid\": \"" +
  kid +
  "\", \"alg\": \"HS256\", \"k\": \"bGVnaXQtc2VjcmV0\" } " +
  "] }"
}

///|
fn fuzz_hs256_header(kid : String) -> Map[String, Json] {
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("HS256")
  header["typ"] = Json::string("JWT")
  header["kid"] = Json::string(kid)
  header
}

///|
test "fuzz jwt: verify and peek_header never panic on random compact strings" {
  for input in (@quickcheck.samples(200) : Array[String]) {
    let _ = try? @jwt.peek_header(input)
    let _ = try? @jwt.verify(
      input,
      @jwt.VerifyKey::Hs256(secret=fuzz_hs_secret),
      @jwt.VerifyOptions::default(0L),
    )
  }
}

///|
test "fuzz jwt kid: sign accepts only safe generated kids" {
  for raw in (@quickcheck.samples(80) : Array[Bytes]) {
    let safe = fuzz_safe_kid(raw)
    let token = @jwt.sign(
      Json::object(Map([])),
      @jwt.Key::Hs256(secret=fuzz_hs_secret),
      kid=safe,
    )
    let verified = @jwt.verify(
      token,
      @jwt.VerifyKey::Hs256(secret=fuzz_hs_secret),
      @jwt.VerifyOptions::default(0L),
    )
    @debug.assert_eq(verified.kid, Some(safe))

    let bad = fuzz_bad_kid(raw)
    let rejected = try {
      let _ = @jwt.sign(
        Json::object(Map([])),
        @jwt.Key::Hs256(secret=fuzz_hs_secret),
        kid=bad,
      )
      false
    } catch {
      InvalidHeader(_) => true
      _ => false
    }
    assert_true(rejected)
  }
}

///|
test "fuzz jwt kid: signed control-data kids reject at verify boundary" {
  for raw in (@quickcheck.samples(80) : Array[Bytes]) {
    let bad = fuzz_bad_kid(raw)
    let token = fuzz_sign_hs256_with_header(
      Json::object(fuzz_hs256_header(bad)),
      Json::object(Map([])),
      fuzz_hs_secret,
    )
    let rejected = try {
      let _ = @jwt.verify(
        token,
        @jwt.VerifyKey::Hs256(secret=fuzz_hs_secret),
        @jwt.VerifyOptions::default(0L),
      )
      false
    } catch {
      InvalidHeader(_) => true
      _ => false
    }
    assert_true(rejected)
  }
}

///|
test "fuzz jwks kid: duplicate kid never selects a first matching key" {
  for raw in (@quickcheck.samples(80) : Array[Bytes]) {
    let kid = fuzz_safe_kid(raw)
    let set = @jwk.parse_set(fuzz_jwks_two_same_kid(kid))
    let header = fuzz_hs256_header(kid)
    let rejected = try {
      let _ = @jwt.select_verify_key(set, header)
      false
    } catch {
      NoMatchingKey => true
      _ => false
    }
    assert_true(rejected)
  }
}

///|
test "fuzz jwk+jwt+jwe: signed JWT survives JWKS selection inside JWE" {
  for sample in (@quickcheck.samples(50) : Array[(Bytes, Bytes, Bytes)]) {
    let (secret_raw, cek_raw, iv_raw) = sample
    let secret = fuzz_bytes(secret_raw, secret_raw.length() % 48 + 16)
    let cek = fuzz_bytes(cek_raw, 32)
    let iv = fuzz_bytes(iv_raw, 12)
    let kid = "kid-" + secret_raw.length().to_string()
    let claims : Map[String, Json] = Map([])
    claims["sub"] = Json::string("cross-format")
    let token = @jwt.sign(Json::object(claims), @jwt.Key::Hs256(secret~), kid~)
    let jwks = "{ \"keys\": [ { \"kty\": \"oct\", \"kid\": \"" +
      kid +
      "\", \"alg\": \"HS256\", \"k\": \"" +
      fuzz_b64u_encode(secret) +
      "\" } ] }"
    let header = @jwt.peek_header(token)
    let key = @jwt.select_verify_key(@jwk.parse_set(jwks), header)
    let wrapped = @jwe.encrypt(
      @utf8.encode(token[:]),
      @jwe.JweAlg::Dir,
      @jwe.JweEnc::A256gcm,
      @jwe.EncryptionKey::EncDir(cek~),
      iv~,
    )
    let decrypted = @jwe.decrypt(wrapped, @jwe.DecryptionKey::DecDir(cek~))
    let decrypted_token = @utf8.decode(decrypted[:]) catch {
      _ => abort("JWE plaintext should be UTF-8 JWT")
    }
    let verified = @jwt.verify(
      decrypted_token,
      key,
      @jwt.VerifyOptions::default(0L),
    )
    @debug.assert_eq(verified.kid, Some(kid))
  }
}

///|
test "fuzz jwks kid: malformed header kid rejects before key selection" {
  let jwks =
    #|{ "keys": [ { "kty": "oct", "kid": "safe", "alg": "HS256", "k": "c2VjcmV0" } ] }
  let set = @jwk.parse_set(jwks)
  for raw in (@quickcheck.samples(80) : Array[Bytes]) {
    let header = fuzz_hs256_header(fuzz_bad_kid(raw))
    let rejected = try {
      let _ = @jwt.select_verify_key(set, header)
      false
    } catch {
      InvalidHeader(_) => true
      _ => false
    }
    assert_true(rejected)
  }
}

///|
fn fuzz_oidc_subject(raw : Bytes) -> String {
  "user-" + fuzz_safe_kid(raw)
}

///|
fn fuzz_oidc_claims(
  now : Int64,
  sub : String,
  extra : Map[String, Json],
) -> Json {
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://issuer.example/")
  m["sub"] = Json::string(sub)
  m["aud"] = Json::string("client-abc")
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  for k, v in extra {
    m[k] = v
  }
  Json::object(m)
}

///|
fn fuzz_logout_claims(
  now : Int64,
  subject : String,
  include_nonce : Bool,
) -> Json {
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://issuer.example/")
  m["aud"] = Json::string("client-abc")
  m["iat"] = Json::number(now.to_double())
  m["jti"] = Json::string("logout-" + subject)
  m["sub"] = Json::string(subject)
  let events : Map[String, Json] = Map([])
  events["http://schemas.openid.net/event/backchannel-logout"] = Json::object(
    Map([]),
  )
  m["events"] = Json::object(events)
  if include_nonce {
    m["nonce"] = Json::string("login-nonce")
  }
  Json::object(m)
}

///|
fn fuzz_entity_statement_claims(
  now : Int64,
  issuer : String,
  subject : String,
) -> Json {
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string(issuer)
  m["sub"] = Json::string(subject)
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  let jwks : Map[String, Json] = Map([])
  jwks["keys"] = Json::array([])
  m["jwks"] = Json::object(jwks)
  Json::object(m)
}

///|
test "fuzz oidc profiles: high-level verifiers never panic on random compact strings" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-fuzz-secret"
  let oidc_opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://issuer.example/", "client-abc",
  )
  let logout_opts = @jwt.LogoutTokenVerifyOptions::default(
    now, "https://issuer.example/", "client-abc",
  )
  let userinfo_opts : @jwt.UserInfoVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://issuer.example/",
    client_id: "client-abc",
    expected_sub: "user-1",
    allowed_algorithms: None,
  }
  let request_opts : @jwt.RequestObjectVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    expected_client_id: "client-abc",
    expected_aud: "https://issuer.example/",
    require_exp: false,
    max_iat_age_sec: None,
    allowed_algorithms: None,
    typ_allowed: None,
  }
  let jarm_opts : @jwt.JarmVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    expected_issuer: "https://issuer.example/",
    client_id: "client-abc",
    expected_state: Some("state-1"),
    allowed_algorithms: None,
    typ_allowed: None,
  }
  let entity_opts : @jwt.EntityStatementVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    subject: "https://op.example/",
    expected_issuer: None,
    expected_kind: None,
    allowed_algorithms: None,
  }
  let ciba_opts : @jwt.CibaVerifyOptions = {
    oidc: oidc_opts,
    expected_auth_req_id: Some("auth-req-1"),
    refresh_token: Some("refresh-token"),
  }
  let dpop_opts : @jwt.DpopVerifyOptions = {
    now,
    max_iat_age_sec: 60L,
    clock_skew_sec: 0L,
    http_method: "GET",
    http_uri: "https://resource.example/path",
    bound_access_token: None,
    expected_jkt: None,
    expected_nonce: None,
    allowed_algorithms: None,
  }
  let self_issued_opts : @jwt.SelfIssuedVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    expected_aud: None,
    expected_nonce: None,
    allowed_algorithms: None,
  }
  for input in (@quickcheck.samples(120) : Array[String]) {
    let _ = try? @jwt.verify_oidc_id_token(
      input,
      @jwt.VerifyKey::Hs256(secret=fuzz_hs_secret),
      oidc_opts,
    )
    let _ = try? @jwt.verify_logout_token(
      input,
      @jwt.VerifyKey::Hs256(secret=fuzz_hs_secret),
      logout_opts,
    )
    let _ = try? @jwt.verify_userinfo_jws(
      input,
      @jwt.VerifyKey::Hs256(secret=fuzz_hs_secret),
      userinfo_opts,
    )
    let _ = try? @jwt.verify_request_object(
      input,
      @jwt.VerifyKey::Hs256(secret=fuzz_hs_secret),
      request_opts,
    )
    let _ = try? @jwt.verify_jarm(
      input,
      @jwt.VerifyKey::Hs256(secret=fuzz_hs_secret),
      jarm_opts,
    )
    let _ = try? @jwt.verify_entity_statement(
      input,
      @jwt.VerifyKey::Hs256(secret=fuzz_hs_secret),
      entity_opts,
    )
    let _ = try? @jwt.verify_ciba_id_token(
      input,
      @jwt.VerifyKey::Hs256(secret=fuzz_hs_secret),
      ciba_opts,
    )
    let _ = try? @jwt.verify_dpop_proof(input, dpop_opts)
    let _ = try? @jwt.verify_self_issued_id_token(input, self_issued_opts)
    let _ = try? @jwt.verify_oidc_id_token_encrypted(
      input,
      @jwe.DecryptionKey::DecDir(cek=secret),
      @jwt.VerifyKey::Hs256(secret=fuzz_hs_secret),
      oidc_opts,
    )
    let _ = try? @jwt.parse_provider_metadata(input)
  }
}

///|
test "fuzz oidc encrypted id token: mutated outer JWE never authenticates" {
  let now = 1_700_000_000L
  let sign_secret : Bytes = b"encrypted-id-fuzz-secret"
  let opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://issuer.example/", "client-abc",
  )
  for sample in (@quickcheck.samples(60) : Array[(Bytes, Bytes, Bytes, Bytes)]) {
    let (subject_raw, cek_raw, iv_raw, entropy) = sample
    let subject = fuzz_oidc_subject(subject_raw)
    let cek = fuzz_bytes(cek_raw, 32)
    let iv = fuzz_bytes(iv_raw, 12)
    let inner = @jwt.sign(
      fuzz_oidc_claims(now, subject, Map([])),
      @jwt.Key::Hs256(secret=sign_secret),
    )
    let outer_header : Map[String, Json] = Map([])
    outer_header["cty"] = Json::string("JWT")
    let outer = @jwe.encrypt(
      @utf8.encode(inner[:]),
      @jwe.JweAlg::Dir,
      @jwe.JweEnc::A256gcm,
      @jwe.EncryptionKey::EncDir(cek~),
      iv~,
      extra_header=outer_header,
    )
    let mutated = fuzz_mutate_compact_token(outer, entropy)
    try
      @jwt.verify_oidc_id_token_encrypted(
        mutated,
        @jwe.DecryptionKey::DecDir(cek~),
        @jwt.VerifyKey::Hs256(secret=sign_secret),
        opts,
      )
    catch {
      _ => ()
    } noraise {
      _ => abort("mutated encrypted ID token authenticated")
    }
  }
}

///|
test "fuzz oidc: nonce and token hashes bind to generated ID tokens" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-fuzz-secret"
  for raw in (@quickcheck.samples(60) : Array[Bytes]) {
    let subject = fuzz_oidc_subject(raw)
    let nonce = "nonce-" + fuzz_safe_kid(raw)
    let access_token = "access-" + fuzz_safe_kid(raw)
    let code = "code-" + fuzz_safe_kid(raw)
    let extra : Map[String, Json] = Map([])
    extra["nonce"] = Json::string(nonce)
    extra["at_hash"] = Json::string(
      @jwt.compute_x_hash(@jwt.Algorithm::HS256, access_token),
    )
    extra["c_hash"] = Json::string(
      @jwt.compute_x_hash(@jwt.Algorithm::HS256, code),
    )
    let token = @jwt.sign(
      fuzz_oidc_claims(now, subject, extra),
      @jwt.Key::Hs256(secret~),
    )
    let opts : @jwt.OidcIdTokenVerifyOptions = {
      now,
      clock_skew_sec: 0L,
      issuer: "https://issuer.example/",
      client_id: "client-abc",
      expected_nonce: Some(nonce),
      access_token: Some(access_token),
      authorization_code: Some(code),
      max_age_sec: None,
      expected_acr: None,
      allowed_algorithms: None,
    }
    let id = @jwt.verify_oidc_id_token(
      token,
      @jwt.VerifyKey::Hs256(secret~),
      opts,
    )
    @debug.assert_eq(id.sub, subject)
    @debug.assert_eq(id.nonce, Some(nonce))

    let bad_opts : @jwt.OidcIdTokenVerifyOptions = {
      ..opts,
      expected_nonce: Some(nonce + "-wrong"),
    }
    let rejected = try {
      let _ = @jwt.verify_oidc_id_token(
        token,
        @jwt.VerifyKey::Hs256(secret~),
        bad_opts,
      )
      false
    } catch {
      NonceMismatch => true
      _ => false
    }
    assert_true(rejected)
  }
}

///|
test "fuzz oidc logout: subject tokens verify and nonce-bearing tokens reject" {
  let now = 1_700_000_000L
  let secret : Bytes = b"logout-fuzz-secret"
  let opts = @jwt.LogoutTokenVerifyOptions::default(
    now, "https://issuer.example/", "client-abc",
  )
  for raw in (@quickcheck.samples(60) : Array[Bytes]) {
    let subject = fuzz_oidc_subject(raw)
    let ok_token = @jwt.sign(
      fuzz_logout_claims(now, subject, false),
      @jwt.Key::Hs256(secret~),
      typ="logout+jwt",
    )
    let logout = @jwt.verify_logout_token(
      ok_token,
      @jwt.VerifyKey::Hs256(secret~),
      opts,
    )
    @debug.assert_eq(logout.sub, Some(subject))

    let nonce_token = @jwt.sign(
      fuzz_logout_claims(now, subject, true),
      @jwt.Key::Hs256(secret~),
      typ="logout+jwt",
    )
    let rejected = try {
      let _ = @jwt.verify_logout_token(
        nonce_token,
        @jwt.VerifyKey::Hs256(secret~),
        opts,
      )
      false
    } catch {
      LogoutTokenForbiddenNonce => true
      _ => false
    }
    assert_true(rejected)
  }
}

///|
test "fuzz oidc userinfo request and jarm bindings reject substitution" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-binding-fuzz"
  for raw in (@quickcheck.samples(50) : Array[Bytes]) {
    let subject = fuzz_oidc_subject(raw)
    let userinfo = @jwt.sign(
      fuzz_oidc_claims(now, subject, Map([])),
      @jwt.Key::Hs256(secret~),
    )
    let userinfo_opts : @jwt.UserInfoVerifyOptions = {
      now,
      clock_skew_sec: 0L,
      issuer: "https://issuer.example/",
      client_id: "client-abc",
      expected_sub: subject,
      allowed_algorithms: None,
    }
    let u = @jwt.verify_userinfo_jws(
      userinfo,
      @jwt.VerifyKey::Hs256(secret~),
      userinfo_opts,
    )
    @debug.assert_eq(u.sub, subject)
    let bad_userinfo_opts : @jwt.UserInfoVerifyOptions = {
      ..userinfo_opts,
      expected_sub: subject + "-wrong",
    }
    let userinfo_rejected = try {
      let _ = @jwt.verify_userinfo_jws(
        userinfo,
        @jwt.VerifyKey::Hs256(secret~),
        bad_userinfo_opts,
      )
      false
    } catch {
      UserInfoSubMismatch => true
      _ => false
    }
    assert_true(userinfo_rejected)

    let jar_claims : Map[String, Json] = Map([])
    jar_claims["iss"] = Json::string("client-abc")
    jar_claims["aud"] = Json::string("https://issuer.example/")
    jar_claims["exp"] = Json::number((now + 600L).to_double())
    jar_claims["iat"] = Json::number(now.to_double())
    jar_claims["client_id"] = Json::string("client-abc")
    jar_claims["response_type"] = Json::string("code")
    jar_claims["redirect_uri"] = Json::string("https://rp.example/cb")
    let jar = @jwt.sign(
      Json::object(jar_claims),
      @jwt.Key::Hs256(secret~),
      typ="oauth-authz-req+jwt",
    )
    let request_opts = @jwt.RequestObjectVerifyOptions::default(
      now, "client-abc", "https://issuer.example/",
    )
    let req = @jwt.verify_request_object(
      jar,
      @jwt.VerifyKey::Hs256(secret~),
      request_opts,
    )
    @debug.assert_eq(req.client_id, "client-abc")
    let bad_request_opts : @jwt.RequestObjectVerifyOptions = {
      ..request_opts,
      expected_client_id: "attacker-client",
    }
    let jar_rejected = try {
      let _ = @jwt.verify_request_object(
        jar,
        @jwt.VerifyKey::Hs256(secret~),
        bad_request_opts,
      )
      false
    } catch {
      InvalidIssuer => true
      ClientIdMismatch => true
      _ => false
    }
    assert_true(jar_rejected)

    let state = "state-" + fuzz_safe_kid(raw)
    let jarm_claims : Map[String, Json] = Map([])
    jarm_claims["iss"] = Json::string("https://issuer.example/")
    jarm_claims["aud"] = Json::string("client-abc")
    jarm_claims["exp"] = Json::number((now + 600L).to_double())
    jarm_claims["iat"] = Json::number(now.to_double())
    jarm_claims["state"] = Json::string(state)
    jarm_claims["code"] = Json::string("code-" + fuzz_safe_kid(raw))
    let jarm = @jwt.sign(
      Json::object(jarm_claims),
      @jwt.Key::Hs256(secret~),
      typ="oauth-authz-resp+jwt",
    )
    let jarm_opts : @jwt.JarmVerifyOptions = {
      now,
      clock_skew_sec: 0L,
      expected_issuer: "https://issuer.example/",
      client_id: "client-abc",
      expected_state: Some(state),
      allowed_algorithms: None,
      typ_allowed: Some([
        "oauth-authz-resp+jwt", "application/oauth-authz-resp+jwt",
      ]),
    }
    let r = @jwt.verify_jarm(jarm, @jwt.VerifyKey::Hs256(secret~), jarm_opts)
    @debug.assert_eq(r.exp, now + 600L)
    let bad_jarm_opts : @jwt.JarmVerifyOptions = {
      ..jarm_opts,
      expected_state: Some(state + "-wrong"),
    }
    let jarm_rejected = try {
      let _ = @jwt.verify_jarm(
        jarm,
        @jwt.VerifyKey::Hs256(secret~),
        bad_jarm_opts,
      )
      false
    } catch {
      ClaimsParseError(_) => true
      _ => false
    }
    assert_true(jarm_rejected)
  }
}

///|
test "fuzz oidc federation and ciba bindings preserve expected subjects" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-federation-ciba-fuzz"
  for raw in (@quickcheck.samples(50) : Array[Bytes]) {
    let subject = "https://op.example/" + fuzz_safe_kid(raw)
    let issuer = if raw.length() % 2 == 0 {
      subject
    } else {
      "https://anchor.example/"
    }
    let kind = if issuer == subject {
      @jwt.EntityStatementKind::Configuration
    } else {
      @jwt.EntityStatementKind::Subordinate
    }
    let entity = @jwt.sign(
      fuzz_entity_statement_claims(now, issuer, subject),
      @jwt.Key::Hs256(secret~),
      typ="entity-statement+jwt",
    )
    let entity_opts : @jwt.EntityStatementVerifyOptions = {
      now,
      clock_skew_sec: 0L,
      subject,
      expected_issuer: Some(issuer),
      expected_kind: Some(kind),
      allowed_algorithms: None,
    }
    let es = @jwt.verify_entity_statement(
      entity,
      @jwt.VerifyKey::Hs256(secret~),
      entity_opts,
    )
    @debug.assert_eq(es.kind, kind)
    let bad_entity_opts : @jwt.EntityStatementVerifyOptions = {
      ..entity_opts,
      subject: subject + "/attacker",
    }
    let entity_rejected = try {
      let _ = @jwt.verify_entity_statement(
        entity,
        @jwt.VerifyKey::Hs256(secret~),
        bad_entity_opts,
      )
      false
    } catch {
      InvalidEntityStatement(_) => true
      _ => false
    }
    assert_true(entity_rejected)

    let refresh_token = "refresh-" + fuzz_safe_kid(raw)
    let auth_req_id = "auth-" + fuzz_safe_kid(raw)
    let extra : Map[String, Json] = Map([])
    extra["urn:openid:params:jwt:claim:auth_req_id"] = Json::string(auth_req_id)
    extra["urn:openid:params:jwt:claim:rt_hash"] = Json::string(
      @jwt.compute_x_hash(@jwt.Algorithm::HS256, refresh_token),
    )
    let ciba_token = @jwt.sign(
      fuzz_oidc_claims(now, fuzz_oidc_subject(raw), extra),
      @jwt.Key::Hs256(secret~),
    )
    let ciba_opts : @jwt.CibaVerifyOptions = {
      oidc: @jwt.OidcIdTokenVerifyOptions::default(
        now, "https://issuer.example/", "client-abc",
      ),
      expected_auth_req_id: Some(auth_req_id),
      refresh_token: Some(refresh_token),
    }
    let ciba = @jwt.verify_ciba_id_token(
      ciba_token,
      @jwt.VerifyKey::Hs256(secret~),
      ciba_opts,
    )
    @debug.assert_eq(ciba.auth_req_id, Some(auth_req_id))
    let bad_ciba_opts : @jwt.CibaVerifyOptions = {
      ..ciba_opts,
      refresh_token: Some(refresh_token + "-wrong"),
    }
    let ciba_rejected = try {
      let _ = @jwt.verify_ciba_id_token(
        ciba_token,
        @jwt.VerifyKey::Hs256(secret~),
        bad_ciba_opts,
      )
      false
    } catch {
      RtHashMismatch => true
      _ => false
    }
    assert_true(ciba_rejected)
  }
}

///|
test "fuzz oidc discovery: random and generated metadata stay total" {
  for input in (@quickcheck.samples(100) : Array[String]) {
    let _ = try? @jwt.parse_provider_metadata(input)
  }
  for raw in (@quickcheck.samples(60) : Array[Bytes]) {
    let issuer = "https://issuer.example/" + fuzz_safe_kid(raw)
    let doc : Map[String, Json] = Map([])
    doc["issuer"] = Json::string(issuer)
    doc["authorization_endpoint"] = Json::string(issuer + "/authorize")
    doc["token_endpoint"] = Json::string(issuer + "/token")
    doc["jwks_uri"] = Json::string(issuer + "/jwks.json")
    doc["response_types_supported"] = Json::array([
      Json::string("code"),
      Json::string("id_token"),
    ])
    doc["subject_types_supported"] = Json::array([Json::string("public")])
    doc["id_token_signing_alg_values_supported"] = Json::array([
      Json::string("RS256"),
      Json::string("EdDSA"),
    ])
    let parsed = @jwt.parse_provider_metadata(Json::object(doc).stringify())
    @debug.assert_eq(parsed.issuer, issuer)
    @debug.assert_eq(parsed.response_types_supported.length(), 2)
    @debug.assert_eq(parsed.subject_types_supported, ["public"])
  }
}
