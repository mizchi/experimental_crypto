// Reverse-direction interop: Node SIGNS / SEALS, MoonBit VERIFIES / DECRYPTS.
// Asserts MoonBit accepts every valid artifact and rejects every tampered one.
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const mb = await import(
  path.resolve(
    __dirname,
    "../../_build/js/debug/build/tests/verify_shim/verify_shim.js",
  )
);

let pass = 0;
function check(name, cond) {
  if (!cond) {
    console.error("INTEROP FAIL:", name);
    process.exit(1);
  }
  console.log("  OK", name);
  pass += 1;
}

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const PAYLOAD = {
  iss: "node-interop",
  sub: "bob",
  iat: 1700000000,
  exp: 4070908800,
};

// Build and sign a JWS with the given alg, returning {token, jwk, secretHex}.
function makeJws(alg, signFn, jwk = "", secretHex = "") {
  const header = b64u(JSON.stringify({ alg, typ: "JWT" }));
  const payload = b64u(JSON.stringify(PAYLOAD));
  const input = `${header}.${payload}`;
  const sig = b64u(signFn(Buffer.from(input, "ascii")));
  return { token: `${input}.${sig}`, jwk, secretHex };
}

function tamper(token) {
  // Flip the last base64url char of the signature.
  const c = token[token.length - 1];
  const repl = c === "A" ? "B" : "A";
  return token.slice(0, -1) + repl;
}

function jwtCase(name, { token, jwk, secretHex }) {
  check(`${name} valid accepted`, mb.jwt_verify(token, jwk, secretHex) === 1);
  check(
    `${name} tampered rejected`,
    mb.jwt_verify(tamper(token), jwk, secretHex) === 0,
  );
}

// ── JOSE: Node signs, MoonBit verifies ──────────────────────────────────────
{
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  jwtCase(
    "EdDSA",
    makeJws("EdDSA", (m) => crypto.sign(null, m, privateKey),
      JSON.stringify(publicKey.export({ format: "jwk" }))),
  );
}
{
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  jwtCase(
    "ES256",
    makeJws("ES256",
      (m) => crypto.sign("sha256", m, { key: privateKey, dsaEncoding: "ieee-p1363" }),
      JSON.stringify(publicKey.export({ format: "jwk" }))),
  );
}
{
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const jwk = JSON.stringify(publicKey.export({ format: "jwk" }));
  jwtCase("RS256", makeJws("RS256", (m) => crypto.sign("sha256", m, privateKey), jwk));
  jwtCase(
    "PS256",
    makeJws("PS256", (m) =>
      crypto.sign("sha256", m, {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      }), jwk),
  );
}
{
  const secret = crypto.randomBytes(32);
  jwtCase(
    "HS256",
    makeJws("HS256",
      (m) => crypto.createHmac("sha256", secret).update(m).digest(),
      "", secret.toString("hex")),
  );
}

// ── AEAD: Node seals, MoonBit opens ─────────────────────────────────────────
const AEAD = [
  { id: 0, name: "ChaCha20-Poly1305", algo: "chacha20-poly1305", keyLen: 32 },
  { id: 1, name: "AES-128-GCM", algo: "aes-128-gcm", keyLen: 16 },
  { id: 2, name: "AES-256-GCM", algo: "aes-256-gcm", keyLen: 32 },
];
for (const a of AEAD) {
  const key = crypto.randomBytes(a.keyLen);
  const nonce = crypto.randomBytes(12);
  const aad = crypto.randomBytes(13);
  const pt = crypto.randomBytes(80);
  const c = crypto.createCipheriv(a.algo, key, nonce, { authTagLength: 16 });
  c.setAAD(aad);
  const body = Buffer.concat([c.update(pt), c.final()]);
  const tag = c.getAuthTag();
  const ct = Buffer.concat([body, tag]);
  const h = (b) => Buffer.from(b).toString("hex");

  const got = mb.aead_open(a.id, h(key), h(nonce), h(aad), h(ct));
  check(`${a.name} valid decrypts`, got === h(pt));

  const bad = Buffer.from(ct);
  bad[bad.length - 1] ^= 0x01; // flip a tag bit
  check(`${a.name} forged rejected`, mb.aead_open(a.id, h(key), h(nonce), h(aad), h(bad)) === "ERR");
}

console.log(`verify-shim interop: ${pass} checks OK`);
