// JWE interop, both directions, via Node's built-in crypto (RSA-OAEP-256 +
// AES-GCM, no npm).
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const mb = await import(
  path.resolve(
    __dirname,
    "../../_build/js/debug/build/tests/jwe_interop/jwe_interop.js",
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
const h = (b) => Buffer.from(b).toString("hex");
const b64u = (b) => Buffer.from(b).toString("base64url");
const fromB64u = (s) => Buffer.from(s, "base64url");
const GCM = { 0: "aes-128-gcm", 1: "aes-256-gcm" };
const ENC = { 0: "A128GCM", 1: "A256GCM" };
const KLEN = { 0: 16, 1: 32 };

// Decrypt a compact JWE given the already-recovered CEK.
function nodeDecryptCompact(token, cek) {
  const [hdr, , ivB, ctB, tagB] = token.split(".");
  const d = crypto.createDecipheriv(
    cek.length === 16 ? "aes-128-gcm" : "aes-256-gcm",
    cek, fromB64u(ivB), { authTagLength: 16 });
  d.setAAD(Buffer.from(hdr, "ascii"));
  d.setAuthTag(fromB64u(tagB));
  return Buffer.concat([d.update(fromB64u(ctB)), d.final()]);
}

// Build a compact JWE Node-side (dir or RSA-OAEP-256).
function nodeEncryptCompact(encId, alg, ek, cek, pt) {
  const header = b64u(JSON.stringify({ alg, enc: ENC[encId] }));
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv(GCM[encId], cek, iv, { authTagLength: 16 });
  c.setAAD(Buffer.from(header, "ascii"));
  const ct = Buffer.concat([c.update(pt), c.final()]);
  const tag = c.getAuthTag();
  return `${header}.${b64u(ek)}.${b64u(iv)}.${b64u(ct)}.${b64u(tag)}`;
}

// ── dir mode, both directions ───────────────────────────────────────────────
for (const encId of [0, 1]) {
  const cek = crypto.randomBytes(KLEN[encId]);
  const pt = crypto.randomBytes(48);

  // MoonBit encrypts -> Node decrypts.
  const tok = mb.jwe_encrypt_dir(encId, h(cek), h(crypto.randomBytes(12)), h(pt));
  check(`dir ${ENC[encId]} MoonBit->Node`, nodeDecryptCompact(tok, cek).equals(pt));

  // Node encrypts -> MoonBit decrypts (+ tamper rejected).
  const tok2 = nodeEncryptCompact(encId, "dir", Buffer.alloc(0), cek, pt);
  check(`dir ${ENC[encId]} Node->MoonBit`, mb.jwe_decrypt_dir(h(cek), tok2) === h(pt));
  const parts = tok2.split(".");
  parts[4] = b64u(Buffer.from(fromB64u(parts[4])).map((x, i) => (i === 0 ? x ^ 1 : x)));
  check(`dir ${ENC[encId]} tamper rejected`, mb.jwe_decrypt_dir(h(cek), parts.join(".")) === "ERR");
}

// ── RSA-OAEP-256, both directions ───────────────────────────────────────────
{
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" }); // { n, e } base64url
  const nHex = h(fromB64u(jwk.n));
  const eHex = h(fromB64u(jwk.e));
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "pem" });
  const oaep = { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" };
  const oaepPub = { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" };

  const pt = crypto.randomBytes(64);

  // MoonBit encrypts (RSA-OAEP-256 + A256GCM) -> Node decrypts.
  const cek = crypto.randomBytes(32);
  const tok = mb.jwe_encrypt_rsa(1, nHex, eHex, h(cek), h(crypto.randomBytes(12)), h(crypto.randomBytes(32)), h(pt));
  const ek = fromB64u(tok.split(".")[1]);
  const recoveredCek = crypto.privateDecrypt(oaep, ek);
  check("RSA-OAEP-256 A256GCM MoonBit->Node", nodeDecryptCompact(tok, recoveredCek).equals(pt));

  // Node encrypts -> MoonBit decrypts (+ tamper rejected).
  const cek2 = crypto.randomBytes(32);
  const ek2 = crypto.publicEncrypt(oaepPub, cek2);
  const tok2 = nodeEncryptCompact(1, "RSA-OAEP-256", ek2, cek2, pt);
  check("RSA-OAEP-256 A256GCM Node->MoonBit", mb.jwe_decrypt_rsa(pkcs8, tok2) === h(pt));
  const p = tok2.split(".");
  p[3] = b64u(Buffer.from(fromB64u(p[3])).map((x, i) => (i === 0 ? x ^ 1 : x)));
  check("RSA-OAEP-256 tamper rejected", mb.jwe_decrypt_rsa(pkcs8, p.join(".")) === "ERR");
}

console.log(`jwe interop: ${pass} checks OK`);
