// PKCS#8 interop: openssl generates a PKCS#8 key; MoonBit loads it and signs a
// JWT; Node verifies the JWS with the public key derived from the same PEM.
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const mb = await import(
  path.resolve(
    __dirname,
    "../../_build/js/debug/build/tests/pkcs8_interop/pkcs8_interop.js",
  )
);

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkcs8-interop-"));
const f = (n) => path.join(dir, n);
const ossl = (args) => execFileSync("openssl", args, { stdio: ["ignore", "pipe", "ignore"] });

let pass = 0;
function check(name, cond) {
  if (!cond) {
    console.error("INTEROP FAIL:", name);
    process.exit(1);
  }
  console.log("  OK", name);
  pass += 1;
}

function genPkcs8(label, genpkeyArgs) {
  const out = f(`${label}.pem`);
  ossl(["genpkey", ...genpkeyArgs, "-out", out]);
  return fs.readFileSync(out, "utf8");
}

function verifyJws(alg, token, pubKey) {
  const [hd, pl, sg] = token.split(".");
  const input = Buffer.from(`${hd}.${pl}`, "ascii");
  const sig = Buffer.from(sg, "base64url");
  if (alg === "RS256") return crypto.verify("sha256", input, pubKey, sig);
  if (alg === "ES256") return crypto.verify("sha256", input, { key: pubKey, dsaEncoding: "ieee-p1363" }, sig);
  if (alg === "ES384") return crypto.verify("sha384", input, { key: pubKey, dsaEncoding: "ieee-p1363" }, sig);
  if (alg === "EdDSA") return crypto.verify(null, input, pubKey, sig);
  throw new Error("alg?");
}

for (const [alg, label, args] of [
  ["RS256", "rsa", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]],
  ["ES256", "ecp256", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]],
  ["ES384", "ecp384", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"]],
  ["EdDSA", "ed25519", ["-algorithm", "ED25519"]],
]) {
  const pem = genPkcs8(label, args);
  const pubKey = crypto.createPublicKey(crypto.createPrivateKey(pem));
  const token = mb.pkcs8_sign_jws(alg, pem);
  check(`${alg} loaded-key JWS verifies`, verifyJws(alg, token, pubKey) === true);
  // Tamper the signature → must fail.
  const p = token.split(".");
  const sig = Buffer.from(p[2], "base64url");
  sig[sig.length - 1] ^= 0x01;
  p[2] = sig.toString("base64url");
  check(`${alg} tampered JWS rejected`, verifyJws(alg, p.join("."), pubKey) === false);
}

fs.rmSync(dir, { recursive: true, force: true });
console.log(`pkcs8 interop: ${pass} checks OK`);
