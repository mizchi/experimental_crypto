// CMS interop: openssl `cms -sign` produces detached SignedData; MoonBit cms
// parses + verifies it (EC P-256 and RSA signers, valid + tampered cases).
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const mb = await import(
  path.resolve(
    __dirname,
    "../../_build/js/debug/build/tests/cms_interop/cms_interop.js",
  )
);

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cms-interop-"));
const f = (n) => path.join(dir, n);
const ossl = (args) => execFileSync("openssl", args, { stdio: ["ignore", "pipe", "ignore"] });

const MESSAGE = Buffer.from("experimental_crypto CMS interop message\n");
const msgHex = MESSAGE.toString("hex");
const msgFile = f("message.bin");
fs.writeFileSync(msgFile, MESSAGE);

let pass = 0;
function check(name, got, want) {
  if (got !== want) {
    console.error(`INTEROP FAIL: ${name} — got ${got}, want ${want}`);
    process.exit(1);
  }
  console.log(`  OK ${name}`);
  pass += 1;
}

function run(label, newkeyArgs) {
  const key = f(`${label}.key`);
  const cert = f(`${label}.cert`);
  ossl(["req", "-x509", ...newkeyArgs, "-keyout", key, "-out", cert, "-nodes",
    "-days", "2", "-subj", `/CN=cms-${label}`]);
  const sig = f(`${label}.der`);
  ossl(["cms", "-sign", "-binary", "-in", msgFile, "-signer", cert, "-inkey", key,
    "-outform", "DER", "-md", "sha256", "-out", sig]);
  const sigHex = fs.readFileSync(sig).toString("hex");

  check(`${label} valid`, mb.cms_verify(sigHex, msgHex), 1);
  check(`${label} tampered message`, mb.cms_verify(sigHex, msgHex.slice(0, -2) + "00"), 0);
}

run("ecdsa-p256", ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"]);
run("rsa-2048", ["-newkey", "rsa:2048"]);

fs.rmSync(dir, { recursive: true, force: true });
console.log(`cms interop: ${pass} checks OK`);
