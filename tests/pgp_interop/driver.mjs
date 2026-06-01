// OpenPGP interop (reverse): real gpg signs; MoonBit pgp.verify_armor verifies.
// Covers Ed25519, RSA-2048, ECDSA nistp256/nistp384, valid + tampered cases.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const mb = await import(
  path.resolve(
    __dirname,
    "../../_build/js/debug/build/tests/pgp_interop/pgp_interop.js",
  )
);

const home = fs.mkdtempSync(path.join(os.tmpdir(), "pgp-interop-"));
fs.chmodSync(home, 0o700);
const f = (n) => path.join(home, n);
const env = { ...process.env, GNUPGHOME: home };
const gpg = (args, opts = {}) =>
  execFileSync("gpg", ["--batch", "--yes", "--no-permission-warning",
    "--pinentry-mode", "loopback", "--passphrase", "", ...args],
    { env, stdio: ["pipe", "pipe", "ignore"], ...opts });

const MESSAGE = Buffer.from("experimental_crypto OpenPGP interop message\n");
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

function run(label, algo, digest) {
  const uid = `${algo}@interop.invalid`;
  gpg(["--quick-generate-key", uid, algo, "sign", "never"]);
  const pub = gpg(["--armor", "--export", uid]).toString("utf8");
  const sigFile = f(`${algo}.sig`);
  gpg(["--digest-algo", digest, "--local-user", uid, "--detach-sign",
    "--armor", "--output", sigFile, msgFile]);
  const sig = fs.readFileSync(sigFile, "utf8");

  check(`${label} valid`, mb.pgp_verify(pub, msgHex, sig), 1);
  check(`${label} tampered message`,
    mb.pgp_verify(pub, msgHex.slice(0, -2) + "00", sig), 0);
  // Corrupt one base64 char in the middle of the signature body.
  const lines = sig.split("\n");
  const mid = Math.floor(lines.length / 2);
  if (lines[mid] && lines[mid].length > 4) {
    const c = lines[mid][2];
    lines[mid] = lines[mid].slice(0, 2) + (c === "A" ? "B" : "A") + lines[mid].slice(3);
  }
  check(`${label} tampered signature`, mb.pgp_verify(pub, msgHex, lines.join("\n")), 0);
}

run("Ed25519", "ed25519", "SHA256");
run("RSA-2048", "rsa2048", "SHA256");
run("ECDSA-P256", "nistp256", "SHA256");
run("ECDSA-P384", "nistp384", "SHA384");

fs.rmSync(home, { recursive: true, force: true });
console.log(`pgp interop: ${pass} checks OK`);
