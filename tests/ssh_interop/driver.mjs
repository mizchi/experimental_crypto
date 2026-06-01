// SSHSIG interop: OpenSSH ssh-keygen -Y sign produces signatures; MoonBit
// ssh.verify_with_allowed_signers verifies them (+ negative cases). A real
// `ssh-keygen -Y verify` sanity-checks each fixture so a setup bug can't be
// mistaken for a MoonBit bug.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const mb = await import(
  path.resolve(
    __dirname,
    "../../_build/js/debug/build/tests/ssh_interop/ssh_interop.js",
  )
);

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-interop-"));
const f = (n) => path.join(dir, n);
const keygen = (args) => execFileSync("ssh-keygen", args, { stdio: ["pipe", "pipe", "pipe"] });

const PRINCIPAL = "alice@interop";
const NAMESPACE = "git";
const MESSAGE = Buffer.from("experimental_crypto SSHSIG interop message\n");
const msgHex = MESSAGE.toString("hex");

let pass = 0;
function check(name, got, want) {
  if (got !== want) {
    console.error(`INTEROP FAIL: ${name} — got ${got}, want ${want}`);
    process.exit(1);
  }
  console.log(`  OK ${name}`);
  pass += 1;
}

function genAndSign(type, extraArgs) {
  const key = f(`${type}_key`);
  keygen(["-t", type, ...extraArgs, "-f", key, "-N", "", "-C", `${type}@interop`, "-q"]);
  const msgFile = f(`${type}.msg`);
  fs.writeFileSync(msgFile, MESSAGE);
  // `-Y sign` writes <msgFile>.sig
  keygen(["-Y", "sign", "-f", key, "-n", NAMESPACE, msgFile]);
  const armor = fs.readFileSync(msgFile + ".sig", "utf8");
  const pub = fs.readFileSync(key + ".pub", "utf8").trim();
  const allowed = f(`${type}.allowed`);
  fs.writeFileSync(allowed, `${PRINCIPAL} ${pub}\n`);

  // Sanity: the real ssh-keygen must accept its own signature.
  execFileSync("ssh-keygen",
    ["-Y", "verify", "-f", allowed, "-I", PRINCIPAL, "-n", NAMESPACE, "-s", msgFile + ".sig"],
    { input: MESSAGE, stdio: ["pipe", "ignore", "ignore"] });

  return { armor, allowedText: fs.readFileSync(allowed, "utf8") };
}

for (const [label, type, extra] of [
  ["Ed25519", "ed25519", []],
  ["ECDSA-P256", "ecdsa", ["-b", "256"]],
  ["RSA-2048", "rsa", ["-b", "2048"]],
]) {
  const { armor, allowedText } = genAndSign(type, extra);
  check(`${label} valid`, mb.ssh_verify(allowedText, PRINCIPAL, armor, msgHex, NAMESPACE), 1);
  check(`${label} tampered message`,
    mb.ssh_verify(allowedText, PRINCIPAL, armor, msgHex.slice(0, -2) + "00", NAMESPACE), 0);
  check(`${label} wrong principal`,
    mb.ssh_verify(allowedText, "mallory@interop", armor, msgHex, NAMESPACE), 0);
  check(`${label} wrong namespace`,
    mb.ssh_verify(allowedText, PRINCIPAL, armor, msgHex, "other"), 0);
}

fs.rmSync(dir, { recursive: true, force: true });
console.log(`ssh interop: ${pass} checks OK`);
