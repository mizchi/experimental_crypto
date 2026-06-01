// X.509 chain interop: openssl mints root -> intermediate -> leaf; MoonBit
// pkix_verify validates it (and a battery of negative cases).
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
    "../../_build/js/debug/build/tests/pkix_interop/pkix_interop.js",
  )
);

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkix-interop-"));
const f = (n) => path.join(dir, n);
const ossl = (args) => execFileSync("openssl", args, { stdio: ["ignore", "pipe", "pipe"] });

function genTime(d) {
  const p = (n, l = 2) => String(n).padStart(l, "0");
  return (
    p(d.getUTCFullYear(), 4) + p(d.getUTCMonth() + 1) + p(d.getUTCDate()) +
    p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds()) + "Z"
  );
}

function ecKey(name) {
  ossl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f(name)]);
}
function der(pem) {
  const out = f(pem.replace(/\.pem$/, ".der"));
  ossl(["x509", "-in", f(pem), "-outform", "DER", "-out", out]);
  return new Uint8Array(fs.readFileSync(out));
}

// Root CA (self-signed).
function makeRoot(keyName, pemName, cn) {
  ecKey(keyName);
  ossl([
    "req", "-new", "-x509", "-key", f(keyName), "-out", f(pemName), "-days", "3",
    "-subj", `/CN=${cn}`,
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
  ]);
}
// Cert signed by (caPem, caKey) with the given extension file.
function sign(csrKey, csrName, caPem, caKey, outPem, subj, ext) {
  ecKey(csrKey);
  ossl(["req", "-new", "-key", f(csrKey), "-out", f(csrName), "-subj", subj]);
  const extFile = f(outPem + ".ext");
  fs.writeFileSync(extFile, ext);
  ossl([
    "x509", "-req", "-in", f(csrName), "-CA", f(caPem), "-CAkey", f(caKey),
    "-CAcreateserial", "-out", f(outPem), "-days", "3", "-extfile", extFile,
  ]);
}

makeRoot("root.key", "root.pem", "Interop Root CA");
makeRoot("other.key", "other.pem", "Unrelated Root CA");
sign("int.key", "int.csr", "root.pem", "root.key", "int.pem", "/CN=Interop Intermediate CA",
  "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n");
sign("leaf.key", "leaf.csr", "int.pem", "int.key", "leaf.pem", "/CN=localhost",
  "subjectAltName=DNS:localhost\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n");

const leaf = der("leaf.pem");
const inter = der("int.pem");
const root = der("root.pem");
const other = der("other.pem");

// Pack intermediates as 4-byte-BE length-prefixed DERs (matches the shim).
function pack(arrs) {
  const parts = [];
  for (const a of arrs) {
    const h = Buffer.alloc(4);
    h.writeUInt32BE(a.length, 0);
    parts.push(h, Buffer.from(a));
  }
  return new Uint8Array(Buffer.concat(parts));
}
const withInter = pack([inter]);
const noInter = pack([]);
const now = genTime(new Date());
const future = "20990101000000Z";
const past = "19710101000000Z";

let pass = 0;
function check(name, got, want) {
  if (got !== want) {
    console.error(`INTEROP FAIL: ${name} — got ${got}, want ${want}`);
    process.exit(1);
  }
  console.log(`  OK ${name} (=${got})`);
  pass += 1;
}

// 1 = trusted+name ok, 0 = untrusted, 2 = parse error, 3 = name mismatch.
check("valid chain + hostname", mb.verify_chain(leaf, withInter, root, now, "localhost"), 1);
check("missing intermediate", mb.verify_chain(leaf, noInter, root, now, "localhost"), 0);
check("expired (now in 2099)", mb.verify_chain(leaf, withInter, root, future, "localhost"), 0);
check("not-yet-valid (now in 1971)", mb.verify_chain(leaf, withInter, root, past, "localhost"), 0);
check("wrong hostname", mb.verify_chain(leaf, withInter, root, now, "evil.example.com"), 3);
check("untrusted anchor", mb.verify_chain(leaf, withInter, other, now, "localhost"), 0);

const tampered = new Uint8Array(leaf);
tampered[tampered.length - 1] ^= 0x01; // corrupt the signature tail
const t = mb.verify_chain(tampered, withInter, root, now, "localhost");
check("tampered leaf rejected (not 1)", t !== 1, true);

fs.rmSync(dir, { recursive: true, force: true });
console.log(`pkix interop: ${pass} checks OK`);
