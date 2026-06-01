// Open the MoonBit-sealed AEAD fixtures with Node's built-in crypto and check
// the recovered plaintext + authentication tag.
import crypto from "node:crypto";
import fs from "node:fs";

const ALG = {
  CHACHA20POLY1305: "chacha20-poly1305",
  AES128GCM: "aes-128-gcm",
  AES256GCM: "aes-256-gcm",
};

const text = fs.readFileSync(process.argv[2], "utf8");
const hx = (h) => Buffer.from(h, "hex");

function blocks(t) {
  const re =
    /-----BEGIN AEAD (\w+)-----\n([\s\S]*?)-----END AEAD \1-----/g;
  const out = [];
  let m;
  while ((m = re.exec(t))) {
    const fields = {};
    for (const line of m[2].trim().split("\n")) {
      const i = line.indexOf("=");
      fields[line.slice(0, i)] = line.slice(i + 1).trim();
    }
    out.push({ name: m[1], ...fields });
  }
  return out;
}

let n = 0;
for (const b of blocks(text)) {
  const algo = ALG[b.name];
  if (!algo) {
    console.error("INTEROP FAIL: unknown AEAD", b.name);
    process.exit(1);
  }
  const ct = hx(b.CT);
  const body = ct.subarray(0, ct.length - 16);
  const tag = ct.subarray(ct.length - 16);
  try {
    const d = crypto.createDecipheriv(algo, hx(b.KEY), hx(b.NONCE), {
      authTagLength: 16,
    });
    d.setAAD(hx(b.AAD));
    d.setAuthTag(tag);
    const out = Buffer.concat([d.update(body), d.final()]);
    if (!out.equals(hx(b.PT))) {
      console.error("INTEROP FAIL:", b.name, "plaintext mismatch");
      process.exit(1);
    }
  } catch (e) {
    console.error("INTEROP FAIL:", b.name, "open/auth failed:", e.message);
    process.exit(1);
  }
  console.log(`  ${b.name}: Node opened + authenticated MoonBit ciphertext OK`);
  n += 1;
}

if (n === 0) {
  console.error("INTEROP FAIL: no AEAD fixtures found");
  process.exit(1);
}
console.log(`aead interop: ${n} algorithms OK`);
