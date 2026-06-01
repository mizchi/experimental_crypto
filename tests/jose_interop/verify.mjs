// Verify the MoonBit-signed JWTs with Node's built-in crypto (no npm). Imports
// the public key from the emitted JWK (or the shared secret for HMAC) and
// checks the JWS signature over `header.payload`.
import crypto from "node:crypto";
import fs from "node:fs";

const text = fs.readFileSync(process.argv[2], "utf8");
const b64u = (s) => Buffer.from(s, "base64url");

function blocks(t) {
  const re = /-----BEGIN JOSE (\w+)-----\n([\s\S]*?)-----END JOSE \1-----/g;
  const out = [];
  let m;
  while ((m = re.exec(t))) {
    const fields = {};
    for (const line of m[2].split("\n")) {
      const i = line.indexOf("=");
      if (i > 0) fields[line.slice(0, i)] = line.slice(i + 1);
    }
    out.push({ alg: m[1], ...fields });
  }
  return out;
}

function verifyOne(b) {
  const parts = b.TOKEN.trim().split(".");
  if (parts.length !== 3) throw new Error("token is not 3 segments");
  const input = Buffer.from(parts[0] + "." + parts[1], "ascii");
  const sig = b64u(parts[2]);

  if (b.alg === "HS256") {
    const mac = crypto.createHmac("sha256", Buffer.from(b.SECRET, "hex"))
      .update(input)
      .digest();
    if (!crypto.timingSafeEqual(mac, sig)) throw new Error("HMAC mismatch");
    return;
  }

  const jwk = JSON.parse(b.JWK.trim());
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });

  let ok;
  if (b.alg === "ES256") {
    // JWS ES256 signature is raw r||s (IEEE P1363), not DER.
    ok = crypto.verify("sha256", input, { key, dsaEncoding: "ieee-p1363" }, sig);
  } else if (b.alg === "EDDSA") {
    ok = crypto.verify(null, input, key, sig);
  } else {
    throw new Error("unknown alg " + b.alg);
  }
  if (!ok) throw new Error("signature verification failed");
}

let n = 0;
for (const b of blocks(text)) {
  try {
    verifyOne(b);
  } catch (e) {
    console.error("INTEROP FAIL:", b.alg, "-", e.message);
    process.exit(1);
  }
  console.log(`  ${b.alg}: Node verified MoonBit-signed JWS OK`);
  n += 1;
}

if (n === 0) {
  console.error("INTEROP FAIL: no JOSE fixtures found");
  process.exit(1);
}
console.log(`jose interop: ${n} algorithms OK`);
