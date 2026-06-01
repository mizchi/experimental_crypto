// Live TLS 1.3 client interop harness.
//
// Drives the MoonBit `tls13` client (compiled to JS, imported below) through a
// full 1-RTT handshake against a real TLS 1.3 server over a TCP socket, then
// sends an HTTP/1.0 GET and prints the decrypted response. Node owns the
// socket and the record framing; every cryptographic step (ClientHello, key
// schedule, AEAD record seal/open, CertificateVerify + Finished) runs in the
// MoonBit code under test.
//
// Usage: node client.mjs <host> <port> [sni]
// Trust model: this is the "leaf key + transcript" proof (client_handshake_1rtt);
// it does NOT validate the certificate chain to a trust anchor.

import net from "node:net";
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const mod = path.resolve(
  __dirname,
  "../../_build/js/debug/build/interop/tls_client/tls_client.js",
);
const mb = await import(mod);

const host = process.argv[2] ?? "127.0.0.1";
const port = Number(process.argv[3] ?? 0);
const sni = process.argv[4] ?? "localhost";
// Cipher suite (TLS u16): 0x1301 AES-128-GCM, 0x1302 AES-256-GCM (SHA-384),
// 0x1303 ChaCha20-Poly1305. Defaults to AES-128-GCM.
const SUITE = Number(process.argv[5] ?? 0x1301);

const hex = (u8) => Buffer.from(u8).toString("hex");

// ── TLS record framing ─────────────────────────────────────────────────────
function record(type, payload, version = 0x0303) {
  const out = Buffer.alloc(5 + payload.length);
  out[0] = type;
  out[1] = version >> 8;
  out[2] = version & 0xff;
  out[3] = payload.length >> 8;
  out[4] = payload.length & 0xff;
  Buffer.from(payload).copy(out, 5);
  return out;
}

// A pull-based reader over the TCP byte stream that hands back whole records.
class RecordReader {
  constructor(sock) {
    this.buf = Buffer.alloc(0);
    this.waiters = [];
    this.closed = false;
    sock.on("data", (d) => {
      this.buf = Buffer.concat([this.buf, d]);
      this._pump();
    });
    sock.on("close", () => {
      this.closed = true;
      this._pump();
    });
    sock.on("error", (e) => {
      this.error = e;
      this._pump();
    });
  }
  _take() {
    if (this.buf.length < 5) return null;
    const len = (this.buf[3] << 8) | this.buf[4];
    if (this.buf.length < 5 + len) return null;
    const rec = this.buf.subarray(0, 5 + len);
    this.buf = this.buf.subarray(5 + len);
    return { type: rec[0], payload: rec.subarray(5), full: Buffer.from(rec) };
  }
  _pump() {
    while (this.waiters.length) {
      const rec = this._take();
      if (rec) {
        this.waiters.shift().resolve(rec);
      } else if (this.closed || this.error) {
        this.waiters.shift().resolve(null);
      } else break;
    }
  }
  next() {
    const rec = this._take();
    if (rec) return Promise.resolve(rec);
    if (this.closed || this.error) return Promise.resolve(null);
    return new Promise((resolve) => this.waiters.push({ resolve }));
  }
}

// Unpack a 4-byte-BE length-prefixed field blob produced by `pack` in MoonBit.
function unpack(u8) {
  const b = Buffer.from(u8);
  const out = [];
  let o = 0;
  while (o + 4 <= b.length) {
    const n = b.readUInt32BE(o);
    o += 4;
    out.push(b.subarray(o, o + n));
    o += n;
  }
  return out;
}

// Split a coalesced handshake-message stream into individual messages
// (1-byte type + 3-byte length + body), stopping once `want` are collected.
function splitHandshake(buf, want) {
  const msgs = [];
  let o = 0;
  while (o + 4 <= buf.length && msgs.length < want) {
    const len = (buf[o + 1] << 16) | (buf[o + 2] << 8) | buf[o + 3];
    const end = o + 4 + len;
    if (end > buf.length) break;
    msgs.push(buf.subarray(o, end));
    o = end;
  }
  return { msgs, rest: buf.subarray(o) };
}

function fail(msg) {
  console.error("INTEROP FAIL:", msg);
  process.exit(1);
}

// Current UTC as ASN.1 GeneralizedTime "YYYYMMDDHHMMSSZ" for chain validity.
function genTime(d = new Date()) {
  const p = (n, l = 2) => String(n).padStart(l, "0");
  return (
    p(d.getUTCFullYear(), 4) +
    p(d.getUTCMonth() + 1) +
    p(d.getUTCDate()) +
    p(d.getUTCHours()) +
    p(d.getUTCMinutes()) +
    p(d.getUTCSeconds()) +
    "Z"
  );
}

function pemBlocks(text) {
  return (
    text.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
    ) ?? []
  );
}

function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return new Uint8Array(Buffer.from(b64, "base64"));
}

// Find, in a system CA bundle, the anchor whose subject DN matches the issuer
// DN of the topmost certificate the server sent.
function findAnchor(bundlePath, issuerDN) {
  const text = fs.readFileSync(bundlePath, "utf8");
  for (const pem of pemBlocks(text)) {
    let x;
    try {
      x = new crypto.X509Certificate(pem);
    } catch {
      continue;
    }
    if (x.subject === issuerDN) return new Uint8Array(x.raw);
  }
  return null;
}

async function main() {
  // 1. X25519 ephemeral keypair (private from Node CSPRNG, public via MoonBit).
  const priv = crypto.randomBytes(32);
  const pub = mb.x25519_public(priv);
  const chRandom = crypto.randomBytes(32);
  const sessionId = crypto.randomBytes(32);

  // 2. ClientHello (built by MoonBit), framed and sent as a plaintext record.
  const ch = Buffer.from(mb.client_hello(SUITE, chRandom, sessionId, pub, sni));

  const sock = net.connect(port, host);
  sock.on("error", (e) => fail("socket: " + e.message));
  await new Promise((res) => sock.once("connect", res));
  const reader = new RecordReader(sock);
  sock.write(record(0x16, ch, 0x0301));

  // 3. Read until ServerHello (type 22). Skip ChangeCipherSpec (type 20).
  let sh = null;
  while (true) {
    const rec = await reader.next();
    if (!rec) fail("connection closed before ServerHello");
    if (rec.type === 0x14) continue; // CCS
    if (rec.type === 0x15) fail("server sent a plaintext alert during hello");
    if (rec.type === 0x16) {
      sh = Buffer.from(rec.payload);
      break;
    }
    fail("unexpected record type before ServerHello: " + rec.type);
  }

  // 4. Derive the ECDHE shared secret and the server handshake key/iv.
  const serverPub = mb.server_key_share(sh);
  const shared = mb.x25519_shared(priv, serverPub);
  const keyiv = Buffer.from(mb.server_hs_keyiv(SUITE, ch, sh, shared));
  const klen = mb.key_len(SUITE);
  const sHsKey = keyiv.subarray(0, klen);
  const sHsIv = keyiv.subarray(klen, klen + 12);

  // 5. Decrypt the server's encrypted handshake flight (type 23 records) and
  //    reassemble EncryptedExtensions, Certificate, CertificateVerify, Finished.
  let acc = Buffer.alloc(0);
  let flightMsgs = [];
  let seq = 0;
  while (flightMsgs.length < 4) {
    const rec = await reader.next();
    if (!rec) fail("connection closed during server flight");
    if (rec.type === 0x14) continue; // CCS between SH and flight
    if (rec.type !== 0x17) fail("unexpected record type in flight: " + rec.type);
    const opened = Buffer.from(
      mb.open_record(SUITE, sHsKey, sHsIv, seq, rec.full),
    );
    seq += 1;
    const ct = opened[0];
    const plain = opened.subarray(1);
    if (ct !== 0x16) fail("non-handshake content during flight: type " + ct);
    acc = Buffer.concat([acc, plain]);
    const { msgs, rest } = splitHandshake(acc, 4 - flightMsgs.length);
    flightMsgs = flightMsgs.concat(msgs);
    acc = Buffer.from(rest);
  }
  const serverFlight = Buffer.concat(flightMsgs);

  // 6. Verify the handshake (CertificateVerify + server Finished) and derive
  //    the client Finished + traffic keys. Trust mode:
  //    - TLS_ANCHOR=<pem>      : validate the chain to that single CA cert.
  //    - TLS_CA_BUNDLE=<pem>   : pick the anchor from a system bundle.
  //    - (neither)             : leaf-key + transcript proof only (no chain).
  let packed;
  try {
    if (process.env.TLS_ANCHOR) {
      const anchorDer = pemToDer(fs.readFileSync(process.env.TLS_ANCHOR, "utf8"));
      packed = Buffer.from(
        mb.run_handshake_verified(
          SUITE, ch, sh, shared, serverFlight, anchorDer, genTime(), sni,
        ),
      );
      console.log("handshake OK; chain verified to anchor " + process.env.TLS_ANCHOR);
    } else if (process.env.TLS_CA_BUNDLE) {
      const chain = unpack(Buffer.from(mb.server_chain(serverFlight)));
      const topmost = new crypto.X509Certificate(Buffer.from(chain[chain.length - 1]));
      const anchorDer = findAnchor(process.env.TLS_CA_BUNDLE, topmost.issuer);
      if (!anchorDer) fail("no trust anchor in bundle for issuer: " + topmost.issuer);
      packed = Buffer.from(
        mb.run_handshake_verified(
          SUITE, ch, sh, shared, serverFlight, anchorDer, genTime(), sni,
        ),
      );
      console.log("handshake OK; chain verified to system-bundle anchor");
    } else {
      packed = Buffer.from(mb.run_handshake(SUITE, ch, sh, shared, serverFlight));
      console.log("handshake OK; server Finished + CertificateVerify verified (leaf-key, no chain)");
    }
  } catch (e) {
    fail("handshake/verification threw: " + e);
  }
  const [
    clientFinished,
    cHsKey,
    cHsIv,
    cApKey,
    cApIv,
    sApKey,
    sApIv,
  ] = unpack(packed);

  // 7. Send CCS (middlebox compat) + the client Finished (handshake epoch, seq 0).
  sock.write(record(0x14, Buffer.from([0x01]), 0x0303));
  const finRec = Buffer.from(
    mb.seal_record(SUITE, cHsKey, cHsIv, 0, 0x16, clientFinished),
  );
  sock.write(finRec);

  // 8. Send an HTTP/1.0 GET under the client application key (app epoch, seq 0).
  const req = Buffer.from(
    `GET / HTTP/1.0\r\nHost: ${sni}\r\n\r\n`,
    "ascii",
  );
  sock.write(Buffer.from(mb.seal_record(SUITE, cApKey, cApIv, 0, 0x17, req)));

  // 9. Read server application records. NewSessionTicket (handshake, type 22)
  //    arrives first under the app key and still consumes a sequence number.
  let appSeq = 0;
  let body = Buffer.alloc(0);
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    const rec = await reader.next();
    if (!rec) break;
    if (rec.type === 0x14) continue;
    if (rec.type !== 0x17) fail("unexpected post-handshake record: " + rec.type);
    let opened;
    try {
      opened = Buffer.from(
        mb.open_record(SUITE, sApKey, sApIv, appSeq, rec.full),
      );
    } catch (e) {
      fail("failed to open application record seq=" + appSeq + ": " + e);
    }
    appSeq += 1;
    const ct = opened[0];
    const plain = opened.subarray(1);
    if (ct === 0x16) continue; // NewSessionTicket — ignore
    if (ct === 0x15) break; // alert (close_notify after response)
    if (ct === 0x17) {
      body = Buffer.concat([body, plain]);
      if (body.includes("\r\n\r\n") && body.length > 0) {
        // Got headers; openssl -www closes after the page, so keep reading
        // until close, but we already have enough to validate.
      }
    }
  }
  sock.destroy();

  const text = body.toString("latin1");
  const firstLine = text.split("\r\n")[0];
  console.log("decrypted application data (" + body.length + " bytes)");
  console.log("status line:", JSON.stringify(firstLine));
  if (!/^HTTP\/1\.[01] \d{3}/.test(firstLine)) {
    fail("response is not a recognisable HTTP status line");
  }
  console.log("INTEROP OK");
  process.exit(0);
}

main().catch((e) => fail("unexpected: " + (e?.stack ?? e)));
