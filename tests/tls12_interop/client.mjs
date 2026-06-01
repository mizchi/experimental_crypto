// Live TLS 1.2 client driver. Speaks a full 1-RTT ECDHE handshake to a real
// `openssl s_server -tls1_2` using the MoonBit `tls12` crypto compiled to JS;
// Node only does the socket I/O and record/handshake framing.
//
// Success = the server accepts our (encrypted) Finished — i.e. it replies with
// its own ChangeCipherSpec + encrypted Finished instead of an alert — we
// decrypt that Finished under the derived server keys, and then exchange
// application data (HTTP GET -> the -www server's response). That round trip
// proves ECDHE agreement, key derivation, the client Finished transcript, and
// both record directions.

import net from "node:net";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const mb = await import(
  path.resolve(
    __dirname,
    "../../_build/js/debug/build/tests/tls12_interop/tls12_interop.js",
  )
);

const HOST = process.env.TLS12_HOST || "127.0.0.1";
const PORT = parseInt(process.env.TLS12_PORT || "0", 10);

const u8 = (a) => (a instanceof Uint8Array ? a : Uint8Array.from(a));
const hex = (a) => Buffer.from(u8(a)).toString("hex");
const cat = (...arrs) => {
  const t = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(t);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
};
const empty = (a) => u8(a).length === 0;

// Named group -> ephemeral private length.
const X25519 = 0x001d, SECP256R1 = 0x0017, SECP384R1 = 0x0018;
const ephLen = (g) => (g === SECP384R1 ? 48 : 32);

// ── socket with a pull-based record reader ──────────────────────────────────
function makeConn(sock) {
  let buf = Buffer.alloc(0);
  const waiters = [];
  sock.on("data", (d) => {
    buf = Buffer.concat([buf, d]);
    pump();
  });
  let closed = false;
  sock.on("close", () => { closed = true; pump(); });
  sock.on("error", () => { closed = true; pump(); });

  function tryRecord() {
    if (buf.length < 5) return null;
    const len = (buf[3] << 8) | buf[4];
    if (buf.length < 5 + len) return null;
    const rec = buf.subarray(0, 5 + len);
    buf = buf.subarray(5 + len);
    return Uint8Array.from(rec);
  }
  function pump() {
    while (waiters.length) {
      const rec = tryRecord();
      if (rec) { waiters.shift().resolve(rec); continue; }
      if (closed) { waiters.shift().resolve(null); continue; }
      break;
    }
  }
  return {
    readRecord: () =>
      new Promise((resolve) => { waiters.push({ resolve }); pump(); }),
    write: (rec) => sock.write(Buffer.from(rec)),
    end: () => sock.end(),
  };
}

// Plaintext record: type(1) || 0x0303 || len(2) || payload.
const plainRecord = (type, payload) =>
  cat(Uint8Array.from([type, 0x03, 0x03, (payload.length >> 8) & 0xff, payload.length & 0xff]), payload);

function fail(msg) { console.error("FAIL:", msg); process.exit(1); }

async function main() {
  if (!PORT) fail("TLS12_PORT not set");
  const sock = net.connect(PORT, HOST);
  await new Promise((res, rej) => { sock.once("connect", res); sock.once("error", rej); });
  const conn = makeConn(sock);

  // 1. ClientHello -------------------------------------------------------------
  const clientRandom = crypto.randomBytes(32);
  const ch = mb.client_hello(u8(clientRandom));
  if (empty(ch)) fail("client_hello produced empty output");
  conn.write(plainRecord(22, ch));

  // 2. Read the server flight up to ServerHelloDone. Reassemble handshake
  //    messages from the type-22 record stream.
  let hsBuf = new Uint8Array(0);
  const msgs = []; // {type, framed}
  let sawDone = false;
  const transcriptParts = [ch];
  while (!sawDone) {
    const rec = await conn.readRecord();
    if (!rec) fail("connection closed before ServerHelloDone");
    const type = rec[0];
    const payload = rec.subarray(5);
    if (type === 21) fail("server sent an alert during the handshake: " + hex(payload));
    if (type !== 22) continue; // ignore anything that isn't handshake here
    hsBuf = cat(hsBuf, payload);
    // Pull complete handshake messages (4-byte header + body).
    while (hsBuf.length >= 4) {
      const len = (hsBuf[1] << 16) | (hsBuf[2] << 8) | hsBuf[3];
      if (hsBuf.length < 4 + len) break;
      const framed = hsBuf.subarray(0, 4 + len);
      msgs.push({ type: hsBuf[0], framed: Uint8Array.from(framed) });
      hsBuf = hsBuf.subarray(4 + len);
      if (framed[0] === 14) sawDone = true; // ServerHelloDone
    }
  }

  const get = (t) => msgs.find((m) => m.type === t);
  const shMsg = get(2), certMsg = get(11), skeMsg = get(12), shdMsg = get(14);
  if (!shMsg || !certMsg || !skeMsg || !shdMsg)
    fail("missing one of ServerHello/Certificate/ServerKeyExchange/ServerHelloDone");

  // Add the server messages to the transcript in order.
  for (const m of [shMsg, certMsg, skeMsg, shdMsg]) transcriptParts.push(m.framed);

  // body = framed minus the 4-byte handshake header.
  const body = (m) => m.framed.subarray(4);

  // 3. Parse ServerHello / Certificate / ServerKeyExchange --------------------
  const shFields = mb.parse_server_hello(body(shMsg));
  if (empty(shFields)) fail("parse_server_hello failed");
  const serverRandom = u8(shFields).subarray(0, 32);
  const suite = (u8(shFields)[32] << 8) | u8(shFields)[33];
  const keyLen = suite === 0xc02c || suite === 0xc030 ? 32 : 16;

  const leaf = mb.parse_certificate_leaf(body(certMsg));
  if (empty(leaf)) fail("parse_certificate_leaf failed");

  const skeParsed = mb.parse_ske(body(skeMsg));
  if (empty(skeParsed)) fail("parse_ske failed");
  const group = (u8(skeParsed)[0] << 8) | u8(skeParsed)[1];
  const serverPub = u8(skeParsed).subarray(2);

  // 4. Verify the ServerKeyExchange signature against the leaf cert ----------
  const ok = mb.verify_ske(u8(leaf), body(skeMsg), u8(clientRandom), u8(serverRandom));
  if (ok !== 1) fail("ServerKeyExchange signature did NOT verify");
  console.log(`  ServerKeyExchange signature verified (suite=0x${suite.toString(16)}, group=0x${group.toString(16)})`);

  // 5. ECDHE: derive shared secret + client public key ------------------------
  const ephPriv = crypto.randomBytes(ephLen(group));
  const clientPub = mb.ecdhe_public(group, u8(ephPriv));
  if (empty(clientPub)) fail("ecdhe_public failed");
  const pms = mb.ecdhe_pms(group, u8(ephPriv), u8(serverPub));
  if (empty(pms)) fail("ecdhe_pms failed");

  // 6. Keys -------------------------------------------------------------------
  const ms = mb.master_secret(suite, u8(pms), u8(clientRandom), u8(serverRandom));
  if (empty(ms)) fail("master_secret failed");
  const kb = u8(mb.key_block(suite, u8(ms), u8(clientRandom), u8(serverRandom)));
  if (empty(kb)) fail("key_block failed");
  const clientKey = kb.subarray(0, keyLen);
  const serverKey = kb.subarray(keyLen, 2 * keyLen);
  const clientIv = kb.subarray(2 * keyLen, 2 * keyLen + 4);
  const serverIv = kb.subarray(2 * keyLen + 4, 2 * keyLen + 8);

  // 7. ClientKeyExchange + ChangeCipherSpec + (encrypted) Finished -----------
  const cke = mb.client_key_exchange(u8(clientPub));
  if (empty(cke)) fail("client_key_exchange failed");
  conn.write(plainRecord(22, cke));
  transcriptParts.push(u8(cke));

  conn.write(plainRecord(20, Uint8Array.from([0x01]))); // ChangeCipherSpec

  const transcript = cat(...transcriptParts);
  const finished = mb.finished_verify_data(suite, u8(ms), 1, transcript);
  if (empty(finished)) fail("finished_verify_data failed");
  // The Finished handshake message joins the transcript (for the server's MAC).
  transcriptParts.push(u8(finished));

  const sealedFinished = mb.seal_record(suite, u8(clientKey), u8(clientIv), 0, 22, u8(finished));
  if (empty(sealedFinished)) fail("seal_record(Finished) failed");
  conn.write(u8(sealedFinished));

  // 8. Read the server's flight: optional NewSessionTicket (plaintext),
  //    ChangeCipherSpec, then the encrypted Finished.
  let serverCcs = false;
  let serverFinishedOk = false;
  let serverSeq = 0n;
  while (!serverFinishedOk) {
    const rec = await conn.readRecord();
    if (!rec) fail("connection closed before the server Finished");
    const type = rec[0];
    if (type === 21) fail("server sent an alert after our Finished: " + hex(rec.subarray(5)));
    if (type === 20) { serverCcs = true; continue; } // ChangeCipherSpec
    if (type === 22 && !serverCcs) continue; // plaintext NewSessionTicket — ignore
    if (type === 22 && serverCcs) {
      // Encrypted server Finished, server write seq 0.
      const pt = mb.open_record(suite, u8(serverKey), u8(serverIv), Number(serverSeq), rec);
      if (empty(pt)) fail("could NOT decrypt the server Finished (key/transcript mismatch)");
      serverSeq += 1n;
      serverFinishedOk = true;
      console.log("  server Finished decrypted under derived server keys");
    }
  }

  // 9. Application data: HTTP GET (client seq 1) -> server response ------------
  const req = Buffer.from("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n", "ascii");
  const sealedReq = mb.seal_record(suite, u8(clientKey), u8(clientIv), 1, 23, u8(req));
  if (empty(sealedReq)) fail("seal_record(HTTP GET) failed");
  conn.write(u8(sealedReq));

  let appData = "";
  for (let i = 0; i < 8 && appData.indexOf("HTTP/1") < 0; i++) {
    const rec = await conn.readRecord();
    if (!rec) break;
    const type = rec[0];
    if (type === 21) break; // close_notify alert at the end is fine
    if (type !== 23) continue;
    const pt = mb.open_record(suite, u8(serverKey), u8(serverIv), Number(serverSeq), rec);
    serverSeq += 1n;
    if (empty(pt)) fail("could NOT decrypt server application data");
    appData += Buffer.from(u8(pt)).toString("latin1");
  }
  conn.end();

  if (appData.indexOf("HTTP/1") < 0)
    fail("did not receive a decryptable HTTP response");
  console.log("  decrypted HTTP response:", appData.split("\r\n")[0]);
  console.log("PASS: full TLS 1.2 ECDHE handshake + application data round trip");
}

main().catch((e) => fail(String(e && e.stack || e)));
