/*
 * Secure Channel Assistant — end-to-end encrypted messaging demo with a
 * Double Ratchet (Signal-style) key exchange.
 * Copyright (C) 2026 MINING123STUDIOS
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/* =========================================================
   SECURE CHANNEL — DOUBLE RATCHET
   =========================================================
   - ECDH (P-256) identity keys bootstrap an initial shared secret.
   - A real Diffie-Hellman ratchet (Signal-style) re-keys on every
     reply: whoever sends first after receiving generates a fresh
     ephemeral key pair and mixes a brand new ECDH result into the
     root key. In an ordinary back-and-forth conversation this means
     a fresh ECDH computation on essentially every message.
   - On top of that, a symmetric hash-chain ratchet advances on every
     single message (even several in a row from the same sender), so
     no message key can ever be recomputed from a later one.
   - AES-GCM's own authentication tag is the only integrity check
     (a separate HMAC would be redundant). The message header is
     bound in as associated data, so tampering with the header alone
     (even without touching the ciphertext) is also detected.
   - decrypt() is transactional: it never mutates any session state
     until the AES-GCM tag has actually verified. This matters more
     than it sounds — without it, a single corrupted or tampered
     packet can permanently desynchronize the ratchet and brick the
     whole conversation. (This was caught and fixed during testing.)

   LARGE PAYLOADS (>~100MB), why this needs special handling:
   - Chrome/Edge/Node's JS engine (V8) throws a hard RangeError once a
     single string exceeds ~512M UTF-16 characters. A ~400MB file's
     base64 form is already ~533M characters — over that line. So the
     ciphertext is base64-encoded in fixed-size CHUNKS (each safely
     small) and carried as an array (`dataChunks`), never as one
     giant string.
   - That alone isn't enough: JSON.stringify() on the whole packet
     still has to produce ONE final string, so it hits the same wall
     for big-enough payloads regardless of internal chunking. Above
     STREAMING_EXPORT_THRESHOLD, Export bypasses JSON.stringify
     entirely — it hands the chunk strings directly to `new
     Blob([...parts])`, which concatenates them at the Blob level
     without ever forming one oversized JS string. Import mirrors
     this: for files written in that format, it reads the file in
     fixed windows via File.slice() instead of file.text(), so it
     never materializes the whole file as one string either.
   - Separately, huge text was previously being dumped straight into
     a <pre>/<textarea> — real browsers become sluggish or unresponsive
     rendering many MB of text in one DOM node. Above DISPLAY_THRESHOLD,
     the UI shows a short summary instead, while the real data lives in
     a JS variable for Export/Copy to use.
   ========================================================= */

let kp = null;           // my long-term identity key pair
let myPubRaw = null;     // raw bytes of my identity public key
let session = null;      // RatchetSession once established
let peerPubRawCached = null;

// --- state for large-payload / attachment handling ---
let pendingAttachment = null;   // { file, name, type, size } set by importMsgBox()
let lastEncryptedPacket = null; // the actual packet object behind cipherOut's display
let pendingDecryptPacket = null;// a packet reconstructed from a large imported file
let lastDecrypted = null;       // { bytes: Uint8Array, fileMeta: {name,type}|null } behind plainOut's display

const MAX_SKIP = 1000;
const MAX_SKIPPED_KEYS = 2000;

const CHUNK_BYTES = 64 * 1024 * 1024;              // 64MB raw per base64 chunk (~85MB base64, far under the ~512M char engine limit)
const DISPLAY_THRESHOLD = 1 * 1024 * 1024;         // above this, show a summary in the UI instead of the full content
const STREAMING_EXPORT_THRESHOLD = 200 * 1024 * 1024; // above this, Export bypasses JSON.stringify entirely
// A plain-looking token rather than a self-describing name — on import
// this is only ever compared byte-for-byte, never displayed, so there's
// no reason for it to spell out what the format is.
const LARGE_FORMAT_MAGIC = "N2xkVA1Qy7ZpKf3H";
const IMPORT_WINDOW = 32 * 1024 * 1024;            // read window size when streaming-importing a large file
const SPINNER_THRESHOLD = 512 * 1024;              // above this, show the progress indicator for encrypt/decrypt/read/import

// Yields to the browser between chunks of otherwise-synchronous work
// (base64 encode/decode loops, file windows) so the tab keeps painting
// — the progress indicator's animation and percentage — instead of
// freezing for the whole operation on large files.
function yieldToUI(){
  return new Promise((resolve) => {
    if(typeof requestAnimationFrame === "function") requestAnimationFrame(() => resolve());
    else setTimeout(resolve, 0);
  });
}

/* ---------- outer envelope obfuscation ----------
   This does NOT add security — the real protection is the ECDH/AES-GCM
   double ratchet above/below. All this does is stop the copy/pasted or
   exported text from visually announcing itself as "an encrypted
   messenger packet" (readable {"header":..., "dataChunks":...} JSON,
   or a base64-of-JSON blob starting with the tell-tale "eyJ..." that
   tools and onlookers recognize on sight). A fixed XOR mask breaks that
   visual signature before base64-encoding, so the result reads as a
   nondescript blob of base64 noise instead. Anyone who has this source
   file can reverse it trivially — that's expected and fine, since it's
   cosmetic camouflage, not a secret. */
const ENVELOPE_MASK = new Uint8Array([0x5a, 0x3c, 0x91, 0xe7, 0x2d, 0x88, 0x14, 0x6b, 0xc2, 0x49, 0xf0, 0x77]);

function maskBytes(bytes){
  const out = new Uint8Array(bytes.length);
  for(let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ ENVELOPE_MASK[i % ENVELOPE_MASK.length];
  return out;
}

// packet -> opaque base64 blob (no braces, quotes, or field names visible)
function encodeOpaquePacket(packet){
  const json = JSON.stringify(packet);
  const masked = maskBytes(new TextEncoder().encode(json));
  return b64(masked);
}

// opaque base64 blob -> packet (throws if it isn't one of ours)
function decodeOpaquePacket(str){
  const cleaned = String(str).trim().replace(/\s+/g, "");
  const masked = unb64(cleaned);       // throws on invalid base64 — caller already handles that
  const json = new TextDecoder().decode(maskBytes(masked));
  return JSON.parse(json);             // throws on malformed JSON — caller already handles that
}

/* ---------- byte helpers ---------- */

function b64(bufOrArr){
  const bytes = bufOrArr instanceof Uint8Array ? bufOrArr : new Uint8Array(bufOrArr);
  let binary = '';
  const chunk = 0x8000;
  for(let i = 0; i < bytes.length; i += chunk){
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}
function unb64(str){
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for(let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function bytesEqual(a, b){
  if(!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for(let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
function compareBytes(a, b){
  const len = Math.min(a.length, b.length);
  for(let i = 0; i < len; i++){ if(a[i] !== b[i]) return a[i] - b[i]; }
  return a.length - b.length;
}
function concatBytes(...arrs){
  const total = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for(const a of arrs){ out.set(a, off); off += a.length; }
  return out;
}

// Split raw bytes into base64 CHUNKS, each individually far under the
// engine's max string length, instead of one monolithic base64 string.
// Async so it can yield between chunks — for very large files this
// loop alone can take seconds, and without yielding the tab would
// freeze (and any progress indicator would freeze right along with it).
async function bytesToBase64Chunks(bytes, onProgress){
  const chunks = [];
  const total = bytes.length || 1;
  for(let offset = 0; offset < bytes.length; offset += CHUNK_BYTES){
    chunks.push(b64(bytes.subarray(offset, offset + CHUNK_BYTES)));
    if(onProgress) onProgress(Math.min(offset + CHUNK_BYTES, bytes.length) / total);
    await yieldToUI();
  }
  if(chunks.length === 0) chunks.push("");
  return chunks;
}
async function base64ChunksToBytes(chunks, onProgress){
  const decoded = [];
  const total = chunks.length || 1;
  for(let i = 0; i < chunks.length; i++){
    decoded.push(unb64(chunks[i]));
    if(onProgress) onProgress((i + 1) / total);
    await yieldToUI();
  }
  const totalLen = decoded.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(totalLen);
  let offset = 0;
  for(const c of decoded){ out.set(c, offset); offset += c.length; }
  return out;
}

/* ---------- low-level crypto ---------- */

async function generateIdentityKeyPair(){
  return await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}
async function generateDHKeyPair(){
  return await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}
async function exportPub(pubKey){
  return new Uint8Array(await crypto.subtle.exportKey("spki", pubKey));
}
async function importPub(rawBytes){
  return await crypto.subtle.importKey("spki", rawBytes, { name: "ECDH", namedCurve: "P-256" }, true, []);
}
async function dh(privateKey, publicKey){
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
  return new Uint8Array(bits);
}
async function hmacRaw(keyBytes, byteTag){
  const hk = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", hk, new Uint8Array([byteTag]));
  return new Uint8Array(sig);
}
async function kdfCK(ckBytes){
  const mkSeed = await hmacRaw(ckBytes, 0x01);
  const nextCK = await hmacRaw(ckBytes, 0x02);
  return { mkSeed, nextCK };
}
async function kdfRK(rkBytes, dhOutBytes){
  const ikm = await crypto.subtle.importKey("raw", dhOutBytes, "HKDF", false, ["deriveBits"]);
  const out = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: rkBytes, info: new TextEncoder().encode("dr-root") },
    ikm, 512
  ));
  return { newRK: out.slice(0, 32), newCKseed: out.slice(32, 64) };
}
async function deriveMessageAesKey(mkSeedBytes){
  const ikm = await crypto.subtle.importKey("raw", mkSeedBytes, "HKDF", false, ["deriveKey"]);
  return await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new TextEncoder().encode("dr-msg-key") },
    ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}
async function fingerprintOf(rawBytes){
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", rawBytes));
  const hex = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  return hex.match(/.{1,4}/g).join(' ').toUpperCase();
}
async function computeInitialSharedSecret(myPriv, peerPub){
  const raw = await dh(myPriv, peerPub);
  const ikm = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveBits"]);
  const out = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new TextEncoder().encode("dr-init-salt"), info: new TextEncoder().encode("dr-init-root") },
    ikm, 256
  ));
  return out;
}

/* ---------- Double Ratchet session ---------- */

class RatchetSession {
  constructor(){
    this.DHs = null;
    this.DHr = null;
    this.DHrRaw = null;
    this.RK = null;
    this.CKs = null;
    this.CKr = null;
    this.Ns = 0;
    this.Nr = 0;
    this.PN = 0;
    this.skipped = new Map();
  }

  static async initAsInitiator(sharedSecretBytes, peerStaticPubKey, peerStaticPubRaw){
    const s = new RatchetSession();
    s.DHs = await generateDHKeyPair();
    s.DHr = peerStaticPubKey;
    s.DHrRaw = peerStaticPubRaw;
    const dhOut = await dh(s.DHs.privateKey, s.DHr);
    const { newRK, newCKseed } = await kdfRK(sharedSecretBytes, dhOut);
    s.RK = newRK;
    s.CKs = newCKseed;
    s.CKr = null;
    return s;
  }

  static initAsResponder(sharedSecretBytes, myStaticKeyPair){
    const s = new RatchetSession();
    s.DHs = myStaticKeyPair;
    s.DHr = null;
    s.DHrRaw = null;
    s.RK = sharedSecretBytes;
    s.CKs = null;
    s.CKr = null;
    return s;
  }

  // extraHeaderFields (optional): merged into the header — e.g. file
  // metadata for attachments. It rides along as AEAD associated data,
  // so it's authenticated (tamper-evident) even though not encrypted.
  async encrypt(plaintextBytes, extraHeaderFields, onProgress){
    if(!this.CKs) throw new Error("no sending chain established yet");
    const { mkSeed, nextCK } = await kdfCK(this.CKs);
    this.CKs = nextCK;
    const aesKey = await deriveMessageAesKey(mkSeed);

    const myPubRawLocal = await exportPub(this.DHs.publicKey);
    const header = Object.assign({ dh: b64(myPubRawLocal), pn: this.PN, n: this.Ns }, extraHeaderFields || {});
    this.Ns++;

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = new TextEncoder().encode(JSON.stringify(header));
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, aesKey, plaintextBytes);

    const dataChunks = await bytesToBase64Chunks(new Uint8Array(cipher), onProgress);
    return { v: 3, header, iv: b64(iv), dataChunks };
  }

  // Pure (non-mutating) chain skip-ahead used during a trial decrypt.
  async _skipToPure(ckr, nr, dhKeyB64, until){
    const staged = [];
    if(ckr == null) return { ckr, nr, staged };
    if(until - nr > MAX_SKIP) throw new Error("peer skipped too many messages at once");
    while(nr < until){
      const { mkSeed, nextCK } = await kdfCK(ckr);
      const aesKey = await deriveMessageAesKey(mkSeed);
      if(this.skipped.size + staged.length >= MAX_SKIPPED_KEYS){
        throw new Error("too many unread out-of-order messages pending");
      }
      staged.push({ key: dhKeyB64 + ":" + nr, aesKey });
      ckr = nextCK;
      nr++;
    }
    return { ckr, nr, staged };
  }

  // Accepts either { dataChunks: [...] } (normal path — decoded here)
  // or { cipherBytes: Uint8Array } (already reconstructed by the
  // streaming importer for a very large file) so both paths converge
  // on the same decryption logic below.
  async decrypt(packet, onProgress){
    if(!packet || packet.v !== 3 || !packet.header) throw new Error("unrecognized packet format");
    const header = packet.header;
    if(typeof header.dh !== "string" || typeof header.n !== "number" || typeof header.pn !== "number"){
      throw new Error("malformed header");
    }
    const dhRawIncoming = unb64(header.dh);
    const skipKey = header.dh + ":" + header.n;
    const iv = unb64(packet.iv);
    const data = packet.cipherBytes ? packet.cipherBytes : await base64ChunksToBytes(packet.dataChunks, onProgress);
    const aad = new TextEncoder().encode(JSON.stringify(header));

    // Case 1: key already cached from an earlier out-of-order skip.
    // Only remove it from the cache on success.
    if(this.skipped.has(skipKey)){
      const aesKey = this.skipped.get(skipKey);
      const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, aesKey, data);
      this.skipped.delete(skipKey);
      return new Uint8Array(plainBuf);
    }

    // Case 2: compute everything into a TENTATIVE working copy first.
    // Nothing touches `this` until the AES-GCM tag has verified.
    let tDHs = this.DHs, tDHr = this.DHr, tDHrRaw = this.DHrRaw;
    let tRK = this.RK, tCKr = this.CKr;
    let tNs = this.Ns, tNr = this.Nr, tPN = this.PN;
    const stagedSkips = [];

    const isNewDHKey = !tDHrRaw || !bytesEqual(tDHrRaw, dhRawIncoming);

    if(isNewDHKey){
      // Skip remaining messages in the OLD chain up to the length the
      // SENDER reports for their previous chain (header.pn) — not our
      // own PN bookkeeping, which is unrelated.
      const oldDhLabel = tDHrRaw ? b64(tDHrRaw) : "__none__";
      const skip1 = await this._skipToPure(tCKr, tNr, oldDhLabel, header.pn);
      tCKr = skip1.ckr; tNr = skip1.nr;
      stagedSkips.push(...skip1.staged);

      const newPeerPub = await importPub(dhRawIncoming);
      tPN = tNs;
      tNs = 0;
      tNr = 0;
      tDHr = newPeerPub;
      tDHrRaw = dhRawIncoming;

      const dhOut1 = await dh(tDHs.privateKey, tDHr);
      const step1 = await kdfRK(tRK, dhOut1);
      tRK = step1.newRK;
      tCKr = step1.newCKseed;

      tDHs = await generateDHKeyPair();
      const dhOut2 = await dh(tDHs.privateKey, tDHr);
      const step2 = await kdfRK(tRK, dhOut2);
      tRK = step2.newRK;
      const tCKs = step2.newCKseed;

      const skip2 = await this._skipToPure(tCKr, tNr, b64(tDHrRaw), header.n);
      tCKr = skip2.ckr; tNr = skip2.nr;
      stagedSkips.push(...skip2.staged);

      const { mkSeed, nextCK } = await kdfCK(tCKr);
      const aesKey = await deriveMessageAesKey(mkSeed);

      const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, aesKey, data);

      this.DHs = tDHs; this.DHr = tDHr; this.DHrRaw = tDHrRaw;
      this.RK = tRK; this.CKs = tCKs; this.CKr = nextCK;
      this.Ns = tNs; this.Nr = tNr + 1; this.PN = tPN;
      for(const s of stagedSkips) this.skipped.set(s.key, s.aesKey);
      return new Uint8Array(plainBuf);

    } else {
      const skip = await this._skipToPure(tCKr, tNr, b64(tDHrRaw), header.n);
      tCKr = skip.ckr; tNr = skip.nr;
      stagedSkips.push(...skip.staged);

      const { mkSeed, nextCK } = await kdfCK(tCKr);
      const aesKey = await deriveMessageAesKey(mkSeed);

      const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, aesKey, data);

      this.CKr = nextCK;
      this.Nr = tNr + 1;
      for(const s of stagedSkips) this.skipped.set(s.key, s.aesKey);
      return new Uint8Array(plainBuf);
    }
  }
}

async function establishSession(myKp, myPubRawLocal, peerPubRawLocal){
  const peerPubKey = await importPub(peerPubRawLocal);
  const sharedSecret = await computeInitialSharedSecret(myKp.privateKey, peerPubKey);
  const iAmInitiator = compareBytes(myPubRawLocal, peerPubRawLocal) < 0;
  if(iAmInitiator){
    return await RatchetSession.initAsInitiator(sharedSecret, peerPubKey, peerPubRawLocal);
  } else {
    return RatchetSession.initAsResponder(sharedSecret, myKp);
  }
}

async function sessionFingerprintOf(myPubRawLocal, peerPubRawLocal){
  const ordered = compareBytes(myPubRawLocal, peerPubRawLocal) < 0
    ? concatBytes(myPubRawLocal, peerPubRawLocal)
    : concatBytes(peerPubRawLocal, myPubRawLocal);
  return await fingerprintOf(ordered);
}

/* ---------- large-payload export / import helpers ---------- */

// Builds an array of string PARTS (never concatenated into one JS
// string) describing a packet in a simple, streamable line format.
// Handed directly to `new Blob(parts)`, which does the concatenation
// at the Blob level — that's what avoids the engine's string-length
// ceiling for huge payloads.
function buildLargeExportParts(packet){
  const parts = [];
  parts.push(LARGE_FORMAT_MAGIC + "\n");
  const headerBytes = new TextEncoder().encode(JSON.stringify(packet.header));
  parts.push(b64(maskBytes(headerBytes)) + "\n");
  parts.push(packet.iv + "\n");
  parts.push(String(packet.dataChunks.length) + "\n");
  for(const c of packet.dataChunks){
    parts.push(c);
    parts.push("\n");
  }
  return parts;
}

// Reads a File/Blob in fixed windows via .slice()/.text() — never
// calling .text() on the whole file — and reconstructs {header, iv,
// cipherBytes}. Mirrors buildLargeExportParts()'s format exactly.
async function streamingParseLargeFile(blob, windowSize, onProgress){
  windowSize = windowSize || IMPORT_WINDOW;
  let offset = 0;
  let residual = "";
  let state = "magic"; // magic -> header -> iv -> count -> chunks -> done
  let expectedChunks = 0;
  let chunkBytesList = [];
  let headerObj = null;
  let ivStr = null;

  function extractLines(){
    const lines = [];
    let idx;
    while((idx = residual.indexOf("\n")) !== -1){
      lines.push(residual.slice(0, idx));
      residual = residual.slice(idx + 1);
    }
    return lines;
  }

  while(state !== "done"){
    if(offset >= blob.size) throw new Error("file ended before all expected chunks were read");
    const slice = blob.slice(offset, Math.min(offset + windowSize, blob.size));
    offset += slice.size;
    residual += await slice.text();

    for(const line of extractLines()){
      if(state === "magic"){
        if(line !== LARGE_FORMAT_MAGIC) throw new Error("not a recognized large-file export");
        state = "header";
      } else if(state === "header"){
        const headerBytes = maskBytes(unb64(line));
        headerObj = JSON.parse(new TextDecoder().decode(headerBytes));
        state = "iv";
      } else if(state === "iv"){
        ivStr = line;
        state = "count";
      } else if(state === "count"){
        expectedChunks = parseInt(line, 10);
        if(!(expectedChunks >= 0)) throw new Error("malformed chunk count");
        state = "chunks";
      } else if(state === "chunks"){
        chunkBytesList.push(unb64(line));
        if(chunkBytesList.length === expectedChunks){
          state = "done";
          break;
        }
      }
    }

    if(onProgress) onProgress(Math.min(offset, blob.size) / (blob.size || 1));
    await yieldToUI();
  }

  const total = chunkBytesList.reduce((s, c) => s + c.length, 0);
  const cipherBytes = new Uint8Array(total);
  let off = 0;
  for(const c of chunkBytesList){ cipherBytes.set(c, off); off += c.length; }

  return { v: 3, header: headerObj, iv: ivStr, cipherBytes };
}

/* ---------- UI: theme ---------- */

function applyTheme(theme){
  document.documentElement.setAttribute('data-theme', theme);
  const btn = document.getElementById('themeToggleBtn');
  btn.textContent = theme === 'light' ? '☀️ Light' : '🌙 Dark';
}
function toggleTheme(){
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(current === 'light' ? 'dark' : 'light');
}
(function initTheme(){
  const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  applyTheme(prefersLight ? 'light' : 'dark');
})();

/* ---------- UI: reload confirmation ---------- */

window.addEventListener('beforeunload', (e) => {
  if(!kp) return; // nothing generated yet — nothing to lose, don't nag
  e.preventDefault();
  e.returnValue = ''; // browsers show their own generic wording; the string itself isn't shown
});

/* ---------- UI: progress indicator ----------
   One floating overlay, created lazily on first use, reused for any
   large-payload step (reading a file, encrypting, decrypting, or
   streaming-importing). Progress.show() puts it in a quick
   "indeterminate" spin; once a step can report real progress,
   Progress.update(fraction) switches it to a slower determinate sweep
   with a percentage. Progress.hide() fades it out. */
const Progress = (() => {
  let el = null, ring = null, labelEl = null, pctEl = null, visible = false;

  function ensure(){
    if(el) return;
    el = document.createElement('div');
    el.id = 'progressOverlay';
    el.setAttribute('role', 'status');
    el.setAttribute('aria-live', 'polite');
    const r = document.createElement('div');
    r.className = 'progress-ring';
    r.setAttribute('aria-hidden', 'true');
    const l = document.createElement('span');
    l.className = 'progress-label';
    const p = document.createElement('span');
    p.className = 'progress-pct';
    el.appendChild(r); el.appendChild(l); el.appendChild(p);
    document.body.appendChild(el);
    ring = r; labelEl = l; pctEl = p;
  }

  function show(label){
    ensure();
    ring.classList.remove('determinate');
    ring.style.setProperty('--pct', 25);
    labelEl.textContent = label || 'Working…';
    pctEl.textContent = '';
    el.classList.add('visible');
    visible = true;
  }

  function update(fraction, label){
    if(!visible) ensure();
    if(label !== undefined) labelEl.textContent = label;
    ring.classList.add('determinate');
    const pct = Math.max(0, Math.min(100, Math.round(fraction * 100)));
    ring.style.setProperty('--pct', pct);
    pctEl.textContent = pct + '%';
    if(!visible){ el.classList.add('visible'); visible = true; }
  }

  function hide(){
    if(!el) return;
    el.classList.remove('visible');
    visible = false;
  }

  return { show, update, hide };
})();

/* ---------- UI: status / small helpers ---------- */

function setStatus(text){
  document.getElementById("status").textContent = text;
}

// Centralized warning for anything that shows, copies, or exports the
// private key, so the message is consistent no matter which action
// triggered it.
function confirmPrivateKeyExposure(action){
  return confirm(
    `⚠️ You're about to ${action} your PRIVATE key.\n\n` +
    `Anyone who obtains it can read your messages and impersonate you. ` +
    `Only continue if you're sure of where it's going (or who's looking at your screen).`
  );
}

function downloadBlob(blob, filename){
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function pickFile(accept){
  return new Promise((resolve) => {
    const input = document.createElement('input');
    input.type = 'file';
    if(accept) input.accept = accept;
    input.onchange = () => resolve(input.files[0] || null);
    input.click();
  });
}

function formatBytes(n){
  if(n < 1024) return n + " B";
  if(n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / (1024 * 1024)).toFixed(2) + " MB";
}

function estimateChunksByteLength(chunks){
  // rough (slightly over-) estimate of decoded byte size from base64 chunk lengths, for display purposes only
  return chunks.reduce((s, c) => s + Math.floor(c.length * 0.75), 0);
}

/* ---------- UI: generic copy / export / import for text boxes ---------- */

function copyBox(id){
  if(id === 'cipherOut'){
    if(!lastEncryptedPacket){ alert("⚠️ Nothing here to copy yet"); return; }
    if(estimateChunksByteLength(lastEncryptedPacket.dataChunks) > STREAMING_EXPORT_THRESHOLD){
      alert("⚠️ This message is too large to copy to the clipboard. Use Export below to save it as a file instead.");
      return;
    }
    navigator.clipboard.writeText(encodeOpaquePacket(lastEncryptedPacket));
    return;
  }
  if(id === 'plainOut'){
    if(!lastDecrypted){ alert("⚠️ Nothing decrypted yet"); return; }
    if(lastDecrypted.fileMeta){
      alert("This decrypted content is a file — use Export below to save it, not Copy.");
      return;
    }
    if(lastDecrypted.bytes.length > STREAMING_EXPORT_THRESHOLD){
      alert("⚠️ This message is too large to copy to the clipboard. Use Export below to save it as a file instead.");
      return;
    }
    navigator.clipboard.writeText(new TextDecoder().decode(lastDecrypted.bytes));
    return;
  }
  const el = document.getElementById(id);
  const text = el.value !== undefined ? el.value : el.textContent;
  if(id === 'privKey' && !confirmPrivateKeyExposure("copy")) return;
  navigator.clipboard.writeText(text);
}

function exportTextBox(id, filename, isSensitive){
  if(id === 'cipherOut'){
    if(!lastEncryptedPacket){ alert("⚠️ Nothing here to export yet"); return; }
    if(estimateChunksByteLength(lastEncryptedPacket.dataChunks) > STREAMING_EXPORT_THRESHOLD){
      const parts = buildLargeExportParts(lastEncryptedPacket);
      downloadBlob(new Blob(parts, { type: 'application/octet-stream' }), filename.replace(/\.[^.]+$/, '.scl'));
    } else {
      downloadBlob(new Blob([encodeOpaquePacket(lastEncryptedPacket)], { type: 'application/octet-stream' }), filename);
    }
    return;
  }
  const el = document.getElementById(id);
  const text = el.value !== undefined ? el.value : el.textContent;
  if(!text){ alert("⚠️ Nothing here to export yet"); return; }
  if(isSensitive && !confirmPrivateKeyExposure("export")) return;
  downloadBlob(new Blob([text], { type: 'text/plain' }), filename);
}

async function importIntoTextarea(id){
  const file = await pickFile();
  if(!file) return;

  if(id === 'cipherIn'){
    pendingDecryptPacket = null;
    if(file.size > DISPLAY_THRESHOLD){
      const showSpinner = file.size > SPINNER_THRESHOLD;
      try {
        if(showSpinner) Progress.show('Reading file…');
        const magicPeek = await file.slice(0, LARGE_FORMAT_MAGIC.length + 1).text();
        if(magicPeek.startsWith(LARGE_FORMAT_MAGIC)){
          pendingDecryptPacket = await streamingParseLargeFile(
            file, undefined,
            showSpinner ? (f) => Progress.update(f, 'Reading file…') : null
          );
        } else if(file.size > STREAMING_EXPORT_THRESHOLD){
          document.getElementById('cipherIn').value =
            `⚠️ This file is ${formatBytes(file.size)} and isn't in this tool's streaming format — ` +
            `it may fail to load. If it came from this tool's Export, that's unexpected; otherwise it wasn't meant for direct import this large.`;
          return;
        } else {
          pendingDecryptPacket = decodeOpaquePacket(await file.text());
        }
      } catch(e){
        console.error(e);
        document.getElementById('cipherIn').value = `❌ Couldn't read ${file.name} as an encrypted message (see console).`;
        return;
      } finally {
        if(showSpinner) Progress.hide();
      }
      document.getElementById('cipherIn').value =
        `📎 Imported: ${file.name} (${formatBytes(file.size)}) — click Decrypt to process it, or edit/paste here to replace it.`;
      return;
    }
  }

  document.getElementById(id).value = (await file.text()).trim();
  if(id === 'peerKey') await updatePeerFingerprint();
}

async function importIntoPre(id){
  const file = await pickFile();
  if(!file) return;
  document.getElementById(id).textContent = (await file.text()).trim();
}

/* ---------- Key generation & identity import/export ---------- */

async function updateMyFingerprint(){
  const fp = await fingerprintOf(myPubRaw);
  document.getElementById("myFingerprint").textContent = fp;
}

function resetTransientState(){
  session = null;
  peerPubRawCached = null;
  pendingAttachment = null;
  lastEncryptedPacket = null;
  pendingDecryptPacket = null;
  lastDecrypted = null;
  document.getElementById("cipherOut").textContent = "";
  document.getElementById("plainOut").textContent = "";
  document.getElementById("sessionFingerprintField").style.display = "none";
}

async function generateKeys(){
  kp = await generateIdentityKeyPair();
  myPubRaw = await exportPub(kp.publicKey);
  const privRaw = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));

  resetTransientState();

  document.getElementById("pubKey").value = b64(myPubRaw);
  document.getElementById("privKey").value = b64(privRaw);
  await updateMyFingerprint();

  setStatus("✅ Keys generated. Awaiting peer...");
}

async function exportIdentity(){
  if(!kp){ alert("⚠️ Generate a key pair first"); return; }
  if(!confirmPrivateKeyExposure("export (as part of your identity backup)")) return;
  const privRaw = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const payload = {
    kind: "secure-channel-identity",
    v: 1,
    publicKey: b64(myPubRaw),
    privateKey: b64(privRaw)
  };
  downloadBlob(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }), 'secure-channel-identity.json');
}

async function importIdentity(){
  const file = await pickFile('application/json');
  if(!file) return;
  try {
    const obj = JSON.parse(await file.text());
    if(!obj.publicKey || !obj.privateKey) throw new Error("missing fields");

    const privBytes = unb64(obj.privateKey);
    const pubBytes = unb64(obj.publicKey);
    const privateKey = await crypto.subtle.importKey("pkcs8", privBytes, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const publicKey = await crypto.subtle.importKey("spki", pubBytes, { name: "ECDH", namedCurve: "P-256" }, true, []);

    kp = { privateKey, publicKey };
    myPubRaw = pubBytes;
    resetTransientState();

    document.getElementById("pubKey").value = obj.publicKey;
    document.getElementById("privKey").value = obj.privateKey;
    await updateMyFingerprint();

    setStatus("✅ Identity restored. Awaiting peer...");
  } catch(e){
    console.error(e);
    alert("⚠️ That file doesn't look like a valid identity backup.");
  }
}

// Show/Hide toggle: swaps the field type, the button label, and marks
// the eye icon with a diagonal strike-through while the key is visible.
function togglePriv(){
  const el = document.getElementById("privKey");
  const icon = document.getElementById("eyeIcon");
  const label = document.getElementById("toggleLabel");
  if(el.type === "password"){
    if(!confirmPrivateKeyExposure("reveal")) return;
    el.type = "text";
    icon.classList.add("crossed");
    label.textContent = "Hide";
  } else {
    el.type = "password";
    icon.classList.remove("crossed");
    label.textContent = "Show";
  }
}

/* ---------- Shared secret / session ---------- */

async function updatePeerFingerprint(){
  const raw = document.getElementById("peerKey").value.trim().replace(/\s+/g, "");
  const el = document.getElementById("peerFingerprint");
  if(!raw){ el.textContent = "Paste a peer key to see this"; return; }
  try {
    const bytes = unb64(raw);
    el.textContent = await fingerprintOf(bytes);
  } catch(e){
    el.textContent = "⚠️ Can't read this as a key yet";
  }
}
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('peerKey').addEventListener('input', updatePeerFingerprint);
  document.getElementById('msg').addEventListener('input', () => { pendingAttachment = null; });
  document.getElementById('cipherIn').addEventListener('input', () => { pendingDecryptPacket = null; });
});

async function derive(){
  try {
    if(!kp){
      setStatus("⚠️ Generate your key pair first");
      return;
    }

    const raw = document.getElementById("peerKey").value.trim();
    if(!raw){
      setStatus("⚠️ Paste a peer public key first");
      return;
    }
    const peerText = raw.replace(/\s+/g, "");

    let peerPubRaw;
    try {
      peerPubRaw = unb64(peerText);
      await importPub(peerPubRaw); // validates it's actually a usable EC public key
    } catch(e){
      setStatus("⚠️ That doesn't look like a valid public key — check for missing characters or extra text");
      return;
    }

    if(compareBytes(myPubRaw, peerPubRaw) === 0){
      setStatus("⚠️ That's your own public key, not a peer's — you need a key from the other person");
      return;
    }

    session = await establishSession(kp, myPubRaw, peerPubRaw);
    peerPubRawCached = peerPubRaw;

    const sessFp = await sessionFingerprintOf(myPubRaw, peerPubRaw);
    document.getElementById("sessionFingerprint").textContent = sessFp;
    document.getElementById("sessionFingerprintField").style.display = "";
    await updatePeerFingerprint();

    setStatus("🔐 Secure session established. You can " + (session.CKs ? "send right away." : "reply once your peer sends the first message."));
  } catch(e){
    console.error("DERIVE ERROR:", e);
    setStatus("❌ Couldn't set up the session (see browser console for details). Double-check the pasted key and try again.");
  }
}

function resetSessionUI(){
  if(!session){
    setStatus("Nothing to reset — no session is active.");
    return;
  }
  if(!confirm("This will end the current secure session. You won't be able to decrypt any messages from this conversation afterward (though your keys stay intact). Continue?")){
    return;
  }
  resetTransientState();
  setStatus("🔄 Session reset. Create a new shared secret to keep talking.");
}

/* ---------- Encrypt / Decrypt ---------- */
/* Both now report errors the same way: written into their own "console"
   output box (cipherOut / plainOut) with a ❌ prefix, rather than a
   popup alert() — consistent command-line-style feedback either way. */

async function doEncrypt(){
  const outEl = document.getElementById("cipherOut");
  if(!session){
    outEl.textContent = "⚠️ No shared secret — set up a session first";
    return;
  }

  let plaintextBytes;
  let extraHeader;
  const willBeLarge = pendingAttachment
    ? pendingAttachment.size > SPINNER_THRESHOLD
    : document.getElementById("msg").value.length > SPINNER_THRESHOLD;

  if(willBeLarge) Progress.show('Reading file…');

  if(pendingAttachment){
    try {
      plaintextBytes = new Uint8Array(await pendingAttachment.file.arrayBuffer());
    } catch(e){
      console.error(e);
      outEl.textContent = "❌ Couldn't read the attached file (see console).";
      if(willBeLarge) Progress.hide();
      return;
    }
    extraHeader = { file: { name: pendingAttachment.name, type: pendingAttachment.type } };
  } else {
    const msgText = document.getElementById("msg").value;
    if(!msgText){
      if(willBeLarge) Progress.hide();
      outEl.textContent = "⚠️ Nothing to encrypt — type a message or import a file first";
      return;
    }
    plaintextBytes = new TextEncoder().encode(msgText);
  }

  try {
    if(willBeLarge) Progress.show('Encrypting…');
    const packet = await session.encrypt(
      plaintextBytes, extraHeader,
      willBeLarge ? (f) => Progress.update(f, 'Encrypting…') : null
    );
    lastEncryptedPacket = packet;

    if(plaintextBytes.length > DISPLAY_THRESHOLD){
      const approxCipherSize = estimateChunksByteLength(packet.dataChunks);
      outEl.textContent = `🔒 Encrypted — approx. ${formatBytes(approxCipherSize)}. Too large to display here. Use Export or Copy below.`;
    } else {
      outEl.textContent = encodeOpaquePacket(packet);
    }
  } catch(e){
    console.error(e);
    if(e.message && e.message.includes("no sending chain")){
      outEl.textContent = "⚠️ You can't send yet — your peer needs to send the first message in this session before you can reply. (Whoever's public key sorts first becomes the initiator and sends first.)";
    } else {
      outEl.textContent = "❌ Encryption failed unexpectedly (see console).";
    }
  } finally {
    if(willBeLarge) Progress.hide();
  }
}

async function doDecrypt(){
  const outEl = document.getElementById("plainOut");
  if(!session){
    outEl.textContent = "⚠️ No shared secret — set up a session first";
    return;
  }

  let packet = pendingDecryptPacket;
  if(!packet){
    try {
      packet = decodeOpaquePacket(document.getElementById("cipherIn").value);
    } catch(e){
      outEl.textContent = "❌ That doesn't look like a valid encrypted message — check you copied the whole thing.";
      return;
    }
  }

  const approxSize = packet.cipherBytes
    ? packet.cipherBytes.length
    : estimateChunksByteLength(packet.dataChunks || []);
  const willBeLarge = approxSize > SPINNER_THRESHOLD;

  try {
    if(willBeLarge) Progress.show('Decrypting…');
    const plainBytes = await session.decrypt(
      packet,
      willBeLarge ? (f) => Progress.update(f, 'Decrypting…') : null
    );
    const fileMeta = (packet.header && packet.header.file) ? packet.header.file : null;
    lastDecrypted = { bytes: plainBytes, fileMeta };

    if(fileMeta){
      outEl.textContent = `🔓 [File: ${fileMeta.name} — ${formatBytes(plainBytes.length)}] Use Export below to save it.`;
    } else if(plainBytes.length > DISPLAY_THRESHOLD){
      outEl.textContent = `🔓 Decrypted — ${formatBytes(plainBytes.length)} of text. Too large to display here. Use Export or Copy below.`;
    } else {
      outEl.textContent = "🔓 " + new TextDecoder().decode(plainBytes);
    }
  } catch(e){
    console.error("DECRYPT ERROR:", e);
    lastDecrypted = null;
    let msg = "❌ Couldn't decrypt this message — ";
    if(e.message && e.message.includes("unrecognized packet")){
      msg += "it isn't in a format this tool recognizes (wrong version, or not from this tool at all).";
    } else if(e.message && e.message.includes("malformed header")){
      msg += "the message header is missing required fields.";
    } else if(e.message && e.message.includes("too many")){
      msg += e.message + ".";
    } else {
      msg += "it may be corrupted, tampered with, encrypted for someone else, or already read.";
    }
    outEl.textContent = msg;
  } finally {
    if(willBeLarge) Progress.hide();
  }
}

/* ---------- msg box: attach any file, any size ---------- */

async function importMsgBox(){
  const file = await pickFile();
  if(!file) return;
  pendingAttachment = { file, name: file.name, type: file.type || 'application/octet-stream', size: file.size };
  document.getElementById('msg').value =
    `📎 Attached: ${file.name} (${formatBytes(file.size)}) — click Encrypt to send it, or type here to replace it with text.`;
}

function exportMsgBox(){
  if(pendingAttachment){
    downloadBlob(pendingAttachment.file, pendingAttachment.name);
    return;
  }
  const text = document.getElementById("msg").value;
  if(!text){ alert("⚠️ Nothing here to export yet"); return; }
  downloadBlob(new Blob([text], { type: 'text/plain' }), 'message.txt');
}

/* ---------- plainOut box: export reconstructs the original file ---------- */

function exportPlainOut(){
  if(!lastDecrypted){
    alert("⚠️ Nothing decrypted yet");
    return;
  }
  if(lastDecrypted.fileMeta){
    downloadBlob(new Blob([lastDecrypted.bytes], { type: lastDecrypted.fileMeta.type || 'application/octet-stream' }), lastDecrypted.fileMeta.name);
  } else {
    downloadBlob(new Blob([lastDecrypted.bytes], { type: 'text/plain' }), 'decrypted-message.txt');
  }
}
