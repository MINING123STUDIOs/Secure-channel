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

   FILE MAP (script split across js/, in load order):
   - constants.js    — this file: thresholds, byte helpers, the outer
                        envelope obfuscation layer.
   - crypto-core.js  — ECDH/HKDF/HMAC/AES-GCM primitives and the
                        RatchetSession double-ratchet implementation.
   - large-payload.js— base64 chunking and the streaming large-file
                        export/import format built on top of it.
   - ui.js           — all DOM wiring, session state, and the
                        Encrypt/Decrypt/Key-management handlers.
   These load as ordinary classic <script> tags (no bundler, no
   modules), so they share one global scope exactly like one big file
   would — order in index.html matters and must match the dependency
   order above.
   ========================================================= */

/* ---------- thresholds ---------- */

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
   double ratchet in crypto-core.js. All this does is stop the
   copy/pasted or exported text from visually announcing itself as "an
   encrypted messenger packet" (readable {"header":..., "dataChunks":...}
   JSON, or a base64-of-JSON blob starting with the tell-tale "eyJ..."
   that tools and onlookers recognize on sight).

   A single fixed-length XOR key (the original approach) breaks the
   brace/quote signature, but it's a weak camouflage: XOR-ing with a
   short repeating key leaves a short repeating period in the output,
   which is itself a recognizable statistical fingerprint (autocorrelation
   at the key length gives it away instantly to anything actually
   looking, and a byte-frequency count on some ciphertexts can even
   recover the key). Instead, envelopeKeystream() expands a fixed public
   seed into an arbitrarily long, non-repeating stream via SHA-256 in
   counter mode — block i = SHA-256(seed || i). Every block is derived
   independently and inherits SHA-256's avalanche property (flipping
   one counter bit flips roughly half of that block's output bits), so
   there's no short period and no simple structure left for a naive
   scanner — or a human eyeballing the blob — to key off of.

   None of this is a secret: the seed is public, it ships in this file,
   and anyone with this source can regenerate the exact same stream.
   That's expected and fine, since it's cosmetic camouflage, not a
   security boundary — see dev.md §3 before treating it as one. */
const ENVELOPE_SEED = new Uint8Array([
  0x5a, 0x3c, 0x91, 0xe7, 0x2d, 0x88, 0x14, 0x6b,
  0xc2, 0x49, 0xf0, 0x77, 0x8e, 0x03, 0xd5, 0xaa
]);

// Expands ENVELOPE_SEED into a `length`-byte pseudorandom keystream.
// Deterministic given `length` alone (never depends on the data being
// masked), which is what keeps maskBytes its own inverse — XOR-ing
// with the same stream twice returns the original bytes.
async function envelopeKeystream(length){
  const blockSize = 32; // SHA-256 output size
  const blockCount = Math.ceil(length / blockSize) || 1;
  const blocks = new Array(blockCount);
  for(let counter = 0; counter < blockCount; counter++){
    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, counter, false);
    const material = concatBytes(ENVELOPE_SEED, counterBytes);
    blocks[counter] = new Uint8Array(await crypto.subtle.digest("SHA-256", material));
  }
  const out = new Uint8Array(blockCount * blockSize);
  for(let i = 0; i < blocks.length; i++) out.set(blocks[i], i * blockSize);
  return out.slice(0, length);
}

async function maskBytes(bytes){
  const stream = await envelopeKeystream(bytes.length);
  const out = new Uint8Array(bytes.length);
  for(let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ stream[i];
  return out;
}

// packet -> opaque base64 blob (no braces, quotes, or field names visible)
async function encodeOpaquePacket(packet){
  const json = JSON.stringify(packet);
  const masked = await maskBytes(new TextEncoder().encode(json));
  return b64(masked);
}

// opaque base64 blob -> packet (throws if it isn't one of ours)
async function decodeOpaquePacket(str){
  const cleaned = String(str).trim().replace(/\s+/g, "");
  const masked = unb64(cleaned);       // throws on invalid base64 — caller already handles that
  const json = new TextDecoder().decode(await maskBytes(masked));
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
