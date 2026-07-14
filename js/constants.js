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
const LARGE_IMPORT_CONFIRM_THRESHOLD = 300 * 1024 * 1024; // above this, ask for confirmation before importing (may crash browser)

// Binary format magic bytes — 4-byte signatures written at the start of
// exported files so import can distinguish binary from base64 text.
// "SCBN" = Secure Channel Binary (small/normal), "SCBL" = Secure Channel Binary Large.
const BIN_MAGIC_SMALL = new Uint8Array([0x53, 0x43, 0x42, 0x4E]); // "SCBN"
const BIN_MAGIC_LARGE = new Uint8Array([0x53, 0x43, 0x42, 0x4C]); // "SCBL"

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
   that tools and onlookers recognize on sight). See dev.md §3 before
   ever treating any part of this as a security boundary — it isn't one.

   Two sub-layers, applied in order by maskBytesOnce():

   1. XOR against a pseudorandom keystream. This is what breaks the
      brace/quote signature. IMPORTANT — XOR has no diffusion: output
      byte i depends on input byte i and nothing else, no matter how the
      keystream is generated. What the keystream generation *does* fix
      relative to a naive fixed short key is periodicity: a short
      repeating XOR key leaves a short repeating period in the output,
      which is itself a giveaway (autocorrelation at the key length, or
      a byte-frequency count, can reveal it). The keystream here has no
      such period — see fillPseudorandomStream() below.

   2. A chained ARX (Add / Rotate / Xor-by-position) mixing pass over
      the XOR'd bytes, taken 4 bytes at a time (arxMixWords()). THIS is
      what provides actual diffusion: each word's transform folds in an
      accumulator carried from the *previous* word's output, so changing
      one word changes every word after it, not just that one word.
      Within a word, 32-bit addition (real carry propagation across bit
      positions — unlike XOR, which never carries) and a bitwise
      rotation (spreads bit influence across byte boundaries) do the
      mixing. The trailing 0–3 bytes that don't form a full word are
      left XOR-only (there's nothing after them to diffuse into, and
      it avoids padding the output to a word boundary).

   That accumulator chain is also this sub-layer's limitation: it only
   carries FORWARD, so within one maskBytesOnce() pass, a change near the
   end of the buffer never affects bytes near the start. maskBytes() (the
   function actually called by encodeOpaquePacket) fixes that by running
   the above twice with reverseBitOrder() in between:

     maskBytesOnce(tags A) -> reverseBitOrder -> maskBytesOnce(tags B) -> reverseBitOrder

   reverseBitOrder() reverses the ENTIRE bit sequence of the buffer (byte
   order flips too, not just the bits within each byte), so whatever was
   near the end for pass 1 is near the start for pass 2. Running the mix
   again there propagates changes in the other direction; the closing
   reverseBitOrder() undoes the flip so the output has the original
   orientation. unmaskBytes() runs all four steps in reverse (reverseBitOrder
   is its own inverse, so "undoing" it is just calling it again). Pass 2
   uses its own domain tags (MASK_STREAM_TAG_2 / ROUND_MATERIAL_TAG_2) so
   it isn't the same keystream/round material re-applied to a permutation
   of pass 1's own output.

   Keystream generation: rather than hashing every 32-byte block with
   SHA-256 (the previous approach), which would mean millions of async
   crypto.subtle.digest calls for this tool's largest supported exports
   (~200MB), a single 32-bit seed is derived from ENVELOPE_SEED via one
   SHA-256 call per stream, then expanded with mulberry32, a small fast
   synchronous PRNG. mulberry32 is NOT cryptographically secure and must
   never be treated as such — it's chosen purely for speed on large
   payloads, exactly the way this whole layer is chosen purely for not
   looking recognizable. Its period (~2^32) comfortably exceeds any
   realistic message size here, and it has no short repeating structure.

   None of this is a secret: the seed is public, it ships in this file,
   and anyone with this source can regenerate the exact same streams.
   That's expected and fine, since it's cosmetic camouflage, not a
   security boundary. */
const ENVELOPE_SEED = new Uint8Array([
  0x5a, 0x3c, 0x91, 0xe7, 0x2d, 0x88, 0x14, 0x6b,
  0xc2, 0x49, 0xf0, 0x77, 0x8e, 0x03, 0xd5, 0xaa
]);


const MASK_STREAM_TAG = 0x00;  // domain tag for pass 1's XOR keystream
const ROUND_MATERIAL_TAG = 0x01; // domain tag for pass 1's ARX round constants/rotations
const MASK_STREAM_TAG_2 = 0x02;  // domain tag for pass 2's XOR keystream (see maskBytes below)
const ROUND_MATERIAL_TAG_2 = 0x03; // domain tag for pass 2's ARX round constants/rotations
// Pass 2 gets its own tags rather than reusing pass 1's: reusing them would
// mean pass 2 XORs/mixes with the exact same keystream and round material as
// pass 1, just against bit-reversed input. Separate tags mean the two passes
// are independent-looking layers, not the same layer applied to a permutation
// of its own output.

// One-time (per call) 32-bit seed for a named stream, derived from the
// public ENVELOPE_SEED via a single SHA-256 call. Different tags produce
// unrelated-looking streams from the same base seed — this is the one
// place a real hash (with its avalanche property) is used; everything
// after this is fast synchronous PRNG expansion, not hashing.
async function envelopeDomainSeed(tag){
  const material = concatBytes(ENVELOPE_SEED, new Uint8Array([tag]));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", material));
  return new DataView(digest.buffer).getUint32(0, false);
}

// Fills a `length`-byte stream from a 32-bit seed, 4 bytes per PRNG call.
// The generator is mulberry32 (small, fast, public-domain; Tommy
// Ettinger) — not a CSPRNG, fine here since this whole layer is
// cosmetic, chosen only to expand a SHA-256-derived seed quickly.
// The PRNG's step is inlined directly in the loop below (rather than
// called through a returned closure) and written via a Uint32Array view
// rather than DataView — both matter once this runs millions of times
// over a large export; profiling a 20MB stream showed the closure-call +
// DataView version costing ~1.7s here alone, most of which this removes.
// Yields periodically so very large (near-200MB) payloads don't freeze
// the tab — see dev.md §2 on async-for-anything-at-scale.
//
// NOTE on endianness: this writes through a Uint32Array view, so the
// byte order of each 4-byte group follows the platform's native order
// rather than an explicit one. Every mainstream JS engine (all current
// desktop and mobile browsers, Node) runs on little-endian hardware, so
// in practice this is consistent for every real user of this tool. That
// wouldn't be an acceptable assumption for the real cryptography in
// crypto-core.js — it's fine here only because this layer is cosmetic
// and both sides of a conversation run the same class of engine.
async function fillPseudorandomStream(seed32, length){
  const out = new Uint8Array(length);
  const wordCount = length >> 2;
  const words = new Uint32Array(out.buffer, out.byteOffset, wordCount);
  let a = seed32 >>> 0;
  for(let i = 0; i < wordCount; i++){
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    words[i] = (t ^ (t >>> 14)) >>> 0;
    if((i & 0xffffff) === 0) await yieldToUI(); // roughly every 64MB (matches CHUNK_BYTES elsewhere)
  }
  const rem = length - wordCount * 4;
  if(rem > 0){
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    const tailWord = (t ^ (t >>> 14)) >>> 0;
    for(let b = 0; b < rem; b++) out[wordCount * 4 + b] = (tailWord >>> (24 - 8 * b)) & 0xff;
  }
  return out;
}

function rotl32(x, r){
  const s = r & 31;
  return ((x << s) | (x >>> (32 - s))) >>> 0;
}
function rotr32(x, r){
  const s = r & 31;
  return ((x >>> s) | (x << (32 - s))) >>> 0;
}

// Chained ARX mixing pass over full 4-byte words of `bytes`, mutated in
// place. `acc` carries the previous word's *output* into the next word's
// input — that chain is what gives real forward diffusion (change one
// word, every later word changes), which plain XOR structurally cannot
// provide regardless of keystream quality. `roundMaterial` supplies one
// 32-bit addition constant per word (added with ordinary 32-bit
// wraparound — genuine carry propagation across bit positions); the
// rotation amount is derived from that same constant (`rc % 31 + 1`)
// rather than stored separately, since a second independent value adds
// generation cost without adding anything a cosmetic layer needs. Set
// `inverse` to undo it — this is why the whole layer needs a separate
// unmaskBytes() rather than being its own inverse the way plain
// XOR-only masking was. Uses Uint32Array views for the same performance
// reason as fillPseudorandomStream above (see its endianness note).
async function arxMixWords(bytes, roundMaterial, inverse){
  const wordCount = bytes.length >> 2;
  const words = new Uint32Array(bytes.buffer, bytes.byteOffset, wordCount);
  const rm = new Uint32Array(roundMaterial.buffer, roundMaterial.byteOffset, wordCount);
  let acc = 0;
  for(let i = 0; i < wordCount; i++){
    const rc = rm[i];
    const rot = (rc % 31) + 1;
    if(!inverse){
      const mixed = rotl32((words[i] + acc + rc) >>> 0, rot);
      words[i] = mixed;
      acc = mixed;
    } else {
      const mixed = words[i];
      words[i] = (rotr32(mixed, rot) - acc - rc) >>> 0;
      acc = mixed; // the chain is keyed on the OUTPUT word, already known while reading forward
    }
    if((i & 0xffffff) === 0) await yieldToUI(); // roughly every 64MB, same cadence as elsewhere
  }
}

// Precomputed byte-level bit-reversal table (bit 7 <-> bit 0, bit 6 <-> bit 1,
// etc. within one byte), used by reverseBitOrder() below. A table lookup is
// cheaper per byte than re-deriving it with shifts every time, which matters
// once this runs across a ~200MB buffer.
const BIT_REVERSE_TABLE = (() => {
  const t = new Uint8Array(256);
  for(let i = 0; i < 256; i++){
    let b = i, r = 0;
    for(let k = 0; k < 8; k++){ r = (r << 1) | (b & 1); b >>= 1; }
    t[i] = r;
  }
  return t;
})();

// Reverses the ENTIRE bit sequence of `bytes`, treating the whole buffer as
// one long bit string rather than reversing bits within each byte in place.
// The very last bit of the buffer becomes the very first bit of the output,
// which means byte order flips too: out[i] is BIT_REVERSE_TABLE applied to
// bytes[length-1-i], not to bytes[i]. It's its own inverse (reversing twice
// restores the original), which is what lets maskBytes/unmaskBytes below
// undo it symmetrically without a separate "unreverse" function.
// Yields periodically for the same reason as fillPseudorandomStream/
// arxMixWords — a synchronous pass over a near-200MB buffer would freeze
// the tab (dev.md §2).
async function reverseBitOrder(bytes){
  const n = bytes.length;
  const out = new Uint8Array(n);
  for(let i = 0; i < n; i++){
    out[i] = BIT_REVERSE_TABLE[bytes[n - 1 - i]];
    if((i & 0xffffff) === 0) await yieldToUI(); // roughly every 16M bytes
  }
  return out;
}

// Single application of the XOR-then-ARX layer described above, parameterized
// on which domain tags to derive its keystream/round material from. This is
// the whole of what maskBytes/unmaskBytes used to do directly; it's now
// applied twice (see maskBytes below) with different tags each time, so it's
// factored out rather than duplicated.
async function maskBytesOnce(bytes, xorTag, roundTag){
  const maskSeed = await envelopeDomainSeed(xorTag);
  const xorStream = await fillPseudorandomStream(maskSeed, bytes.length);
  const out = new Uint8Array(bytes.length);
  for(let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ xorStream[i];

  const wordCount = out.length >> 2;
  if(wordCount > 0){
    const roundSeed = await envelopeDomainSeed(roundTag);
    const roundMaterial = await fillPseudorandomStream(roundSeed, wordCount * 4);
    await arxMixWords(out.subarray(0, wordCount * 4), roundMaterial, false);
  }
  return out;
}

// Inverse of maskBytesOnce for the same tag pair.
async function unmaskBytesOnce(bytes, xorTag, roundTag){
  const out = new Uint8Array(bytes); // copy — never mutate the caller's buffer

  const wordCount = out.length >> 2;
  if(wordCount > 0){
    const roundSeed = await envelopeDomainSeed(roundTag);
    const roundMaterial = await fillPseudorandomStream(roundSeed, wordCount * 4);
    await arxMixWords(out.subarray(0, wordCount * 4), roundMaterial, true);
  }

  const maskSeed = await envelopeDomainSeed(xorTag);
  const xorStream = await fillPseudorandomStream(maskSeed, out.length);
  for(let i = 0; i < out.length; i++) out[i] ^= xorStream[i];
  return out;
}

// maskBytes = maskOnce, reverseBitOrder, maskOnce again (different tags),
// reverseBitOrder again.
//
// WHY: within a single maskBytesOnce pass, arxMixWords' mixing accumulator
// only carries forward — word i's output folds in word i-1's output, never
// word i+1's. So in one pass, flipping a byte near the END of the buffer has
// NO effect at all on bytes near the start; diffusion is one-directional.
// Reversing the entire buffer's bit order between the two passes (not just
// each byte's bits — the whole thing, so byte order flips too) means
// whatever was near the end for pass 1 is near the start for pass 2, and
// vice versa. Running maskBytesOnce again on that reversed buffer mixes in
// the other direction. Combined, a change anywhere in the input now
// propagates through the entire output, not just through what followed it.
// The final reverseBitOrder restores the original byte/bit orientation so
// output length and layout otherwise still line up the way callers expect.
//
// Pass 2 uses MASK_STREAM_TAG_2/ROUND_MATERIAL_TAG_2 (not the pass-1 tags)
// so it isn't the same keystream/round material folded over a permutation
// of its own output — see the comment on those constants.
async function maskBytes(bytes){
  const pass1 = await reverseBitOrder(bytes); 
  const flipped1 = await maskBytesOnce(pass1, MASK_STREAM_TAG, ROUND_MATERIAL_TAG);
  const pass2 = await reverseBitOrder(flipped1);
  return await maskBytesOnce(pass2, MASK_STREAM_TAG_2, ROUND_MATERIAL_TAG_2);
}

// Exact inverse of maskBytes, undoing each step in reverse order. Because
// reverseBitOrder is its own inverse, undoing it is just calling it again —
// there's no separate "unreverse" function needed.
async function unmaskBytes(bytes){
  const flipped2 = await unmaskBytesOnce(bytes, MASK_STREAM_TAG_2, ROUND_MATERIAL_TAG_2);
  const pass2Undone = await reverseBitOrder(flipped2);
  const flipped1 = await unmaskBytesOnce(pass2Undone, MASK_STREAM_TAG, ROUND_MATERIAL_TAG);
  return await reverseBitOrder(flipped1); 
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
  const json = new TextDecoder().decode(await unmaskBytes(masked));
  return JSON.parse(json);             // throws on malformed JSON — caller already handles that
}

// packet -> binary blob (small, for file export — raw masked bytes, not base64)
async function encodeOpaquePacketBinary(packet){
  const json = JSON.stringify(packet);
  const masked = await maskBytes(new TextEncoder().encode(json));
  return concatBytes(BIN_MAGIC_SMALL, masked);
}

// binary blob -> packet (inverse of encodeOpaquePacketBinary)
async function decodeOpaquePacketBinary(bytes){
  const masked = bytes.slice(BIN_MAGIC_SMALL.length);
  const json = new TextDecoder().decode(await unmaskBytes(masked));
  return JSON.parse(json);
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
