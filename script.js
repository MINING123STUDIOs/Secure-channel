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
   ========================================================= */

let kp = null;           // my long-term identity key pair
let myPubRaw = null;     // raw bytes of my identity public key
let session = null;      // RatchetSession once established
let peerPubRawCached = null;
let lastDecryptedRaw = null; // exact decrypted string, for accurate export

const MAX_SKIP = 1000;
const MAX_SKIPPED_KEYS = 2000;

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

  async encrypt(plaintextBytes){
    if(!this.CKs) throw new Error("no sending chain established yet");
    const { mkSeed, nextCK } = await kdfCK(this.CKs);
    this.CKs = nextCK;
    const aesKey = await deriveMessageAesKey(mkSeed);

    const myPubRawLocal = await exportPub(this.DHs.publicKey);
    const header = { dh: b64(myPubRawLocal), pn: this.PN, n: this.Ns };
    this.Ns++;

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = new TextEncoder().encode(JSON.stringify(header));
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, aesKey, plaintextBytes);

    return { v: 2, header, iv: b64(iv), data: b64(new Uint8Array(cipher)) };
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

  async decrypt(packet){
    if(!packet || packet.v !== 2 || !packet.header) throw new Error("unrecognized packet format");
    const header = packet.header;
    if(typeof header.dh !== "string" || typeof header.n !== "number" || typeof header.pn !== "number"){
      throw new Error("malformed header");
    }
    const dhRawIncoming = unb64(header.dh);
    const skipKey = header.dh + ":" + header.n;
    const iv = unb64(packet.iv);
    const data = unb64(packet.data);
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

function tryParseEnvelope(text){
  try {
    const obj = JSON.parse(text);
    if(obj && obj.__binary__ === true && typeof obj.data === "string" && typeof obj.name === "string") return obj;
  } catch(e){ /* not an envelope, that's fine */ }
  return null;
}

async function fileToBoxValue(file){
  const isTextish = file.type.startsWith('text/') ||
    /\.(txt|md|json|csv|log|js|css|html)$/i.test(file.name);
  if(isTextish){
    return await file.text();
  }
  const buf = await file.arrayBuffer();
  const dataB64 = b64(new Uint8Array(buf));
  return JSON.stringify({ __binary__: true, name: file.name, type: file.type || "application/octet-stream", data: dataB64 });
}

/* ---------- UI: generic copy / export / import for text boxes ---------- */

function copyBox(id){
  const el = document.getElementById(id);
  const text = el.value !== undefined ? el.value : el.textContent;
  if(id === 'privKey' && !confirmPrivateKeyExposure("copy")) return;
  navigator.clipboard.writeText(text);
}

function exportTextBox(id, filename, isSensitive){
  const el = document.getElementById(id);
  const text = el.value !== undefined ? el.value : el.textContent;
  if(!text){ alert("⚠️ Nothing here to export yet"); return; }
  if(isSensitive && !confirmPrivateKeyExposure("export")) return;
  downloadBlob(new Blob([text], { type: 'text/plain' }), filename);
}

async function importIntoTextarea(id){
  const file = await pickFile();
  if(!file) return;
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

async function generateKeys(){
  kp = await generateIdentityKeyPair();
  myPubRaw = await exportPub(kp.publicKey);
  const privRaw = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));

  session = null;
  peerPubRawCached = null;
  lastDecryptedRaw = null;
  document.getElementById("cipherOut").textContent = "";
  document.getElementById("plainOut").textContent = "";
  document.getElementById("sessionFingerprintField").style.display = "none";

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
    session = null;
    peerPubRawCached = null;
    lastDecryptedRaw = null;
    document.getElementById("cipherOut").textContent = "";
    document.getElementById("plainOut").textContent = "";
    document.getElementById("sessionFingerprintField").style.display = "none";

    document.getElementById("pubKey").value = obj.publicKey;
    document.getElementById("privKey").value = obj.privateKey;
    await updateMyFingerprint();

    setStatus("✅ Identity restored. Awaiting peer...");
  } catch(e){
    console.error(e);
    alert("⚠️ That file doesn't look like a valid identity backup.");
  }
}

function togglePriv(){
  const el = document.getElementById("privKey");
  if(el.type === "password"){
    if(!confirmPrivateKeyExposure("reveal")) return;
    el.type = "text";
  } else {
    el.type = "password";
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
  session = null;
  peerPubRawCached = null;
  lastDecryptedRaw = null;
  document.getElementById("sessionFingerprintField").style.display = "none";
  document.getElementById("cipherOut").textContent = "";
  document.getElementById("plainOut").textContent = "";
  setStatus("🔄 Session reset. Create a new shared secret to keep talking.");
}

/* ---------- Encrypt / Decrypt ---------- */

async function doEncrypt(){
  if(!session){
    alert("⚠️ No shared secret — set up a session first");
    return;
  }
  const msgText = document.getElementById("msg").value;
  if(!msgText){
    alert("⚠️ Nothing to encrypt — type a message or import a file first");
    return;
  }
  try {
    const packet = await session.encrypt(new TextEncoder().encode(msgText));
    document.getElementById("cipherOut").textContent = JSON.stringify(packet, null, 2);
  } catch(e){
    console.error(e);
    if(e.message && e.message.includes("no sending chain")){
      alert("⚠️ You can't send yet — your peer needs to send the first message in this session before you can reply. (Whoever's public key sorts first becomes the initiator and sends first.)");
    } else {
      alert("❌ Encryption failed unexpectedly (see console).");
    }
  }
}

async function doDecrypt(){
  const outEl = document.getElementById("plainOut");
  if(!session){
    outEl.textContent = "⚠️ No shared secret — set up a session first";
    return;
  }
  let packet;
  try {
    packet = JSON.parse(document.getElementById("cipherIn").value);
  } catch(e){
    outEl.textContent = "❌ That doesn't look like valid JSON — check you copied the whole encrypted message.";
    return;
  }

  try {
    const plainBytes = await session.decrypt(packet);
    const text = new TextDecoder().decode(plainBytes);
    lastDecryptedRaw = text;

    const env = tryParseEnvelope(text);
    if(env){
      const size = formatBytes(unb64(env.data).length);
      outEl.textContent = `🔓 [File: ${env.name} — ${size}] Use the Export button below to save it.`;
    } else {
      outEl.textContent = "🔓 " + text;
    }
  } catch(e){
    console.error("DECRYPT ERROR:", e);
    lastDecryptedRaw = null;
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
  }
}

/* ---------- msg box: import/export supporting arbitrary files ---------- */

async function importMsgBox(){
  const file = await pickFile();
  if(!file) return;
  try {
    document.getElementById("msg").value = await fileToBoxValue(file);
  } catch(e){
    console.error(e);
    alert("❌ Couldn't read that file (see console).");
  }
}

function exportMsgBox(){
  const text = document.getElementById("msg").value;
  if(!text){ alert("⚠️ Nothing here to export yet"); return; }
  const env = tryParseEnvelope(text);
  if(env){
    downloadBlob(new Blob([unb64(env.data)], { type: env.type }), env.name);
  } else {
    downloadBlob(new Blob([text], { type: 'text/plain' }), 'message.txt');
  }
}

/* ---------- plainOut box: export reconstructs the original file ---------- */

function exportPlainOut(){
  if(lastDecryptedRaw == null){
    alert("⚠️ Nothing decrypted yet");
    return;
  }
  const env = tryParseEnvelope(lastDecryptedRaw);
  if(env){
    downloadBlob(new Blob([unb64(env.data)], { type: env.type }), env.name);
  } else {
    downloadBlob(new Blob([lastDecryptedRaw], { type: 'text/plain' }), 'decrypted-message.txt');
  }
}
