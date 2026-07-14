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

/* ---------- session state ---------- */

let kp = null;           // my long-term identity key pair
let myPubRaw = null;     // raw bytes of my identity public key
let session = null;      // RatchetSession once established
let peerPubRawCached = null;

// --- state for large-payload / attachment handling ---
let pendingAttachment = null;   // { file, name, type, size } set by importMsgBox()
let lastEncryptedPacket = null; // the actual packet object behind cipherOut's display
let pendingDecryptPacket = null;// a packet reconstructed from a large imported file
let lastDecrypted = null;       // { bytes: Uint8Array, fileMeta: {name,type}|null } behind plainOut's display

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
// triggered it. Returns a Promise<boolean> — true if the user confirmed.
async function confirmPrivateKeyExposure(action, outEl){
  return showConfirmWarning(
    outEl,
    `⚠️ You're about to ${action} your PRIVATE key. ` +
    `Anyone who obtains it can read your messages and impersonate you. ` +
    `Only continue if you're sure of where it's going (or who's looking at your screen).`,
    '✅ Continue',
    '❌ Cancel'
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

/* ---------- Clear button functionality ---------- */

function clearInputField(id) {
  const el = document.getElementById(id);
  if (!el) return;
  
  // Clear the field
  el.value = '';
  
  // Handle specific field logic
  if (id === 'msg') {
    pendingAttachment = null;
  } else if (id === 'cipherIn') {
    pendingDecryptPacket = null;
  } else if (id === 'peerKey') {
    updatePeerFingerprint();
  }
}

/* ---------- Paste button functionality ---------- */

async function pasteInputField(id) {
  try {
    const text = await navigator.clipboard.readText();
    const el = document.getElementById(id);
    if (!el) return;
    
    el.value = text;
    
    // Handle specific field logic
    if (id === 'peerKey') {
      updatePeerFingerprint();
    }
  } catch(e) {
    console.error('Paste failed:', e);
    showInlineMessage(document.getElementById("cipherOut"), "⚠️ Could not read from clipboard. Please paste manually.");
  }
}

/* ---------- Large file import confirmation ---------- */

function showLargeImportWarning(outEl, file, onConfirm){
  outEl.textContent = `⚠️ File is ${formatBytes(file.size)} — too large to import safely. The browser may crash or become unresponsive.`;
  const row = document.createElement('div');
  row.className = 'confirm-row';
  const yes = document.createElement('button');
  yes.className = 'confirm-yes';
  yes.textContent = '✅ Import anyway';
  const no = document.createElement('button');
  no.className = 'confirm-no';
  no.textContent = '❌ Cancel';
  function cleanup(){ row.remove(); outEl.textContent = ''; }
  yes.onclick = () => { cleanup(); onConfirm(file); };
  no.onclick = cleanup;
  row.appendChild(yes);
  row.appendChild(no);
  outEl.parentElement.insertBefore(row, outEl.nextSibling);
}

/* ---------- Generic inline confirmation warning ---------- */
/* Active confirmations keyed by output element. Each entry stores
   { resolve, cleanup }. Clicking a button that would trigger a new
   confirmation in the same element cancels the previous one: resolves
   it as false AND removes the old DOM elements synchronously. */
const _activeConfirms = new Map();

function showConfirmWarning(outEl, message, yesLabel, noLabel){
  /* cancel any previous confirmation on this same element */
  if(_activeConfirms.has(outEl)){
    const prev = _activeConfirms.get(outEl);
    prev.resolve(false);
    prev.cleanup();
  }
  return new Promise(resolve => {
    outEl.textContent = message;
    const row = document.createElement('div');
    row.className = 'confirm-row';
    const yes = document.createElement('button');
    yes.className = 'confirm-yes';
    yes.textContent = yesLabel || '✅ Continue';
    const no = document.createElement('button');
    no.className = 'confirm-no';
    no.textContent = noLabel || '❌ Cancel';
    function cleanup(){ row.remove(); outEl.textContent = ''; _activeConfirms.delete(outEl); }
    _activeConfirms.set(outEl, { resolve, cleanup });
    yes.onclick = () => { cleanup(); resolve(true); };
    no.onclick = () => { cleanup(); resolve(false); };
    row.appendChild(yes);
    row.appendChild(no);
    outEl.parentElement.insertBefore(row, outEl.nextSibling);
  });
}

/* ---------- Inline dismissible message (no user choice required) ---------- */
const _activeWarnings = new Map();

function showInlineMessage(outEl, message, ms){
  if(_activeWarnings.has(outEl)) clearTimeout(_activeWarnings.get(outEl));
  outEl.textContent = message;
  const t = setTimeout(() => { outEl.textContent = ''; _activeWarnings.delete(outEl); }, ms || 3500);
  _activeWarnings.set(outEl, t);
}

function estimateChunksByteLength(chunks){
  // rough (slightly over-) estimate of decoded byte size from base64 chunk lengths, for display purposes only
  return chunks.reduce((s, c) => s + Math.floor(c.length * 0.75), 0);
}

/* ---------- UI: generic copy / export / import for text boxes ----------
   Note: cipherOut, plainOut, and privKeyOut are RESULT boxes (Encrypt/Decrypt
   output, or inline confirmations), not inputs — there's deliberately no
   Import button wired to them in index.html, since importing a file into
   an output space doesn't make sense. Only genuine input fields (peerKey,
   msg, cipherIn) support Import. */

async function copyBox(id){
  if(id === 'cipherOut'){
    if(!lastEncryptedPacket){ showInlineMessage(document.getElementById("cipherOut"), "⚠️ Nothing here to copy yet"); return; }
    if(estimateChunksByteLength(lastEncryptedPacket.dataChunks) > STREAMING_EXPORT_THRESHOLD){
      showInlineMessage(document.getElementById("cipherOut"), "⚠️ This message is too large to copy to the clipboard. Use Export below to save it as a file instead.");
      return;
    }
    navigator.clipboard.writeText(await encodeOpaquePacket(lastEncryptedPacket));
    return;
  }
  if(id === 'plainOut'){
    if(!lastDecrypted){ showInlineMessage(document.getElementById("plainOut"), "⚠️ Nothing decrypted yet"); return; }
    if(lastDecrypted.fileMeta){
      showInlineMessage(document.getElementById("plainOut"), "This decrypted content is a file — use Export below to save it, not Copy.");
      return;
    }
    if(lastDecrypted.bytes.length > STREAMING_EXPORT_THRESHOLD){
      showInlineMessage(document.getElementById("plainOut"), "⚠️ This message is too large to copy to the clipboard. Use Export below to save it as a file instead.");
      return;
    }
    navigator.clipboard.writeText(new TextDecoder().decode(lastDecrypted.bytes));
    return;
  }
  const el = document.getElementById(id);
  const text = el.value !== undefined ? el.value : el.textContent;
  if(id === 'privKey'){
    if(!await confirmPrivateKeyExposure("copy", document.getElementById("privKeyOut"))) return;
  }
  navigator.clipboard.writeText(text);
}

async function exportTextBox(id, filename, isSensitive){
  if(id === 'cipherOut'){
    if(!lastEncryptedPacket){ showInlineMessage(document.getElementById("cipherOut"), "⚠️ Nothing here to export yet"); return; }
    if(estimateChunksByteLength(lastEncryptedPacket.dataChunks) > STREAMING_EXPORT_THRESHOLD){
      const parts = await buildLargeExportPartsBinary(lastEncryptedPacket);
      downloadBlob(new Blob(parts, { type: 'application/octet-stream' }), filename.replace(/\.[^.]+$/, '.scb'));
    } else {
      downloadBlob(new Blob([await encodeOpaquePacketBinary(lastEncryptedPacket)], { type: 'application/octet-stream' }), filename);
    }
    return;
  }
  const el = document.getElementById(id);
  const text = el.value !== undefined ? el.value : el.textContent;
  if(!text){ showInlineMessage(document.getElementById(id === 'privKey' ? 'privKeyOut' : id), "⚠️ Nothing here to export yet"); return; }
  if(isSensitive){
    if(!await confirmPrivateKeyExposure("export", document.getElementById("privKeyOut"))) return;
  }
  downloadBlob(new Blob([text], { type: 'text/plain' }), filename);
}

async function importIntoTextareaProcess(id, file){
  if(id === 'cipherIn'){
    pendingDecryptPacket = null;
    if(file.size > DISPLAY_THRESHOLD){
      const showSpinner = file.size > SPINNER_THRESHOLD;
      try {
        if(showSpinner) Progress.show('Reading file…');

        // Peek at the first bytes to detect format
        const magicSlice = await file.slice(0, 4).arrayBuffer();
        const magicBytes = new Uint8Array(magicSlice);
        const isBinSmall = bytesEqual(magicBytes, BIN_MAGIC_SMALL);
        const isBinLarge = bytesEqual(magicBytes, BIN_MAGIC_LARGE);

        if(isBinSmall){
          const fullBytes = new Uint8Array(await file.arrayBuffer());
          pendingDecryptPacket = await decodeOpaquePacketBinary(fullBytes);
        } else if(isBinLarge){
          pendingDecryptPacket = await streamingParseLargeBinaryFile(
            file, undefined,
            showSpinner ? (f) => Progress.update(f, 'Reading file…') : null
          );
        } else {
          // Not binary — try text formats (old .scl or base64)
          const magicPeek = new TextDecoder().decode(magicBytes);
          if(magicPeek.startsWith(LARGE_FORMAT_MAGIC)){
            pendingDecryptPacket = await streamingParseLargeFile(
              file, undefined,
              showSpinner ? (f) => Progress.update(f, 'Reading file…') : null
            );
          } else if(file.size > STREAMING_EXPORT_THRESHOLD){
            document.getElementById('cipherIn').value =
              `⚠️ This file is ${formatBytes(file.size)} and isn't in this tool's format — ` +
              `it may fail to load. If it came from this tool's Export, that's unexpected; otherwise it wasn't meant for direct import this large.`;
            return;
          } else {
            pendingDecryptPacket = await decodeOpaquePacket(await file.text());
          }
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

async function importIntoTextarea(id){
  const file = await pickFile();
  if(!file) return;
  if(file.size > LARGE_IMPORT_CONFIRM_THRESHOLD){
    const outEl = id === 'cipherIn' ? document.getElementById('plainOut') : document.getElementById('cipherOut');
    showLargeImportWarning(outEl, file, (f) => importIntoTextareaProcess(id, f));
    return;
  }
  await importIntoTextareaProcess(id, file);
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
  if(!kp){ showInlineMessage(document.getElementById("privKeyOut"), "⚠️ Generate a key pair first"); return; }
  if(!await confirmPrivateKeyExposure("export (as part of your identity backup)", document.getElementById("privKeyOut"))) return;
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
    showInlineMessage(document.getElementById("cipherOut"), "⚠️ That file doesn't look like a valid identity backup.");
  }
}

// Show/Hide toggle: swaps the field type, the button label, and marks
// the eye icon with a diagonal strike-through while the key is visible.
async function togglePriv(){
  const el = document.getElementById("privKey");
  const icon = document.getElementById("eyeIcon");
  const label = document.getElementById("toggleLabel");
  if(el.type === "password"){
    if(!await confirmPrivateKeyExposure("reveal", document.getElementById("privKeyOut"))) return;
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
  document.getElementById('msg').addEventListener('input', function(){
    pendingAttachment = null;
    if(this.value === '⚠️ Nothing here to export yet') this.value = '';
  });
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

async function resetSessionUI(){
  if(!session){
    setStatus("Nothing to reset — no session is active.");
    return;
  }
  if(!await showConfirmWarning(
    document.getElementById("cipherOut"),
    "This will end the current secure session. You won't be able to decrypt any messages from this conversation afterward (though your keys stay intact). Continue?",
    '✅ Reset session',
    '❌ Cancel'
  )){
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
      outEl.textContent = await encodeOpaquePacket(packet);
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

async function doDecryptProcess(packet){
  const outEl = document.getElementById("plainOut");
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

async function doDecrypt(){
  const outEl = document.getElementById("plainOut");
  if(!session){
    outEl.textContent = "⚠️ No shared secret — set up a session first";
    return;
  }

  let packet = pendingDecryptPacket;
  if(!packet){
    try {
      packet = await decodeOpaquePacket(document.getElementById("cipherIn").value);
    } catch(e){
      outEl.textContent = "❌ That doesn't look like a valid encrypted message — check you copied the whole thing.";
      return;
    }
  }

  const approxSize = packet.cipherBytes
    ? packet.cipherBytes.length
    : estimateChunksByteLength(packet.dataChunks || []);

  if(approxSize > LARGE_IMPORT_CONFIRM_THRESHOLD){
    showLargeImportWarning(outEl, { size: approxSize, name: 'encrypted message' }, () => doDecryptProcess(packet));
    return;
  }

  await doDecryptProcess(packet);
}

/* ---------- msg box: attach any file, any size ---------- */

function importMsgBoxAttach(file){
  pendingAttachment = { file, name: file.name, type: file.type || 'application/octet-stream', size: file.size };
  document.getElementById('msg').value =
    `📎 Attached: ${file.name} (${formatBytes(file.size)}) — click Encrypt to send it, or type here to replace it with text.`;
}

async function importMsgBox(){
  const file = await pickFile();
  if(!file) return;
  if(file.size > LARGE_IMPORT_CONFIRM_THRESHOLD){
    showLargeImportWarning(document.getElementById('cipherOut'), file, importMsgBoxAttach);
    return;
  }
  importMsgBoxAttach(file);
}

function exportMsgBox(){
  if(pendingAttachment){
    downloadBlob(pendingAttachment.file, pendingAttachment.name);
    return;
  }
  const text = document.getElementById("msg").value;
  if(!text){ document.getElementById("msg").value = "⚠️ Nothing here to export yet"; return; }
  downloadBlob(new Blob([text], { type: 'text/plain' }), 'message.txt');
}

/* ---------- plainOut box: export reconstructs the original file ---------- */

function exportPlainOut(){
  if(!lastDecrypted){
    showInlineMessage(document.getElementById("plainOut"), "⚠️ Nothing decrypted yet");
    return;
  }
  if(lastDecrypted.fileMeta){
    downloadBlob(new Blob([lastDecrypted.bytes], { type: lastDecrypted.fileMeta.type || 'application/octet-stream' }), lastDecrypted.fileMeta.name);
  } else {
    downloadBlob(new Blob([lastDecrypted.bytes], { type: 'text/plain' }), 'decrypted-message.txt');
  }
}
