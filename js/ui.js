/*
 * Secure Channel Assistant — end-to-end encrypted messaging with a
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
let myPrivKeyB64 = null; // private key base64, kept out of DOM
let session = null;      // RatchetSession once established
let peerPubRawCached = null;

// --- state for large-payload / attachment handling ---
let pendingAttachment = null;   // { file, name, type, size } set by importMsgBox()
let lastEncryptedPacket = null; // the actual packet object behind cipherOut's display
let lastEncryptedPacketB64 = null; // cached base64 for clipboard
let pendingDecryptPacket = null;// a packet reconstructed from a large imported file
let lastDecrypted = null;       // { bytes: Uint8Array, fileMeta: {name,type}|null } behind plainOut's display

/* ---------- UI: theme ---------- */

function applyTheme(theme){
  document.documentElement.setAttribute('data-theme', theme);
  const btn = document.getElementById('themeToggleBtn');
  btn.textContent = theme === 'light' ? LABEL_THEME_LIGHT : LABEL_THEME_DARK;
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
    labelEl.textContent = label || PROGRESS_WORKING;
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
    CONFIRM_PRIVKEY_EXPOSURE(action),
    BTN_CONTINUE,
    BTN_CANCEL,
    PRIVKEY_CONFIRM_TIMEOUT
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
    if(DEBUG) console.error('Paste failed:', e.message);
    showInlineMessage(document.getElementById(id), MSG_CLIPBOARD_FAILED);
  }
}

/* ---------- Large file import confirmation ---------- */

function showLargeImportWarning(outEl, file, onConfirm){
  outEl.textContent = CONFIRM_LARGE_IMPORT(formatBytes(file.size));
  const row = document.createElement('div');
  row.className = 'confirm-row';
  const yes = document.createElement('button');
  yes.textContent = BTN_IMPORT_ANYWAY;
  const no = document.createElement('button');
  no.className = 'danger-btn';
  no.textContent = BTN_CANCEL;
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

function showConfirmWarning(outEl, message, yesLabel, noLabel, timeout){
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
    yes.textContent = yesLabel || BTN_CONTINUE;
    const no = document.createElement('button');
    no.className = 'danger-btn';
    no.textContent = noLabel || BTN_CANCEL;
    function cleanup(){ row.remove(); outEl.textContent = ''; _activeConfirms.delete(outEl); if(timer) clearTimeout(timer); }
    _activeConfirms.set(outEl, { resolve, cleanup });
    yes.onclick = () => { cleanup(); resolve(true); };
    no.onclick = () => { cleanup(); resolve(false); };
    const timer = timeout ? setTimeout(() => { cleanup(); resolve(false); }, timeout) : null;
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
  return chunks.reduce((s, c) => s + (c instanceof Uint8Array ? c.length : Math.floor(c.length * 0.75)), 0);
}

/* ---------- UI: generic copy / export / import for text boxes ----------
   Note: cipherOut, plainOut, and privKeyOut are RESULT boxes (Encrypt/Decrypt
   output, or inline confirmations), not inputs — there's deliberately no
   Import button wired to them in index.html, since importing a file into
   an output space doesn't make sense. Only genuine input fields (peerKey,
   msg, cipherIn) support Import. */

async function copyBox(id){
  if(id === 'cipherOut'){
    if(!lastEncryptedPacket){ showInlineMessage(document.getElementById("cipherOut"), MSG_NOTHING_TO_COPY); return; }
    if(estimateChunksByteLength(lastEncryptedPacket.dataChunks) > STREAMING_EXPORT_THRESHOLD){
      showInlineMessage(document.getElementById("cipherOut"), MSG_TOO_LARGE_TO_COPY);
      return;
    }
    try { await navigator.clipboard.writeText(lastEncryptedPacketB64); }
    catch(e){ showInlineMessage(document.getElementById("cipherOut"), MSG_CLIPBOARD_WRITE_FAILED); }
    return;
  }
  if(id === 'plainOut'){
    if(!lastDecrypted){ showInlineMessage(document.getElementById("plainOut"), MSG_NOTHING_DECRYPTED); return; }
    if(lastDecrypted.fileMeta){
      showInlineMessage(document.getElementById("plainOut"), MSG_FILE_USE_EXPORT);
      return;
    }
    if(lastDecrypted.bytes.length > STREAMING_EXPORT_THRESHOLD){
      showInlineMessage(document.getElementById("plainOut"), MSG_TOO_LARGE_TO_COPY);
      return;
    }
    try { await navigator.clipboard.writeText(new TextDecoder().decode(lastDecrypted.bytes)); }
    catch(e){ showInlineMessage(document.getElementById("plainOut"), MSG_CLIPBOARD_WRITE_FAILED); }
    return;
  }
  if(id === 'privKey'){
    if(!await confirmPrivateKeyExposure("copy", document.getElementById("privKeyOut"))) return;
    try { await navigator.clipboard.writeText(myPrivKeyB64); }
    catch(e){ showInlineMessage(document.getElementById("privKeyOut"), MSG_CLIPBOARD_WRITE_FAILED); }
    return;
  }
  const el = document.getElementById(id);
  const text = el.value !== undefined ? el.value : el.textContent;
  try { await navigator.clipboard.writeText(text); }
  catch(e){ showInlineMessage(el, MSG_CLIPBOARD_WRITE_FAILED); }
}

async function exportTextBox(id, filename, isSensitive){
  if(id === 'cipherOut'){
    if(!lastEncryptedPacket){ showInlineMessage(document.getElementById("cipherOut"), MSG_NOTHING_TO_EXPORT); return; }
    if(estimateChunksByteLength(lastEncryptedPacket.dataChunks) > STREAMING_EXPORT_THRESHOLD){
      const parts = await buildLargeExportPartsBinary(lastEncryptedPacket);
      downloadBlob(new Blob(parts, { type: 'application/octet-stream' }), filename.replace(/\.[^.]+$/, '.scb'));
    } else {
      downloadBlob(new Blob([await encodeOpaquePacketBinary(lastEncryptedPacket)], { type: 'application/octet-stream' }), filename);
    }
    return;
  }
  if(id === 'privKey'){
    if(!myPrivKeyB64){ showInlineMessage(document.getElementById("privKeyOut"), MSG_NOTHING_TO_EXPORT); return; }
    if(!await confirmPrivateKeyExposure("export", document.getElementById("privKeyOut"))) return;
    downloadBlob(new Blob([myPrivKeyB64], { type: 'text/plain' }), filename);
    return;
  }
  const el = document.getElementById(id);
  const text = el.value !== undefined ? el.value : el.textContent;
  if(!text){ showInlineMessage(document.getElementById(id), MSG_NOTHING_TO_EXPORT); return; }
  downloadBlob(new Blob([text], { type: 'text/plain' }), filename);
}

async function importIntoTextareaProcess(id, file){
  if(id === 'cipherIn'){
    pendingDecryptPacket = null;
    if(file.size > DISPLAY_THRESHOLD){
      const showSpinner = file.size > SPINNER_THRESHOLD;
      try {
        if(showSpinner) Progress.show(PROGRESS_READING);

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
            showSpinner ? (f) => Progress.update(f, PROGRESS_READING) : null
          );
        } else {
          // Not binary — try text formats (old .scl or base64)
          const magicPeek = new TextDecoder().decode(magicBytes);
          if(magicPeek.startsWith(LARGE_FORMAT_MAGIC)){
            pendingDecryptPacket = await streamingParseLargeFile(
              file, undefined,
              showSpinner ? (f) => Progress.update(f, PROGRESS_READING) : null
            );
          } else if(file.size > STREAMING_EXPORT_THRESHOLD){
            document.getElementById('cipherIn').value = MSG_WRONG_FORMAT_LARGE(formatBytes(file.size));
            return;
          } else {
            pendingDecryptPacket = await decodeOpaquePacket(await file.text());
          }
        }
      } catch(e){
        if(DEBUG) console.error('File import failed:', e.message);
        document.getElementById('cipherIn').value = MSG_CANT_READ_CIPHER_FILE(file.name);
        return;
      } finally {
        if(showSpinner) Progress.hide();
      }
      document.getElementById('cipherIn').value = MSG_CIPHER_IMPORTED(file.name, formatBytes(file.size));
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
  if(session) session.clear();
  session = null;
  peerPubRawCached = null;
  pendingAttachment = null;
  lastEncryptedPacket = null;
  lastEncryptedPacketB64 = null;
  pendingDecryptPacket = null;
  if(lastDecrypted && lastDecrypted.bytes) secureClear(lastDecrypted.bytes);
  lastDecrypted = null;
  document.getElementById("pubKey").value = "";
  document.getElementById("cipherOut").textContent = "";
  document.getElementById("plainOut").textContent = "";
  document.getElementById("sessionFingerprintField").classList.add("hidden");
}

async function generateKeys(){
  if(kp){
    if(!await showConfirmWarning(
      document.getElementById("privKeyOut"),
      CONFIRM_KEY_REPLACEMENT,
      BTN_GENERATE_NEW_KEYS,
      BTN_CANCEL
    )) return;
  }

  kp = await generateIdentityKeyPair();
  myPubRaw = await exportPub(kp.publicKey);
  const privRaw = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));

  resetTransientState();

  document.getElementById("pubKey").value = b64(myPubRaw);
  myPrivKeyB64 = b64(privRaw);
  document.getElementById("privKey").value = '•'.repeat(myPrivKeyB64.length);
  secureClear(privRaw);
  await updateMyFingerprint();

  setStatus(STATUS_KEYS_GENERATED);
}

async function exportIdentity(){
  if(!kp){ showInlineMessage(document.getElementById("privKeyOut"), MSG_GENERATE_KEYS_FIRST); return; }
  if(!await confirmPrivateKeyExposure("export (as part of your identity backup)", document.getElementById("privKeyOut"))) return;
  const privRaw = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const payload = {
    kind: "secure-channel-identity",
    v: 1,
    publicKey: b64(myPubRaw),
    privateKey: b64(privRaw)
  };
  secureClear(privRaw);
  const bytes = await encodeIdentityBytes(payload);
  downloadBlob(new Blob([bytes], { type: 'application/octet-stream' }), 'secure-channel-identity.scid');
}

async function importIdentity(){
  const file = await pickFile('.scid,.json');
  if(!file) return;
  try {
    let obj;
    const magicSlice = await file.slice(0, 4).arrayBuffer();
    const magicBytes = new Uint8Array(magicSlice);

    if(bytesEqual(magicBytes, ID_MAGIC)){
      const fullBytes = new Uint8Array(await file.arrayBuffer());
      obj = await decodeIdentityBytes(fullBytes);
      secureClear(fullBytes);
    } else {
      obj = JSON.parse(await file.text());
    }

    if(!obj.publicKey || !obj.privateKey) throw new Error("missing fields");

    const privBytes = unb64(obj.privateKey);
    const pubBytes = unb64(obj.publicKey);
    const privateKey = await crypto.subtle.importKey("pkcs8", privBytes, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const publicKey = await crypto.subtle.importKey("spki", pubBytes, { name: "ECDH", namedCurve: "P-256" }, true, []);

    const derivedPub = await exportPub(privateKey);
    if(!bytesEqual(derivedPub, pubBytes)) throw new Error("key pair mismatch");
    secureClear(derivedPub);
    secureClear(privBytes);

    kp = { privateKey, publicKey };
    myPubRaw = pubBytes;
    resetTransientState();

    document.getElementById("pubKey").value = obj.publicKey;
    myPrivKeyB64 = obj.privateKey;
    document.getElementById("privKey").value = '•'.repeat(myPrivKeyB64.length);
    await updateMyFingerprint();

    setStatus(STATUS_IDENTITY_RESTORED);
  } catch(e){
    if(DEBUG) console.error('Identity import failed:', e.message);
    showInlineMessage(document.getElementById("cipherOut"), MSG_INVALID_IDENTITY_FILE);
  }
}

let _privKeyAutohideTimer = null;

// Show/Hide toggle: swaps the field type, the button label, and marks
// the eye icon with a diagonal strike-through while the key is visible.
async function togglePriv(){
  const el = document.getElementById("privKey");
  const icon = document.getElementById("eyeIcon");
  const label = document.getElementById("toggleLabel");
  if(!myPrivKeyB64) return;
  if(el.type === "password"){
    if(!await confirmPrivateKeyExposure("reveal", document.getElementById("privKeyOut"))) return;
    el.value = myPrivKeyB64;
    el.type = "text";
    icon.classList.add("crossed");
    label.textContent = LABEL_HIDE;
    if(_privKeyAutohideTimer) clearTimeout(_privKeyAutohideTimer);
    _privKeyAutohideTimer = setTimeout(() => {
      el.type = "password";
      el.value = '•'.repeat(myPrivKeyB64.length);
      icon.classList.remove("crossed");
      label.textContent = LABEL_SHOW;
      _privKeyAutohideTimer = null;
    }, PRIVKEY_AUTOHIDE_TIMEOUT);
  } else {
    el.type = "password";
    el.value = '•'.repeat(myPrivKeyB64.length);
    icon.classList.remove("crossed");
    label.textContent = LABEL_SHOW;
    if(_privKeyAutohideTimer){ clearTimeout(_privKeyAutohideTimer); _privKeyAutohideTimer = null; }
  }
}

/* ---------- Shared secret / session ---------- */

async function updatePeerFingerprint(){
  const raw = document.getElementById("peerKey").value.trim().replace(/\s+/g, "");
  const el = document.getElementById("peerFingerprint");
  if(!raw){ el.textContent = MSG_PASTE_PEER_KEY_FIRST; return; }
  try {
    const bytes = unb64(raw);
    el.textContent = await fingerprintOf(bytes);
  } catch(e){
    el.textContent = MSG_CANT_READ_PEER_KEY;
  }
}
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('peerKey').addEventListener('input', updatePeerFingerprint);
  document.getElementById('msg').addEventListener('input', function(){
    pendingAttachment = null;
    if(this.value === MSG_NOTHING_TO_EXPORT) this.value = '';
  });
  document.getElementById('cipherIn').addEventListener('input', () => { pendingDecryptPacket = null; });

  /* ---------- button bindings ---------- */

  document.getElementById('themeToggleBtn').addEventListener('click', toggleTheme);

  document.getElementById('generateKeysBtn').addEventListener('click', generateKeys);
  document.getElementById('exportIdentityBtn').addEventListener('click', exportIdentity);
  document.getElementById('importIdentityBtn').addEventListener('click', importIdentity);

  document.getElementById('copyPubKeyBtn').addEventListener('click', () => copyBox('pubKey'));
  document.getElementById('exportPubKeyBtn').addEventListener('click', () => exportTextBox('pubKey', 'my-public-key.txt'));

  document.getElementById('togglePrivBtn').addEventListener('click', togglePriv);
  document.getElementById('copyPrivKeyBtn').addEventListener('click', () => copyBox('privKey'));
  document.getElementById('exportPrivKeyBtn').addEventListener('click', () => exportTextBox('privKey', 'my-private-key.txt', true));

  document.getElementById('copyPeerKeyBtn').addEventListener('click', () => copyBox('peerKey'));
  document.getElementById('pastePeerKeyBtn').addEventListener('click', () => pasteInputField('peerKey'));
  document.getElementById('exportPeerKeyBtn').addEventListener('click', () => exportTextBox('peerKey', 'peer-public-key.txt'));
  document.getElementById('importPeerKeyBtn').addEventListener('click', () => importIntoTextarea('peerKey'));
  document.getElementById('clearPeerKeyBtn').addEventListener('click', () => clearInputField('peerKey'));

  document.getElementById('deriveBtn').addEventListener('click', derive);
  document.getElementById('resetSessionBtn').addEventListener('click', resetSessionUI);

  document.getElementById('copyMsgBtn').addEventListener('click', () => copyBox('msg'));
  document.getElementById('pasteMsgBtn').addEventListener('click', () => pasteInputField('msg'));
  document.getElementById('exportMsgBtn').addEventListener('click', exportMsgBox);
  document.getElementById('importMsgBtn').addEventListener('click', importMsgBox);
  document.getElementById('clearMsgBtn').addEventListener('click', () => clearInputField('msg'));

  document.getElementById('encryptBtn').addEventListener('click', doEncrypt);

  document.getElementById('copyCipherOutBtn').addEventListener('click', () => copyBox('cipherOut'));
  document.getElementById('exportCipherOutBtn').addEventListener('click', () => exportTextBox('cipherOut', 'encrypted-message.bin'));

  document.getElementById('copyCipherInBtn').addEventListener('click', () => copyBox('cipherIn'));
  document.getElementById('pasteCipherInBtn').addEventListener('click', () => pasteInputField('cipherIn'));
  document.getElementById('exportCipherInBtn').addEventListener('click', () => exportTextBox('cipherIn', 'encrypted-message.bin'));
  document.getElementById('importCipherInBtn').addEventListener('click', () => importIntoTextarea('cipherIn'));
  document.getElementById('clearCipherInBtn').addEventListener('click', () => clearInputField('cipherIn'));

  document.getElementById('decryptBtn').addEventListener('click', doDecrypt);

  document.getElementById('copyPlainOutBtn').addEventListener('click', () => copyBox('plainOut'));
  document.getElementById('exportPlainOutBtn').addEventListener('click', exportPlainOut);
});

async function derive(){
  try {
    if(!kp){
      setStatus(STATUS_GENERATE_FIRST);
      return;
    }

    const raw = document.getElementById("peerKey").value.trim();
    if(!raw){
      setStatus(STATUS_PASTE_PEER_KEY);
      return;
    }
    const peerText = raw.replace(/\s+/g, "");

    let peerPubRaw;
    try {
      peerPubRaw = unb64(peerText);
      await importPub(peerPubRaw); // validates it's actually a usable EC public key
    } catch(e){
      setStatus(STATUS_INVALID_PEER_KEY);
      return;
    }

    if(compareBytes(myPubRaw, peerPubRaw) === 0){
      setStatus(STATUS_OWN_KEY);
      return;
    }

    session = await establishSession(kp, myPubRaw, peerPubRaw);
    peerPubRawCached = peerPubRaw;

    const sessFp = await sessionFingerprintOf(myPubRaw, peerPubRaw);
    document.getElementById("sessionFingerprint").textContent = sessFp;
    document.getElementById("sessionFingerprintField").classList.remove("hidden");
    await updatePeerFingerprint();

    setStatus(STATUS_SESSION_ESTABLISHED(!!session.CKs));
  } catch(e){
    if(DEBUG) console.error("DERIVE ERROR:", e.message);
    setStatus(STATUS_SESSION_FAILED);
  }
}

async function resetSessionUI(){
  if(!session){
    setStatus(STATUS_NOTHING_TO_RESET);
    return;
  }
  if(!await showConfirmWarning(
    document.getElementById("cipherOut"),
    CONFIRM_SESSION_RESET,
    BTN_RESET_SESSION,
    BTN_CANCEL
  )){
    return;
  }
  resetTransientState();
  setStatus(STATUS_SESSION_RESET);
}

/* ---------- Encrypt / Decrypt ---------- */
/* Both now report errors the same way: written into their own "console"
   output box (cipherOut / plainOut) with a ❌ prefix, rather than a
   popup alert() — consistent command-line-style feedback either way. */

async function doEncrypt(){
  const outEl = document.getElementById("cipherOut");
  if(!session){
    outEl.textContent = MSG_NO_SESSION;
    return;
  }

  let plaintextBytes;
  let extraHeader;
  const willBeLarge = pendingAttachment
    ? pendingAttachment.size > SPINNER_THRESHOLD
    : document.getElementById("msg").value.length > SPINNER_THRESHOLD;

  // --- streaming path: large file attachments ---
  if(pendingAttachment && pendingAttachment.size > STREAMING_ENCRYPT_THRESHOLD){
    const file = pendingAttachment.file;
    const filename = pendingAttachment.name.replace(/\.[^.]+$/, '') + '.scb';
    const canStreamToDisk = typeof showSaveFilePicker === 'function';
    const confirmMsg = canStreamToDisk
      ? CONFIRM_LARGE_ENCRYPT(formatBytes(file.size))
      : CONFIRM_LARGE_ENCRYPT(formatBytes(file.size)) + "\n\n" + MSG_STREAMING_UNAVAILABLE;
    if(!await showConfirmWarning(outEl, confirmMsg, BTN_CONTINUE, BTN_CANCEL)) return;

    try {
      Progress.show(PROGRESS_ENCRYPTING);
      const header = { file: { name: pendingAttachment.name, type: pendingAttachment.type } };

      if(canStreamToDisk){
        // Chrome/Edge: write directly to disk — zero extra memory.
        const handle = await showSaveFilePicker({ suggestedName: filename });
        const writable = await handle.createWritable();
        let size = 0;
        for await(const part of streamingEncryptExport(session, file, header, (f) => Progress.update(f, PROGRESS_ENCRYPTING))){
          await writable.write(part);
          size += part.byteLength;
        }
        await writable.close();
        lastEncryptedPacket = null;
        lastEncryptedPacketB64 = null;
        outEl.textContent = MSG_ENCRYPTED_LARGE(formatBytes(size));
      } else {
        // Firefox/Safari: stream into a Blob via Response, still buffers in memory
        // but avoids accumulating a parts[] array.
        let size = 0;
        const src = streamingEncryptExport(session, file, header, (f) => Progress.update(f, PROGRESS_ENCRYPTING));
        const stream = new ReadableStream({
          async start(ctrl){
            try {
              for await(const part of src){
                size += part.byteLength;
                ctrl.enqueue(part);
              }
              ctrl.close();
            } catch(e){ ctrl.error(e); }
          }
        });
        const blob = await new Response(stream).blob();
        lastEncryptedPacket = null;
        lastEncryptedPacketB64 = null;
        outEl.textContent = MSG_ENCRYPTED_LARGE(formatBytes(size));
        downloadBlob(blob, filename);
      }
    } catch(e){
      if(DEBUG) console.error('Streaming encryption failed:', e.message);
      outEl.textContent = MSG_ENCRYPT_FAILED;
    } finally {
      Progress.hide();
    }
    return;
  }

  // --- standard path: text messages and small file attachments ---
  if(willBeLarge) Progress.show(PROGRESS_READING);

  if(pendingAttachment){
    try {
      const file = pendingAttachment.file;
      const totalChunks = Math.ceil(file.size / FILE_READ_CHUNK);
      plaintextBytes = new Uint8Array(file.size);
      let offset = 0;
      for(let i = 0; i < totalChunks; i++){
        const end = Math.min(offset + FILE_READ_CHUNK, file.size);
        const chunkBuf = await file.slice(offset, end).arrayBuffer();
        plaintextBytes.set(new Uint8Array(chunkBuf), offset);
        offset = end;
        if(willBeLarge) Progress.update(i / totalChunks, PROGRESS_READING);
        await yieldToUI();
      }
    } catch(e){
      if(DEBUG) console.error('File read failed:', e.message);
      outEl.textContent = MSG_CANT_READ_FILE;
      if(willBeLarge) Progress.hide();
      return;
    }
    extraHeader = { file: { name: pendingAttachment.name, type: pendingAttachment.type } };
  } else {
    const msgText = document.getElementById("msg").value;
    if(!msgText){
      if(willBeLarge) Progress.hide();
      outEl.textContent = MSG_NOTHING_TO_ENCRYPT;
      return;
    }
    plaintextBytes = new TextEncoder().encode(msgText);
  }

  try {
    if(willBeLarge) Progress.show(PROGRESS_ENCRYPTING);
    const packet = await session.encrypt(
      plaintextBytes, extraHeader,
      willBeLarge ? (f) => Progress.update(f, PROGRESS_ENCRYPTING) : null
    );
    lastEncryptedPacket = packet;
    // Multi-chunk packets store Uint8Array cipher chunks which can't be
    // JSON-serialized; they're accessed via binary export only.
    lastEncryptedPacketB64 = Array.isArray(packet.chunkIvs)
      ? null
      : await encodeOpaquePacket(packet);

    if(plaintextBytes.length > DISPLAY_THRESHOLD){
      const approxCipherSize = estimateChunksByteLength(packet.dataChunks);
      outEl.textContent = MSG_ENCRYPTED_LARGE(formatBytes(approxCipherSize));
    } else {
      outEl.textContent = lastEncryptedPacketB64;
    }
  } catch(e){
    if(DEBUG) console.error('Encryption failed:', e.message);
    if(e.message && e.message.includes("no sending chain")){
      outEl.textContent = MSG_CANT_SEND_YET;
    } else {
      outEl.textContent = MSG_ENCRYPT_FAILED;
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
    if(willBeLarge) Progress.show(PROGRESS_DECRYPTING);
    const plainBytes = await session.decrypt(
      packet,
      willBeLarge ? (f) => Progress.update(f, PROGRESS_DECRYPTING) : null
    );
    const fileMeta = (packet.header && packet.header.file) ? packet.header.file : null;
    lastDecrypted = { bytes: plainBytes, fileMeta };

    if(fileMeta){
      outEl.textContent = MSG_DECRYPT_FILE_PROMPT(fileMeta.name, formatBytes(plainBytes.length));
    } else if(plainBytes.length > DISPLAY_THRESHOLD){
      outEl.textContent = MSG_DECRYPTED_LARGE(formatBytes(plainBytes.length));
    } else {
      outEl.textContent = MSG_DECRYPTED_PREFIX + new TextDecoder().decode(plainBytes);
    }
  } catch(e){
    if(DEBUG) console.error("DECRYPT ERROR:", e.message);
    lastDecrypted = null;
    let msg = MSG_DECRYPT_FAILED;
    if(e.message && e.message.includes("unrecognized packet")){
      msg += MSG_DECRYPT_BAD_FORMAT;
    } else if(e.message && e.message.includes("malformed header")){
      msg += MSG_DECRYPT_MISSING_FIELDS;
    } else if(e.message && e.message.includes("too many")){
      msg += e.message + ".";
    } else {
      msg += MSG_DECRYPT_CORRUPTED;
    }
    outEl.textContent = msg;
  } finally {
    if(willBeLarge) Progress.hide();
  }
}

async function doDecrypt(){
  const outEl = document.getElementById("plainOut");
  if(!session){
    outEl.textContent = MSG_NO_SESSION;
    return;
  }

  let packet = pendingDecryptPacket;
  if(!packet){
    try {
      packet = await decodeOpaquePacket(document.getElementById("cipherIn").value);
    } catch(e){
      outEl.textContent = MSG_INVALID_CIPHER;
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
  document.getElementById('msg').value = MSG_FILE_ATTACHED(file.name, formatBytes(file.size));
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
  if(!text){ showInlineMessage(document.getElementById("cipherOut"), MSG_NOTHING_TO_EXPORT); return; }
  downloadBlob(new Blob([text], { type: 'text/plain' }), 'message.txt');
}

/* ---------- plainOut box: export reconstructs the original file ---------- */

function exportPlainOut(){
  if(!lastDecrypted){
    showInlineMessage(document.getElementById("plainOut"), MSG_NOTHING_DECRYPTED);
    return;
  }
  if(lastDecrypted.fileMeta){
    downloadBlob(new Blob([lastDecrypted.bytes], { type: lastDecrypted.fileMeta.type || 'application/octet-stream' }), lastDecrypted.fileMeta.name);
  } else {
    downloadBlob(new Blob([lastDecrypted.bytes], { type: 'text/plain' }), 'decrypted-message.txt');
  }
}
