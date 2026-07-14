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
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-512", rawBytes));
  const hex = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  const first = hex.slice(0, 64).match(/.{1,4}/g).join(' ').toUpperCase();
  const second = hex.slice(64).match(/.{1,4}/g).join(' ').toUpperCase();
  return ' ' + first + '\n[' + second + ']';
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
    this._decryptTimestamps = [];
  }

  clear(){
    this.DHs = null;
    this.DHr = null;
    this.DHrRaw = null;
    if(this.RK) secureClear(this.RK);
    if(this.CKs) secureClear(this.CKs);
    if(this.CKr) secureClear(this.CKr);
    this.RK = null;
    this.CKs = null;
    this.CKr = null;
    for(const [, key] of this.skipped) secureClear(key);
    this.skipped.clear();
    this.Ns = 0;
    this.Nr = 0;
    this.PN = 0;
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
      while(this.skipped.size + staged.length >= MAX_SKIPPED_KEYS){
        const oldest = this.skipped.keys().next().value;
        const oldKey = this.skipped.get(oldest);
        secureClear(oldKey);
        this.skipped.delete(oldest);
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
    const now = Date.now();
    this._decryptTimestamps = this._decryptTimestamps.filter(t => now - t < 1000);
    if(this._decryptTimestamps.length >= DECRYPT_RATE_LIMIT){
      throw new Error("decryption rate limit exceeded");
    }
    this._decryptTimestamps.push(now);
    if(!packet || packet.v !== 3 || !packet.header) throw new Error("unrecognized packet format");
    const header = packet.header;
    if(typeof header.dh !== "string" || typeof header.n !== "number" || typeof header.pn !== "number"){
      throw new Error("malformed header");
    }
    if(header.n < 0 || header.pn < 0 || !Number.isInteger(header.n) || !Number.isInteger(header.pn)){
      throw new Error("invalid header numbers");
    }
    if(header.dh.length > 200 || !/^[A-Za-z0-9+/=]+$/.test(header.dh)){
      throw new Error("invalid dh field");
    }
    if(!packet.iv || typeof packet.iv !== "string" || packet.iv.length > 50){
      throw new Error("invalid iv");
    }
    const dhRawIncoming = unb64(header.dh);
    if(dhRawIncoming.length !== 65){
      throw new Error("invalid public key length");
    }
    const skipKey = header.dh + ":" + header.n;
    const iv = unb64(packet.iv);
    if(iv.length !== 12){
      throw new Error("invalid iv length");
    }
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
