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
  const newRK = out.slice(0, 32);
  const newCKseed = out.slice(32, 64);
  secureClear(out);
  return { newRK, newCKseed };
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

var GCM_CHUNK_BYTES = 512 * 1024 * 1024; // 512 MB – well under the 2 GiB SubtleCrypto limit

async function deriveChunkIv(baseIv, chunkIndex){
  const ikm = await crypto.subtle.importKey("raw", baseIv, "HKDF", false, ["deriveBits"]);
  const derived = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0),
      info: new TextEncoder().encode("gcm-iv-" + chunkIndex) },
    ikm, 96
  ));
  return derived;
}
async function computeInitialSharedSecret(myPriv, peerPub){
  const raw = await dh(myPriv, peerPub);
  const ikm = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveBits"]);
  const out = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new TextEncoder().encode("dr-init-salt"), info: new TextEncoder().encode("dr-init-root") },
    ikm, 256
  ));
  secureClear(raw);
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
    secureClear(dhOut);
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

    const myPubRawLocal = await exportPub(this.DHs.publicKey);
    const header = Object.assign({ dh: b64(myPubRawLocal), pn: this.PN, n: this.Ns }, extraHeaderFields || {});
    this.Ns++;

    const baseIv = crypto.getRandomValues(new Uint8Array(12));
    const aad = new TextEncoder().encode(JSON.stringify(header));

    // Chunk plaintext into GCM_CHUNK_BYTES pieces so each
    // crypto.subtle.encrypt() call stays well under the 2 GiB limit.
    // Single-chunk packets use baseIv directly (full backward compat);
    // multi-chunk packets derive a unique IV per chunk via HKDF.
    // Each chunk advances the sending chain independently (matching
    // how the receiver's decrypt loop advances the receiving chain).
    const totalChunks = Math.max(1, Math.ceil(plaintextBytes.length / GCM_CHUNK_BYTES));
    const cipherChunks = [];
    const chunkIvs = [];

    for(let i = 0; i < totalChunks; i++){
      const { mkSeed, nextCK } = await kdfCK(this.CKs);
      this.CKs = nextCK;
      const aesKey = await deriveMessageAesKey(mkSeed);
      secureClear(mkSeed);

      const start = i * GCM_CHUNK_BYTES;
      const chunk = plaintextBytes.subarray(start, Math.min(start + GCM_CHUNK_BYTES, plaintextBytes.length));
      const chunkIv = totalChunks > 1 ? await deriveChunkIv(baseIv, i) : baseIv;
      const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv: chunkIv, additionalData: aad }, aesKey, chunk);
      secureClear(aesKey);
      cipherChunks.push(new Uint8Array(cipher));
      chunkIvs.push(b64(chunkIv));
      if(onProgress) onProgress((i + 1) / totalChunks);
      await yieldToUI();
    }

    // Single-chunk packets use the legacy monolithic dataChunks format
    // (full backward compat). Multi-chunk packets store each GCM chunk
    // as a raw Uint8Array so the b64() call (which uses
    // String.fromCharCode.apply) is never given a 512 MB+ array.
    let dataChunks;
    if(totalChunks === 1){
      dataChunks = await bytesToBase64Chunks(cipherChunks[0], onProgress);
    } else {
      dataChunks = cipherChunks; // Uint8Array[] — handled by decrypt & export
    }
    const packet = { v: 3, header, iv: b64(baseIv), dataChunks };
    if(totalChunks > 1) packet.chunkIvs = chunkIvs;
    return packet;
  }

  // Pure (non-mutating) chain skip-ahead used during a trial decrypt.
  async _skipToPure(ckr, nr, dhKeyB64, until){
    const staged = [];
    if(ckr == null) return { ckr, nr, staged };
    if(until - nr > MAX_SKIP) throw new Error("peer skipped too many messages at once");
    while(nr < until){
      const { mkSeed, nextCK } = await kdfCK(ckr);
      const aesKey = await deriveMessageAesKey(mkSeed);
      secureClear(mkSeed);
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
    if(dhRawIncoming.length < 80 || dhRawIncoming.length > 120){
      throw new Error("invalid public key length");
    }
    const skipKey = header.dh + ":" + header.n;
    const iv = unb64(packet.iv);
    if(iv.length !== 12){
      throw new Error("invalid iv length");
    }
    const aad = new TextEncoder().encode(JSON.stringify(header));

    // Determine which decrypt sub-path to use.
    // chunkIvs present → new chunked format (512 MB per-chunk AES-GCM)
    // otherwise        → legacy single-IV format (backward compatible)
    const useChunked = Array.isArray(packet.chunkIvs);

    let plainBuf;

    if(useChunked){
      // ---- chunked path: each chunk is an independent AES-GCM ciphertext ----
      const chunkIvs = packet.chunkIvs;
      const chunkCount = chunkIvs.length;
      const plainChunks = [];

      for(let i = 0; i < chunkCount; i++){
        const chunkIv = unb64(chunkIvs[i]);
        if(chunkIv.length !== 12) throw new Error("invalid chunk IV length");

        // Case 1a: key already cached from an earlier out-of-order skip.
        if(this.skipped.has(skipKey)){
          const aesKey = this.skipped.get(skipKey);
          const cipherChunk = packet.cipherBytes
            ? packet.cipherBytes.subarray(i * GCM_CHUNK_BYTES, Math.min((i + 1) * GCM_CHUNK_BYTES, packet.cipherBytes.length))
            : packet.dataChunks[i] instanceof Uint8Array
              ? packet.dataChunks[i]
              : unb64(packet.dataChunks[i]);
          plainChunks.push(new Uint8Array(await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: chunkIv, additionalData: aad }, aesKey, cipherChunk)));
          secureClear(aesKey);
          if(onProgress) onProgress((i + 1) / chunkCount);
          continue;
        }

        // Case 1b: compute tentative working copy.  For single-chunk
        // packets nothing touches `this` until the AES-GCM tag verifies.
        // For multi-chunk packets, ratchet state commits to `this` after
        // key derivation (lines ~341-357) before chunk decryption — see
        // inline comments there.
        let tDHs = this.DHs, tDHr = this.DHr, tDHrRaw = this.DHrRaw;
        let tRK = this.RK, tCKr = this.CKr;
        let tNs = this.Ns, tNr = this.Nr, tPN = this.PN;
        const stagedSkips = [];
        const isNewDHKey = !tDHrRaw || !bytesEqual(tDHrRaw, dhRawIncoming);
        let aesKey;

        if(isNewDHKey){
          const oldDhLabel = tDHrRaw ? b64(tDHrRaw) : "__none__";
          const skip1 = await this._skipToPure(tCKr, tNr, oldDhLabel, header.pn);
          tCKr = skip1.ckr; tNr = skip1.nr;
          stagedSkips.push(...skip1.staged);

          const newPeerPub = await importPub(dhRawIncoming);
          tPN = tNs; tNs = 0; tNr = 0;
          tDHr = newPeerPub; tDHrRaw = dhRawIncoming;

          const dhOut1 = await dh(tDHs.privateKey, tDHr);
          const step1 = await kdfRK(tRK, dhOut1);
          secureClear(dhOut1);
          tRK = step1.newRK; tCKr = step1.newCKseed;

          const oldDHs = tDHs;
          tDHs = await generateDHKeyPair();
          const dhOut2 = await dh(tDHs.privateKey, tDHr);
          const step2 = await kdfRK(tRK, dhOut2);
          secureClear(dhOut2);
          tRK = step2.newRK;
          const tCKs = step2.newCKseed;

          const skip2 = await this._skipToPure(tCKr, tNr, b64(tDHrRaw), header.n);
          tCKr = skip2.ckr; tNr = skip2.nr;
          stagedSkips.push(...skip2.staged);

          const { mkSeed, nextCK } = await kdfCK(tCKr);
          aesKey = await deriveMessageAesKey(mkSeed);
          secureClear(mkSeed);
          tCKr = nextCK;

          // Commit ratchet state after key derivation — first chunk must
          // succeed for any subsequent chunks to work.
          this.DHs = tDHs; this.DHr = tDHr; this.DHrRaw = tDHrRaw;
          this.RK = tRK; this.CKs = tCKs; this.CKr = tCKr;
          this.Ns = tNs; this.Nr = tNr + 1; this.PN = tPN;
          for(const s of stagedSkips) this.skipped.set(s.key, s.aesKey);
        } else {
          const skip = await this._skipToPure(tCKr, tNr, b64(tDHrRaw), header.n);
          tCKr = skip.ckr; tNr = skip.nr;
          stagedSkips.push(...skip.staged);

          const { mkSeed, nextCK } = await kdfCK(tCKr);
          aesKey = await deriveMessageAesKey(mkSeed);
          secureClear(mkSeed);
          tCKr = nextCK;

          this.CKr = tCKr;
          this.Nr = tNr + 1;
          for(const s of stagedSkips) this.skipped.set(s.key, s.aesKey);
        }

        // Decrypt this chunk — if the tag fails, an exception propagates
        // and the committed state above is already correct (it committed
        // the key derivation, not the plaintext).
        const cipherChunk = packet.cipherBytes
          ? packet.cipherBytes.subarray(i * GCM_CHUNK_BYTES, Math.min((i + 1) * GCM_CHUNK_BYTES, packet.cipherBytes.length))
          : packet.dataChunks[i] instanceof Uint8Array
            ? packet.dataChunks[i]
            : unb64(packet.dataChunks[i]);
        plainChunks.push(new Uint8Array(await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: chunkIv, additionalData: aad }, aesKey, cipherChunk)));
        secureClear(aesKey);
        if(this.skipped.has(skipKey)) this.skipped.delete(skipKey);
        if(onProgress) onProgress((i + 1) / chunkCount);
      }

      // Concatenate all decrypted chunks
      const totalLen = plainChunks.reduce((s, c) => s + c.length, 0);
      plainBuf = new Uint8Array(totalLen);
      let offset = 0;
      for(const c of plainChunks){ plainBuf.set(c, offset); offset += c.length; }

    } else {
      // ---- legacy path: single IV, single AES-GCM ciphertext ----
      const data = packet.cipherBytes
        ? packet.cipherBytes
        : packet.dataChunks[0] instanceof Uint8Array
          ? concatBytes(...packet.dataChunks)
          : await base64ChunksToBytes(packet.dataChunks, onProgress);

      if(this.skipped.has(skipKey)){
        const aesKey = this.skipped.get(skipKey);
        plainBuf = new Uint8Array(await crypto.subtle.decrypt(
          { name: "AES-GCM", iv, additionalData: aad }, aesKey, data));
        this.skipped.delete(skipKey);
        return plainBuf;
      }

      let tDHs = this.DHs, tDHr = this.DHr, tDHrRaw = this.DHrRaw;
      let tRK = this.RK, tCKr = this.CKr;
      let tNs = this.Ns, tNr = this.Nr, tPN = this.PN;
      const stagedSkips = [];
      const isNewDHKey = !tDHrRaw || !bytesEqual(tDHrRaw, dhRawIncoming);

      if(isNewDHKey){
        const oldDhLabel = tDHrRaw ? b64(tDHrRaw) : "__none__";
        const skip1 = await this._skipToPure(tCKr, tNr, oldDhLabel, header.pn);
        tCKr = skip1.ckr; tNr = skip1.nr;
        stagedSkips.push(...skip1.staged);

        const newPeerPub = await importPub(dhRawIncoming);
        tPN = tNs; tNs = 0; tNr = 0;
        tDHr = newPeerPub; tDHrRaw = dhRawIncoming;

        const dhOut1 = await dh(tDHs.privateKey, tDHr);
        const step1 = await kdfRK(tRK, dhOut1);
        secureClear(dhOut1);
        tRK = step1.newRK; tCKr = step1.newCKseed;

        const oldDHs = tDHs;
        tDHs = await generateDHKeyPair();
        const dhOut2 = await dh(tDHs.privateKey, tDHr);
        const step2 = await kdfRK(tRK, dhOut2);
        secureClear(dhOut2);
        tRK = step2.newRK;
        const tCKs = step2.newCKseed;

        const skip2 = await this._skipToPure(tCKr, tNr, b64(tDHrRaw), header.n);
        tCKr = skip2.ckr; tNr = skip2.nr;
        stagedSkips.push(...skip2.staged);

        const { mkSeed, nextCK } = await kdfCK(tCKr);
        const aesKey = await deriveMessageAesKey(mkSeed);
        secureClear(mkSeed);

        plainBuf = new Uint8Array(await crypto.subtle.decrypt(
          { name: "AES-GCM", iv, additionalData: aad }, aesKey, data));
        secureClear(aesKey);

        this.DHs = tDHs; this.DHr = tDHr; this.DHrRaw = tDHrRaw;
        this.RK = tRK; this.CKs = tCKs; this.CKr = nextCK;
        this.Ns = tNs; this.Nr = tNr + 1; this.PN = tPN;
        for(const s of stagedSkips) this.skipped.set(s.key, s.aesKey);
        return plainBuf;

      } else {
        const skip = await this._skipToPure(tCKr, tNr, b64(tDHrRaw), header.n);
        tCKr = skip.ckr; tNr = skip.nr;
        stagedSkips.push(...skip.staged);

        const { mkSeed, nextCK } = await kdfCK(tCKr);
        const aesKey = await deriveMessageAesKey(mkSeed);
        secureClear(mkSeed);

        plainBuf = new Uint8Array(await crypto.subtle.decrypt(
          { name: "AES-GCM", iv, additionalData: aad }, aesKey, data));
        secureClear(aesKey);

        this.CKr = nextCK;
        this.Nr = tNr + 1;
        for(const s of stagedSkips) this.skipped.set(s.key, s.aesKey);
        return plainBuf;
      }
    }

    return plainBuf;
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
