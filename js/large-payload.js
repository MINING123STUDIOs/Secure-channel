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

/* ---------- byte <-> base64 chunk helpers ----------
   Split raw bytes into base64 CHUNKS, each individually far under the
   engine's max string length, instead of one monolithic base64 string.
   Async so it can yield between chunks — for very large files this
   loop alone can take seconds, and without yielding the tab would
   freeze (and any progress indicator would freeze right along with it). */

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

/* ---------- large-payload export / import helpers ---------- */

// Builds an array of string PARTS (never concatenated into one JS
// string) describing a packet in a simple, streamable line format.
// Handed directly to `new Blob(parts)`, which does the concatenation
// at the Blob level — that's what avoids the engine's string-length
// ceiling for huge payloads.
async function buildLargeExportParts(packet){
  const parts = [];
  parts.push(LARGE_FORMAT_MAGIC + "\n");
  const headerBytes = new TextEncoder().encode(JSON.stringify(packet.header));
  parts.push(b64(await maskBytes(headerBytes)) + "\n");
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
        const headerBytes = await unmaskBytes(unb64(line));
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

  return { v: 3, header: headerObj, iv: ivStr, dataChunks: chunkBytesList };
}

/* ---------- binary large-payload export ---------- */

/**
 * Build the binary-export parts array from an already-encrypted packet.
 * This is the non-streaming path used by the legacy base64-chunked export.
 *
 * Binary layout (each field is concatenated in order):
 *   magic        4 bytes  – BIN_MAGIC_LARGE
 *   headerLen    4 bytes  – big-endian uint32
 *   header       variable – masked JSON header
 *   iv          12 bytes  – raw AES-GCM IV
 *   chunkCount   4 bytes  – big-endian uint32
 *   chunks       variable – for each chunk: length (4 bytes BE) + raw cipher bytes
 *
 * @param {object} packet – encrypted packet with .header, .iv, .dataChunks[]
 * @returns {Promise<Uint8Array[]>} ordered array of binary parts
 */
async function buildLargeExportPartsBinary(packet){
  const headerBytes = await maskBytes(new TextEncoder().encode(JSON.stringify(packet.header)));
  const ivBytes = unb64(packet.iv);
  const chunkCount = packet.dataChunks.length;

  // Build binary export parts array (all chunks held in memory until Blob is created)
  const parts = [];
  parts.push(new Uint8Array(BIN_MAGIC_LARGE));

  // header length (4 bytes big-endian) + masked header
  const headerLenBuf = new Uint8Array(4);
  new DataView(headerLenBuf.buffer).setUint32(0, headerBytes.length, false);
  parts.push(headerLenBuf);
  parts.push(headerBytes);

  // IV (12 bytes raw)
  parts.push(ivBytes);

  // chunk count (4 bytes big-endian)
  const countBuf = new Uint8Array(4);
  new DataView(countBuf.buffer).setUint32(0, chunkCount, false);
  parts.push(countBuf);

  // each chunk: length (4 bytes) + raw bytes
  for(const c of packet.dataChunks){
    const raw = c instanceof Uint8Array ? c : unb64(c);
    const lenBuf = new Uint8Array(4);
    new DataView(lenBuf.buffer).setUint32(0, raw.length, false);
    parts.push(lenBuf);
    parts.push(raw);
  }

  return parts;
}

/* ---------- binary large-payload import ---------- */

async function streamingParseLargeBinaryFile(blob, windowSize, onProgress){
  windowSize = windowSize || IMPORT_WINDOW;
  let offset = 0;
  let buf = new Uint8Array(0);

  function ensure(n){
    // Ensure buf has at least n bytes, reading more from the file if needed
    return (async () => {
      while(buf.length < n){
        if(offset >= blob.size) throw new Error("binary file ended unexpectedly");
        const slice = await blob.slice(offset, Math.min(offset + windowSize, blob.size)).arrayBuffer();
        offset += slice.byteLength;
        const newBuf = new Uint8Array(buf.length + slice.byteLength);
        newBuf.set(buf);
        newBuf.set(new Uint8Array(slice), buf.length);
        buf = newBuf;
        if(onProgress) onProgress(Math.min(offset, blob.size) / (blob.size || 1));
        await yieldToUI();
      }
    })();
  }

  function readU32(){
    const v = new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0, false);
    buf = buf.slice(4);
    return v;
  }

  function readBytes(n){
    const out = buf.slice(0, n);
    buf = buf.slice(n);
    return out;
  }

  // magic (already verified by caller, skip 4 bytes)
  await ensure(4);
  buf = buf.slice(4);

  // header
  await ensure(4);
  const headerLen = readU32();
  await ensure(headerLen);
  const maskedHeader = readBytes(headerLen);
  const headerObj = JSON.parse(new TextDecoder().decode(await unmaskBytes(maskedHeader)));

  // IV (12 bytes raw, encode to base64 for the packet)
  await ensure(12);
  const ivBytes = readBytes(12);
  const ivStr = b64(ivBytes);

  // chunk count
  await ensure(4);
  const chunkCount = readU32();

  // chunks
  const chunkBytesList = [];
  for(let i = 0; i < chunkCount; i++){
    await ensure(4);
    const chunkLen = readU32();
    await ensure(chunkLen);
    chunkBytesList.push(readBytes(chunkLen));
    if(onProgress) onProgress((i + 1) / chunkCount);
    await yieldToUI();
  }

  return { v: 3, header: headerObj, iv: ivStr, dataChunks: chunkBytesList };
}

/* ---------- streaming encrypt + export ----------
   Reads a File via File.slice(), encrypts each chunk immediately, and yields
   binary export parts incrementally.  Neither the full plaintext nor the full
   ciphertext is ever held in memory — peak RAM stays near GCM_CHUNK_BYTES + one
   cipher chunk (~512 MB + ~512 MB overhead, ~1 GB total). */

async function* streamingEncryptExport(session, file, extraHeader, onProgress){
  const chunkCount = Math.max(1, Math.ceil(file.size / GCM_CHUNK_BYTES));

  // --- header (compute once, reuse for every yielded part) ---
  const myPubRawLocal = await exportPub(session.DHs.publicKey);
  const header = Object.assign(
    { dh: b64(myPubRawLocal), pn: session.PN, n: session.Ns },
    extraHeader || {}
  );

  const baseIv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(JSON.stringify(header));
  const maskedHeader = await maskBytes(new TextEncoder().encode(JSON.stringify(header)));
  const ivBytes = unb64(b64(baseIv));

  // Yield: magic + header length + masked header + IV + chunk count
  yield new Uint8Array(BIN_MAGIC_LARGE);
  const headerLenBuf = new Uint8Array(4);
  new DataView(headerLenBuf.buffer).setUint32(0, maskedHeader.length, false);
  yield headerLenBuf;
  yield maskedHeader;
  yield ivBytes;
  const countBuf = new Uint8Array(4);
  new DataView(countBuf.buffer).setUint32(0, chunkCount, false);
  yield countBuf;

  // --- stream: read → encrypt → yield cipher chunk ---
  let offset = 0;
  let ckCursor = session.CKs;
  try{
    for(let i = 0; i < chunkCount; i++){
      const { mkSeed, nextCK } = await kdfCK(ckCursor);
      ckCursor = nextCK;
      const aesKey = await deriveMessageAesKey(mkSeed);
      secureClear(mkSeed);

      const end = Math.min(offset + GCM_CHUNK_BYTES, file.size);
      const plainBuf = await file.slice(offset, end).arrayBuffer();
      const chunk = new Uint8Array(plainBuf);
      offset = end;

      const chunkIv = chunkCount > 1 ? await deriveChunkIv(baseIv, i) : baseIv;
      const cipher = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: chunkIv, additionalData: aad },
        aesKey, chunk
      );
      secureClear(chunk);
      secureClear(aesKey);

      // Yield: chunk length (4 bytes) + raw cipher bytes
      const lenBuf = new Uint8Array(4);
      new DataView(lenBuf.buffer).setUint32(0, cipher.byteLength, false);
      yield lenBuf;
      yield new Uint8Array(cipher);

      if(onProgress) onProgress((i + 1) / chunkCount);
      await yieldToUI();
    }
    // Commit state only after all chunks succeed.
    session.CKs = ckCursor;
    session.Ns++;
  } catch(e){
    // On failure, state was never mutated — session remains consistent
    // at the pre-streaming snapshot.  Rethrow for the consumer.
    throw e;
  }
}
