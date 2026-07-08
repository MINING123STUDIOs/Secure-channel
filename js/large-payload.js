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

  const total = chunkBytesList.reduce((s, c) => s + c.length, 0);
  const cipherBytes = new Uint8Array(total);
  let off = 0;
  for(const c of chunkBytesList){ cipherBytes.set(c, off); off += c.length; }

  return { v: 3, header: headerObj, iv: ivStr, cipherBytes };
}
