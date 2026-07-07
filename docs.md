# Secure Channel Assistant — Documentation

A single-page, client-side, end-to-end encrypted messaging tool. Everything —
key generation, key exchange, encryption, decryption — happens in your
browser. Nothing is sent anywhere by the tool itself; you copy/paste or
export the encrypted result to your contact through whatever channel you
already use (email, chat, a shared doc, anything).

Files: `index.html` (structure), `style.css` (styling, light/dark themes),
and four scripts under `js/` — `constants.js`, `crypto-core.js`,
`large-payload.js`, `ui.js` — loaded in that order (all logic: crypto,
UI wiring, import/export). See §6 for what lives in each.

---

## 1. What it does, in one paragraph

Two people each generate a key pair here. They exchange **public** keys
(safe to share over any channel) and each pastes the other's into this tool
to derive a shared secret. From that point on, every message is encrypted
with a **Double Ratchet** — the same design Signal uses — so keys keep
changing automatically, message by message and reply by reply. If a single
message's key were ever exposed, it wouldn't expose any other message, past
or future.

---

## 2. Cryptographic design

### 2.1 Identity keys and the initial handshake

- Each person generates an **ECDH P-256** key pair (`generateIdentityKeyPair`).
  The public key is exported in SPKI format and shown as base64; the private
  key is exported in PKCS8 format and also shown as base64 (masked as a
  password field by default).
- To establish a session (`establishSession`), both sides compute an ECDH
  shared secret from *their own private key* and *the other's public key*,
  then run it through HKDF-SHA256 (`computeInitialSharedSecret`) with a fixed
  salt/info string to get the initial root key.
- **Who sends first?** Whoever's public key sorts lower (byte-for-byte,
  `compareBytes`) becomes the *initiator*: they immediately generate a fresh
  ephemeral DH key pair and are ready to send. The other side is the
  *responder*: they hold the root key but have no sending chain yet, so
  they must wait for the initiator's first message before they can reply
  (attempting to encrypt first raises `"no sending chain established yet"`,
  which the UI turns into a plain-English explanation).

### 2.2 The Double Ratchet (`RatchetSession`)

Two ratchets run on top of each other, matching the standard Signal design:

1. **DH ratchet** — every time the *sending* direction switches (i.e. you
   reply to a message that used a different DH key than the one you last
   saw), a brand-new ephemeral ECDH key pair is generated and mixed into the
   root key via HKDF (`kdfRK`). In an ordinary back-and-forth conversation
   this means a fresh ECDH computation on essentially every message.
2. **Symmetric-key (hash-chain) ratchet** — within a single sending chain,
   each message advances a one-way HMAC-SHA256 chain (`kdfCK`): one output
   becomes the next chain key, another seeds the actual AES key for *this*
   message (`deriveMessageAesKey`, itself another HKDF step). The chain key
   is discarded once used, so a compromised message key can't be used to
   recompute any other message's key — forward and (within a chain)
   backward secrecy.

Each encrypted packet carries a small **header** — the sender's current
ratchet public key (`dh`), the length of their previous sending chain
(`pn`), and the message's index in the current chain (`n`) — plus,
optionally, file metadata (`file: {name, type}`) for attachments. This
header is not encrypted, but it *is* authenticated: it's passed as AES-GCM
**associated data**, so tampering with the header alone (without touching
the ciphertext) still fails authentication.

`decrypt()` is written to be **transactional**: nothing about the session's
state (`RK`, `CKs`, `CKr`, counters, the skipped-key cache) is mutated until
the AES-GCM tag has actually verified. This matters because a naive
implementation that updates state *before* checking the tag can be
permanently desynchronized by a single corrupted or tampered packet —
bricking the whole conversation. Out-of-order messages are handled the same
way: skipped message keys are computed into a scratch map first and only
committed to the session after a successful decrypt (`_skipToPure`,
`skipped`).

Limits: up to `MAX_SKIP` (1000) messages can be skipped in one jump, and up
to `MAX_SKIPPED_KEYS` (2000) unread out-of-order keys are cached at once —
both are sanity limits against a malicious or buggy peer forcing unbounded
memory growth.

### 2.3 Fingerprints

- **Your fingerprint** and **their fingerprint** (once you paste their key)
  are each just a SHA-256 hash of that single public key, formatted as
  hex in 4-character groups (`fingerprintOf`).
- The **session fingerprint** is a SHA-256 hash of *both* raw public keys
  concatenated in a fixed (sorted) order, so it comes out identical on both
  ends (`sessionFingerprintOf`).
- Read the session fingerprint aloud to your contact over a channel you
  already trust (phone call, in person). If it matches on both screens,
  you're talking to them and not a person-in-the-middle who swapped a key
  in transit — pasting a public key alone doesn't prove who it came from.

### 2.4 What's *not* covered

This is a demo-grade implementation, not an audited protocol:

- No X3DH-style pre-key bundles — the initial handshake is a single static
  ECDH, so there's no protection if a long-term private key is later
  compromised *and* the initial exchange was recorded (no deniability
  properties are claimed either).
- Session state lives only in page memory. Refreshing or closing the tab
  erases keys and the session entirely (there's a `beforeunload` warning
  once you've generated keys, and an **Export Identity** button to back up
  your key pair first).
- No persistence, no accounts, no server component of any kind.

---

## 3. The two "obfuscation" layers (read this if you care about what the
   ciphertext looks like)

**Neither of these adds cryptographic security.** The actual protection is
entirely the ECDH/AES-GCM double ratchet described above. These two layers
exist purely so the transported text doesn't visually *announce itself* as
"an encrypted messenger payload" to a casual reader or a naive scanning
tool — closer to traffic camouflage than to encryption.

### 3.1 Outer envelope masking

Internally, an encrypted message is a plain object:
`{ v: 3, header: {...}, iv: "...", dataChunks: [...] }`. Naively
`JSON.stringify`-ing that (the old behavior) produces obviously-structured
JSON, and naively base64-encoding *that* produces the classic `"eyJ..."`
prefix that anyone who's seen a JWT recognizes on sight.

Instead, `encodeOpaquePacket()` / `decodeOpaquePacket()`:

1. `JSON.stringify` the packet (unchanged internally),
2. XOR every byte against a pseudorandom keystream (`maskBytes()` /
   `envelopeKeystream()`) — not a secret and not meant to be one; it
   exists only to break the recognizable `{"` / `eyJ` byte pattern,
3. base64-encode the result.

The keystream is generated by expanding a fixed public seed
(`ENVELOPE_SEED`) with SHA-256 in counter mode — block *i* is
`SHA-256(seed || i)` — rather than repeating a short fixed XOR key. This
is purely a camouflage-quality improvement, not a security one: a short
repeating key leaves a short repeating period in the output, which is
itself a giveaway (autocorrelation at the key length, or a byte-frequency
count, can reveal it). A SHA-256-derived stream has no such period, and
each block inherits SHA-256's avalanche property, so there's nothing
short-and-structural for a naive scanner — or a human eyeballing the
blob — to key off of. `maskBytes()` is still deterministic given only the
data's length, so masking twice still returns the original bytes.

The output is a single blob of base64-looking noise with no visible braces,
quotes, or field names. It's what you see in the **Encrypt** output box, what
gets copied to the clipboard, and what gets written to
`encrypted-message.bin` on Export. It's trivially reversible by anyone who
has this source file — that's expected; it's cosmetic, not a secret.

> **Breaking change:** because the keystream algorithm changed, a masked
> blob or `.scl` file exported before this change will not decode with
> the current code (and vice versa). This fails cleanly — `decodeOpaquePacket`
> and `streamingParseLargeFile` already treat any non-matching input as
> "not a valid encrypted message" rather than silently returning garbage —
> but old exports do need to be re-sent/re-encrypted with the current
> version.

### 3.2 Large-file streaming format

Files large enough to bypass in-memory JSON entirely (see §4) are written
line-by-line to a `.scl` file instead. That format now uses:

- a fixed, non-descriptive magic token (`LARGE_FORMAT_MAGIC`) instead of the
  old literal string `"SECURE-CHANNEL-LARGE-V1"`, and
- the header line masked and base64-encoded the same way as §3.1, instead of
  being raw, human-readable JSON.

The iv, chunk count, and ciphertext chunk lines are already base64 and
weren't changed — they didn't carry a recognizable signature to begin with.

---

## 4. Large-file / large-message handling

Two independent browser/engine limits drove this design, and both are
explained in the comment block at the top of `js/constants.js`:

1. **String length ceiling.** V8 (Chrome/Edge/Node) throws once a single
   string exceeds roughly 512M UTF-16 characters. A ~400MB file's base64
   form is already past that. So ciphertext is base64-encoded in fixed
   `CHUNK_BYTES` (64MB raw, ~85MB base64) pieces and kept as an array
   (`dataChunks`), never joined into one string.
2. **Chunking alone isn't enough** — `JSON.stringify()` on the whole packet
   still produces one final string. Above `STREAMING_EXPORT_THRESHOLD`
   (200MB), Export bypasses `JSON.stringify` entirely: chunk strings are
   handed directly to `new Blob([...parts])`, which concatenates at the
   Blob level without ever forming one oversized JS string
   (`buildLargeExportParts`). Import mirrors this: `streamingParseLargeFile`
   reads the file in fixed windows via `File.slice()`, never via a
   whole-file `.text()` call.
3. Separately, dumping many MB of text into a `<pre>`/`<textarea>` makes
   real browsers sluggish. Above `DISPLAY_THRESHOLD` (1MB), the UI shows a
   short summary instead ("Encrypted — approx. 42.1 MB..."), while the real
   packet lives in a JS variable (`lastEncryptedPacket` /
   `pendingDecryptPacket`) for Export/Copy to use directly.

| Threshold | Value | Meaning |
|---|---|---|
| `SPINNER_THRESHOLD` | 512 KB | Above this, the progress indicator appears for encrypt/decrypt/read/import. |
| `DISPLAY_THRESHOLD` | 1 MB | Above this, the UI shows a summary instead of the full text/ciphertext. |
| `STREAMING_EXPORT_THRESHOLD` | 200 MB | Above this, Export/Import use the line-based streaming `.scl` format instead of one JSON/base64 blob. |
| `CHUNK_BYTES` | 64 MB | Size of each raw chunk before base64-encoding. |
| `IMPORT_WINDOW` | 32 MB | Read window size when streaming-importing a large file. |
| `MAX_SKIP` | 1000 | Max out-of-order messages skippable in one jump. |
| `MAX_SKIPPED_KEYS` | 2000 | Max cached out-of-order message keys. |

### Progress indicator

For anything crossing `SPINNER_THRESHOLD`, a floating indicator (bottom
right) appears: a quick indeterminate spin while the work is starting,
switching to a determinate percentage once a step can actually report
progress (chunk N of M during base64 encode/decode, or bytes read during a
streamed file import). The base64 encode/decode loops (`bytesToBase64Chunks`,
`base64ChunksToBytes`) and the streaming file reader now `await` a
`yieldToUI()` between chunks specifically so the tab keeps painting — and
the indicator keeps animating — instead of freezing for the whole operation
on very large files.

---

## 5. Using the tool

1. **Generate Key Pair.** Creates your identity key pair. Your public key
   (safe to share) and its fingerprint appear immediately; your private key
   is hidden behind a password field — click **Show** (with a confirmation
   prompt) to reveal it, or **Copy**/**Export** it (also confirmed).
2. **Share only your public key** with your contact, and paste theirs into
   **Peer's public key**. Both of you do this once.
3. **Create Shared Secret.** Derives the session. The status line and the
   **Session Fingerprint** field update once it succeeds. Read the session
   fingerprint aloud to your contact over a trusted channel to confirm
   you're really talking to each other.
4. **Encrypt.** Type a message, or **Import file** to attach any file
   instead (text, image, anything). Click **Encrypt**. Copy or Export the
   result to send to your contact through any channel you like — this tool
   never sends anything itself.
5. **Decrypt.** Paste (or **Import**) what your contact sent you, click
   **Decrypt**. Plain text appears inline; a decrypted file prompts you to
   **Export** it (which restores the original filename/type) rather than
   copy it.
6. **Export Identity / Import Identity**, at any time, to back up or
   restore your key pair as a small JSON file — this is the only way to
   pick a conversation back up after refreshing the page, since nothing
   else is persisted.
7. **Reset Session** clears the current shared secret and any pending
   encrypt/decrypt state without touching your identity keys.

Refreshing or closing the page erases everything (keys, session, all of
it) — there's no account and no cloud backup. Once you've generated keys,
the browser will also ask for confirmation before you navigate away, as a
safety net.

---

## 6. File-by-file reference

### `index.html`
Structure only: the info panel, the four numbered panels (Key Generation,
Shared Secret, Encrypt, Decrypt), and the footer. All interactivity is
wired via `onclick` handlers calling into the `js/` scripts. Note that
`cipherOut` and `plainOut` are *result* boxes — they only get Copy/Export
controls, not Import, since importing a file into an output space doesn't
make sense. Only genuine input fields (`peerKey`, `msg`, `cipherIn`, plus
the identity-level Import Identity) offer Import.

### `style.css`
CSS custom properties (`:root` / `[data-theme="light"]`) drive both the
dark and light themes — everything from panel backgrounds to the danger/
accent colors is a variable, so new UI (like the progress indicator) picks
up the correct theme automatically. Notable pieces:
- `.eye-icon` / `.eye-icon.crossed` — the private-key show/hide toggle's
  diagonal strike-through, in `var(--danger)` (red in both themes).
- `#progressOverlay` / `.progress-ring` — the floating progress indicator;
  a conic-gradient ring masked into a donut shape, with a soft glow
  (`filter: drop-shadow`) and pulse animation, respecting
  `prefers-reduced-motion`.

### `js/` (loaded in this order — later files depend on earlier ones)

Split out of what used to be one `script.js`, along the same four regions
that file was already organized into internally:

- **`constants.js`** — thresholds (§4 table), `yieldToUI`,
  `maskBytes`/`envelopeKeystream`/`encodeOpaquePacket`/`decodeOpaquePacket`
  (§3.1), and base64/byte utilities (`b64`, `unb64`, `bytesEqual`,
  `compareBytes`, `concatBytes`). No dependencies on the other three files.
- **`crypto-core.js`** — `generateIdentityKeyPair`, `generateDHKeyPair`,
  `dh`, `kdfRK`, `kdfCK`, `deriveMessageAesKey`, `fingerprintOf`,
  `computeInitialSharedSecret`, and the `RatchetSession` class
  (`encrypt`/`decrypt`) described in §2. Depends on `constants.js` for the
  byte helpers and `MAX_SKIP`/`MAX_SKIPPED_KEYS`.
- **`large-payload.js`** — `bytesToBase64Chunks`/`base64ChunksToBytes`,
  `buildLargeExportParts`/`streamingParseLargeFile` (§3.2, §4). Depends on
  `constants.js` (`yieldToUI`, `maskBytes`, thresholds); does not depend
  on `crypto-core.js`.
- **`ui.js`** — session state (`kp`, `session`, etc.), theme toggle, the
  `Progress` indicator module, status/copy/export/import helpers, key
  generation & identity import/export, the show/hide toggle, and the
  top-level `doEncrypt`/`doDecrypt` handlers that tie everything together.
  Depends on all three files above.

These are loaded as plain classic `<script>` tags (no bundler, no
`type="module"`), so — same as one big file — they share a single global
scope; a `let`/`const`/`function` declared in an earlier file is visible
to a later one, but not the reverse. That's why the load order in
`index.html` matters and mirrors the dependency order above.

---

## 7. Threat model summary

**Protects against:** a passive eavesdropper on whatever channel you use to
relay the encrypted blob (email, chat, etc.); a single message key being
exposed without exposing past/future messages; silent tampering with a
message or its header; casual visual recognition of the blob as "an
encrypted message" (§3, cosmetic only).

**Does not protect against:** someone with access to your device while keys
are in memory; a person-in-the-middle who swaps public keys in transit *and
you skip verifying the session fingerprint out-of-band*; loss of your
private key (no recovery — that's what Export Identity is for); an attacker
who has this source code and therefore knows `ENVELOPE_SEED` (§3.1 is not a
secret); formal cryptographic audit (this hasn't had one).

---

## License

GPL-3.0, per the header in `index.html`, `style.css`, and each file under
`js/`. See <https://www.gnu.org/licenses/> for the full text.
