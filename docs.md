# Secure Channel Assistant — Documentation

A single-page, client-side, end-to-end encrypted messaging tool. Everything —
key generation, key exchange, encryption, decryption — happens in your
browser. Nothing is sent anywhere by the tool itself; you copy/paste or
export the encrypted result to your contact through whatever channel you
already use (email, chat, a shared doc, anything).

Files: `index.html` (structure), `style.css` (styling, light/dark themes),
and five scripts under `js/` — `constants.js`, `msg.js`, `crypto-core.js`,
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
memory growth. When the cache is full, the oldest entries are evicted
(LRU) rather than rejecting new messages outright.

`decrypt()` enforces a rate limit of `DECRYPT_RATE_LIMIT` (2) decryption
attempts per second per session, measured via a sliding 1-second timestamp
window. This mitigates brute-force or timing-analysis attempts against the
AES-GCM tag.

Incoming packets are validated before processing: `header.dh` is checked for
valid base64 and correct length (80–120 bytes — SPKI format, ~91 bytes for P-256 public
key), `header.n` and `header.pn` must be non-negative integers, and
`packet.iv` must be valid base64 decoding to exactly 12 bytes.

### 2.3 Fingerprints

- **Your fingerprint** and **their fingerprint** (once you paste their key)
  are each a SHA-512 hash of that single public key, displayed as two lines:
  the first 256 bits on line 1, and the last 256 bits in `[brackets]` on
  line 2 (`fingerprintOf`).
- The **session fingerprint** is a SHA-512 hash of *both* raw public keys
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

Instead, `encodeOpaquePacket()` / `decodeOpaquePacket()` run the packet
bytes through `maskBytes()` / `unmaskBytes()`, then base64-encode/decode.
For file exports, `encodeOpaquePacketBinary()` / `decodeOpaquePacketBinary()`
produce/consume raw masked bytes (not base64), prefixed with a 4-byte magic
(`SCBN`), so exported files are compact binary blobs instead of ASCII text.
Clipboard copy/paste still uses the base64 text form.
Internally that's a single "layer" (XOR keystream + chained ARX mix)
applied **twice**, with a full bit-reversal of the buffer in between —
`maskBytesOnce → reverseBitOrder → maskBytesOnce → reverseBitOrder` —
and undone in exact reverse order by `unmaskBytes()`. What each piece does:

**The XOR sub-layer.** Against a pseudorandom keystream — this is what
breaks the `{"` / `eyJ` byte pattern. A short *repeating* XOR key (the
original approach) would leave a short repeating period in the output —
itself a giveaway via autocorrelation or a byte-frequency count — so the
keystream here has no such period (see "keystream generation" below).
Worth being precise about what this does *not* do: XOR has no diffusion,
regardless of how the keystream is generated — output byte *i* depends
on input byte *i* and nothing else.

**The ARX sub-layer.** A chained mixing pass applied on top of the XOR
output, 4 bytes at a time (`arxMixWords()`). Each word's transform folds
in an accumulator carried from the *previous* word's output, so changing
one word changes every word after it. Within a word: ordinary 32-bit
addition (`(word + acc + roundConstant) >>> 0`) provides genuine carry
propagation across bit positions, which XOR alone never has, and a
bitwise rotation by 1–31 bits spreads that across byte boundaries. The
trailing 0–3 bytes that don't form a full word are left XOR-only —
there's nothing after them to diffuse into.

**Why apply it twice.** That accumulator chain only carries *forward*:
within one pass, a change near the *end* of the buffer has zero effect
on bytes near the *start* — diffusion is one-directional. `maskBytes()`
fixes this by reversing the entire buffer's bit order (`reverseBitOrder()`
— the whole bit sequence, not just the bits within each byte, so byte
order flips too) between the two passes. Whatever was near the end for
pass 1 is near the start for pass 2, so the second pass mixes in the
other direction; the closing `reverseBitOrder()` restores the original
orientation. `reverseBitOrder()` is its own inverse (reversing twice
restores the input), so `unmaskBytes()` doesn't need a separate
"unreverse" — it just calls the same function again while undoing the
other steps in reverse order. The second pass derives its keystream and
round material from different domain tags than the first (see below), so
it isn't the same material re-applied to a permutation of its own output.

**Keystream generation.** Both sub-layers' pseudorandom material come
from `fillPseudorandomStream()`, which derives a 32-bit seed from the
public `ENVELOPE_SEED` (and, per pass, a distinct one-byte domain tag)
via one SHA-256 call, then expands it with mulberry32, a small fast
synchronous PRNG — not cryptographically secure, and not meant to be;
it's chosen for speed. The earlier version of this layer hashed every
32-byte block with SHA-256 directly, which for this tool's largest
supported export (~200MB) means millions of async
`crypto.subtle.digest` calls — measured in the tens of seconds. The
current version measures in the hundreds of milliseconds for a 20MB
payload in a real browser page (proportionally a couple of seconds at
200MB) for a *single* pass; since the two-pass construction above runs
that work twice plus two linear bit-reversal passes, budget roughly
double that end to end (isolated testing shows close to a 2x
multiplier; the bit-reversal passes themselves are cheap by comparison).

None of this is a secret: the seed is public, ships in this file, and
anyone with this source can regenerate the exact same streams. That's
expected and fine — it's cosmetic camouflage, not a security boundary.
The output is a single blob of base64-looking noise with no visible
braces, quotes, or field names. It's what you see in the **Encrypt**
output box and what gets copied to the clipboard. File Export writes
raw binary bytes (prefixed with a 4-byte magic signature) instead of
base64 text, for compactness.

> **Breaking change:** because the masking algorithm changed, a masked
> blob or `.scl` file exported before this change will not decode with
> the current code (and vice versa). This fails cleanly — `decodeOpaquePacket`
> and `streamingParseLargeFile` already treat any non-matching input as
> "not a valid encrypted message" rather than silently returning garbage —
> but old exports do need to be re-sent/re-encrypted with the current
> version.
>
> **Second breaking change (this revision):** `maskBytes`/`unmaskBytes`
> went from a single XOR+ARX pass to the two-pass-with-bit-reversal
> construction described above. Same consequence as the previous
> breaking change — anything masked with the one-pass version (including
> the previous revision's exports) won't decode with this version, and
> vice versa. Still fails cleanly rather than silently, for the same
> reason.

### 3.1.1 Diffusion characteristics (measured)

Verified with a standalone Node harness exercising `maskBytes`/
`unmaskBytes` directly (round trips, known-value checks on
`reverseBitOrder`, and bit-level avalanche comparisons — not part of the
in-browser test suite in dev.md §6, since it only needs `constants.js`):

- Flipping the *last* bit of a buffer changed **0 of 32 bits** in the
  first output word under the old single pass (confirming the
  forward-only limitation above), versus **roughly a third to half** of
  those 32 bits under the current two-pass construction.
- Across a whole 4096-byte buffer, flipping one input bit changes on the
  order of 40–50% of output bits — the range expected of a decent
  avalanche effect, though this is a cosmetic layer and no formal
  avalanche guarantee is being claimed.
- A constant-byte input (worst case for revealing a short period) showed
  no repeating period up to 64 bytes in the output.
- Round trips (`unmaskBytes(maskBytes(x)) === x`) were verified across
  buffer lengths from 0 to 500,000 bytes, including lengths not a
  multiple of 4, and separately at ~5MB.



### 3.2 Large-file streaming format

Files large enough to bypass in-memory JSON entirely (see §4) are exported
in a binary format instead. There are two parallel formats:

**Legacy text format (`.scl`):** A line-based text file with a fixed magic
token (`LARGE_FORMAT_MAGIC`), a masked+base64 header, base64 IV, chunk
count, and base64 ciphertext chunks. Still supported on import for
backward compatibility.

**Current binary format (`.scb`):** A compact binary file used for all new
exports. The structure is:

- 4-byte magic: `SCBN` (small, ≤200MB) or `SCBL` (large, >200MB)
- For small: raw masked bytes (same as §3.1 but without base64)
- For large: 4-byte header length + masked header bytes + 12-byte raw IV
  + 4-byte chunk count + per-chunk: 4-byte length + raw ciphertext bytes

Import auto-detects the format by reading the first 4 bytes. Clipboard
copy/paste always uses the base64 text form (`encodeOpaquePacket`/
`decodeOpaquePacket`), not the binary form.

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
   (200MB), Export bypasses `JSON.stringify` entirely: raw binary chunks are
   handed directly to `new Blob([...parts])`, which concatenates at the
   Blob level without ever forming one oversized JS string
   (`buildLargeExportPartsBinary`). Import mirrors this:
   `streamingParseLargeBinaryFile` reads the file in fixed windows via
   `File.slice()`, never via a whole-file `.text()` call. The legacy text
   `.scl` format (`buildLargeExportParts`/`streamingParseLargeFile`) is still
   supported on import for backward compatibility.
3. Separately, dumping many MB of text into a `<pre>`/`<textarea>` makes
   real browsers sluggish. Above `DISPLAY_THRESHOLD` (1MB), the UI shows a
   short summary instead ("Encrypted — approx. 42.1 MB..."), while the real
   packet lives in a JS variable (`lastEncryptedPacket` /
   `pendingDecryptPacket`) for Export/Copy to use directly.

| Threshold | Value | Meaning |
|---|---|---|
| `SPINNER_THRESHOLD` | 512 KB | Above this, the progress indicator appears for encrypt/decrypt/read/import. |
| `DISPLAY_THRESHOLD` | 1 MB | Above this, the UI shows a summary instead of the full text/ciphertext. |
| `STREAMING_EXPORT_THRESHOLD` | 200 MB | Above this, Export uses the binary streaming `.scb` format instead of one binary blob. |
| `LARGE_IMPORT_CONFIRM_THRESHOLD` | 300 MB | Above this, Import shows a confirmation warning before loading (may crash browser). |
| `CHUNK_BYTES` | 64 MB | Size of each raw chunk before base64-encoding. |
| `IMPORT_WINDOW` | 32 MB | Read window size when streaming-importing a large file. |
| `MAX_SKIP` | 1000 | Max out-of-order messages skippable in one jump. |
| `MAX_SKIPPED_KEYS` | 2000 | Max cached out-of-order message keys (LRU-evicted when full). |
| `DECRYPT_RATE_LIMIT` | 2 | Max decryption attempts per second per session. |

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
   is stored in a JavaScript variable (not the DOM) and shown behind a
   password field — click **Show** (with an inline confirmation) to reveal
   it temporarily, or **Copy**/**Export** it (also confirmed) using the
   JS variable directly. A new confirmation on the same output area cancels
   the previous one. If keys already exist, Generate Key Pair shows a
   confirmation warning before replacing them.
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
   encrypt/decrypt state without touching your identity keys (with an
   inline confirmation first).

Refreshing or closing the page erases everything (keys, session, all of
it) — there's no account and no cloud backup. Once you've generated keys,
the browser will also ask for confirmation before you navigate away, as a
safety net.

---

## 6. File-by-file reference

### `index.html`
Structure only: the info panel, the four numbered panels (Key Generation,
Shared Secret, Encrypt, Decrypt), and the footer. All interactivity is
wired via `addEventListener` bindings in `ui.js`, keeping the CSP free of
`'unsafe-inline'`. Includes a Content Security Policy meta tag restricting
scripts to `'self'` and blocking network requests, iframes, and plugins. Note that `cipherOut`,
`plainOut`, and `privKeyOut` are *result* boxes — they only
get Copy/Export controls (or inline confirmations), not Import, since
importing a file into an output space doesn't make sense. Only genuine
input fields (`peerKey`, `msg`, `cipherIn`, plus the identity-level
Import Identity) offer Import.

**Accessibility:** all form controls have `<label>` elements with
`for`/`id` associations. Dynamic output regions (`#status`, `#cipherOut`,
`#plainOut`, `#privKeyOut`, `#sessionFingerprintField`) carry
`aria-live="polite"` so screen readers announce content changes.
Fingerprint displays use `role="status"` with `aria-labelledby` pointing
to their descriptive `<div>`. Emoji-only buttons (theme toggle, eye icon)
have `aria-label` attributes. The page content is wrapped in a `<main>`
landmark.

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

- **`constants.js`** — thresholds (§4 table), `yieldToUI`, the envelope
  obfuscation layer (`maskBytes`/`unmaskBytes`/`maskBytesOnce`/
  `unmaskBytesOnce`/`reverseBitOrder`/`arxMixWords`/
  `fillPseudorandomStream`/`encodeOpaquePacket`/`decodeOpaquePacket`/`encodeOpaquePacketBinary`/`decodeOpaquePacketBinary`, §3.1),
  binary format magic constants (`BIN_MAGIC_SMALL`/`BIN_MAGIC_LARGE`),
  `secureClear()` for zeroing sensitive buffers, and base64/byte utilities
  (`b64`, `unb64`, `bytesEqual`, `compareBytes`, `concatBytes`).
  No dependencies on the other files.
- **`msg.js`** — all user-facing strings (error messages, status messages,
  confirmation warnings, button labels, progress labels) extracted into
  named constants. No dependencies on other files; loaded after
  `constants.js` but before `crypto-core.js`.
- **`crypto-core.js`** — `generateIdentityKeyPair`, `generateDHKeyPair`,
  `dh`, `kdfRK`, `kdfCK`, `deriveMessageAesKey`, `fingerprintOf`,
  `computeInitialSharedSecret`, and the `RatchetSession` class
  (`encrypt`/`decrypt`/`clear`) described in §2. Depends on `constants.js` for
  the byte helpers, `MAX_SKIP`/`MAX_SKIPPED_KEYS`, and `DECRYPT_RATE_LIMIT`.
- **`large-payload.js`** — `bytesToBase64Chunks`/`base64ChunksToBytes`,
  `buildLargeExportParts`/`streamingParseLargeFile` (legacy text `.scl` format),
  `buildLargeExportPartsBinary`/`streamingParseLargeBinaryFile` (current binary `.scb` format, §3.2, §4).
  Depends on `constants.js` (`yieldToUI`, `maskBytes`/`unmaskBytes`, thresholds,
  binary magic constants); does not depend on `crypto-core.js`.
- **`ui.js`** — session state (`kp`, `session`, `myPrivKeyB64`,
  `lastEncryptedPacketB64`), theme toggle, the
  `Progress` indicator module, status/copy/export/import helpers, key
  generation & identity import/export, the show/hide toggle, and the
  top-level `doEncrypt`/`doDecrypt` handlers that tie everything together.
  Depends on all four files above.

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

## Known Limitations (JavaScript)

These are inherent to the language — no workaround exists without changing
the runtime (e.g., moving to a native binary or WebAssembly module).

**1. `secureClear` may be optimized away (L1).**
V8 and SpiderMonkey can eliminate `.fill(0)` on buffers that are not
subsequently read (dead-store elimination). There is no `SecureZeroMemory`
equivalent in JavaScript. The zeroing is best-effort — it does the right
thing conceptually, but the compiler may remove it. CryptoKey objects
(returned by Web Crypto `deriveKey`) are opaque — `secureClear` cannot
touch their internal material at all; they are cleared only when the
garbage collector reclaims them (timing non-deterministic). The private
key is also held as an immutable JS string (`myPrivKeyB64`), which
cannot be zeroed at all (L3) — it persists in the heap until garbage
collected.

**2. `compareBytes` is not constant-time (L2).**
The function finds the first differing byte via a data-dependent branch.
This is only used for comparing public keys (which are public), never for
secret material, so the timing side-channel is not exploitable in current
usage. If future code needs byte comparison on secrets, use a
constant-time alternative (e.g., accumulate XOR differences in a register
and check at the end).

**3. Private key held as JS string (L3).**
JavaScript strings are immutable. When `myPrivKeyB64` is reassigned, the
old string remains in the heap until the garbage collector reclaims it.
The `b64()`/`unb64()` helpers also create intermediate binary strings
that cannot be zeroed. This is unavoidable in pure JS.

---

## License

GPL-3.0, per the header in `index.html`, `style.css`, and each file under
`js/`. See <https://www.gnu.org/licenses/> for the full text.
