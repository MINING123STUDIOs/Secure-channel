# Secure Channel Assistant — Development Standards

This project is a zero-dependency, client-side, security-sensitive tool.
Those three properties are the source of almost every rule below: there's
no build step to catch mistakes for you, no server to patch after the
fact, and a bug in the crypto path is a confidentiality bug, not a
cosmetic one. Read this before touching anything under `js/`.

---

## 1. Non-negotiables

These are the properties that make this tool what it is. Don't erode them
without an explicit, deliberate decision (and a note in `docs.md`):

- **Zero runtime dependencies.** No CDN scripts, no npm packages shipped to
  the browser, no build step required to open `index.html` and have it
  work. If a feature seems to need a library, look harder for a Web
  Platform API first (this codebase already does everything — ECDH,
  AES-GCM, HKDF, HMAC — with `crypto.subtle` alone).
- **Nothing phones home.** The tool must never make a network request on
  its own initiative (fetch, WebSocket, beacon, analytics, font CDN,
  anything). Encrypt/decrypt/export/import are all local. If you're ever
  tempted to add a "check for updates" or telemetry call, don't.
- **Nothing persists without the user explicitly exporting it.** No
  `localStorage`, `sessionStorage`, IndexedDB, or cookies for key material
  or session state, ever — the refresh-erases-everything model is a
  deliberate security property (a stolen/borrowed device can't leak past
  sessions), not an oversight. If a future feature needs persistence,
  it must be opt-in, clearly labeled, and never applied to private keys
  or session ratchet state by default.
- **The private key never leaves the device silently.** Every code path
  that copies, exports, or reveals the private key must continue to go
  through `confirmPrivateKeyExposure()` (or an equivalent explicit
  confirmation). Don't add a new export/copy/display path for the private
  key that skips it.
- **GPL-3.0 headers stay on every source file**, including any new ones.

---

## 2. Code style & structure

- **Plain functions and one class** (`RatchetSession`) — keep it that way.
  Don't introduce a framework, a module bundler, or a class hierarchy for
  what's currently a few dozen functions; it adds ceremony without adding
  clarity at this size.
- **Section comment banners** (`/* ---------- X ---------- */`) mark the
  regions within each file under `js/` (e.g. byte helpers and the envelope
  mask within `constants.js`, or low-level crypto vs. the ratchet class
  within `crypto-core.js`). Put new code in the right file and the right
  section within it, or add a new banner if it's genuinely a new concern —
  don't bury unrelated logic inside an existing section, and don't add a
  fifth top-level file without a clear reason (see §6 in `docs.md` for
  what belongs where and in what load order).
- **Constants at the top, not inline.** Any new size threshold, timeout,
  or limit belongs next to `CHUNK_BYTES` / `DISPLAY_THRESHOLD` /
  `SPINNER_THRESHOLD` etc., with a one-line comment explaining what
  crosses it and why. Never hardcode a magic number for one of these deep
  in a function.
- **Explain the *why*, not the *what*, in comments.** The existing style
  (see the file-top comment block in `constants.js`, or the note above
  `ENVELOPE_SEED`)
  explains the reasoning a future reader can't infer from the code alone
  — an engine limit, a security property, a bug that was caught and fixed.
  Keep doing that; don't add comments that just restate the line below
  them.
- **Async all the way down for anything touching bytes at scale.** Any
  loop that could run long on a large file must be `async` and `await`
  something that yields control back to the browser periodically (see
  `yieldToUI()`), the same way `bytesToBase64Chunks` does. A synchronous
  loop over tens of megabytes freezes the tab and makes the progress
  indicator lie.

---

## 3. Security-critical code standards

Anything touching `RatchetSession`, key derivation, or the packet format
gets extra scrutiny. Specifically:

- **`decrypt()` must stay transactional.** Compute into the tentative
  `t*` locals, verify the AES-GCM tag, *then* commit to `this`. This was a
  real bug that got caught during initial development — reintroducing it
  (e.g. by mutating `this.CKr` before the `crypto.subtle.decrypt` call
  succeeds) would let a single corrupted or malicious packet permanently
  desync a session. Any change to `decrypt()` should be re-verified against
  this property specifically.
- **The AAD (associated data) must exactly match what the sender
  authenticated.** `JSON.stringify(header)` is used as AAD on both sides;
  if you ever change how a header is constructed or serialized, both
  `encrypt()` and `decrypt()` must produce byte-identical serializations
  for the same logical header, including key order. This is why
  `encodeOpaquePacket`/`decodeOpaquePacket` (the outer obfuscation layer)
  operate on the *whole packet* rather than re-deriving `header` — they
  never touch the object that's fed into `JSON.stringify` for AAD purposes.
- **Never conflate the obfuscation layer with encryption.** `maskBytes` /
  `ENVELOPE_SEED` (see `docs.md` §3) is cosmetic camouflage, not a secret
  and not a security boundary — the keystream construction was strengthened
  for better avalanche/diffusion characteristics (no more short repeating
  XOR period), but that's still about not looking recognizable, not about
  resisting a real adversary. Don't let a future change start treating it
  as one (e.g. "we could skip real encryption for X since it's masked
  anyway" — no). Note `maskBytes` is `async` (it calls `crypto.subtle.digest`),
  so every call site must `await` it — `encodeOpaquePacket`,
  `decodeOpaquePacket`, and `buildLargeExportParts` are all `async` for
  exactly this reason.
- **Respect `MAX_SKIP` / `MAX_SKIPPED_KEYS`.** These bound how much work a
  malicious or buggy peer can force. If you add a new code path that walks
  the hash chain or caches message keys, it needs the same bounds.
- **No new cryptographic primitives without a strong reason.** The current
  set (ECDH P-256, HKDF-SHA256, HMAC-SHA256, AES-256-GCM) is deliberate and
  all available natively via `crypto.subtle`. Don't add a hand-rolled
  cipher, a non-constant-time comparison for secret material (`bytesEqual`
  is already constant-time-ish via OR-accumulation — keep that pattern for
  any new secret comparison), or a "simpler" KDF.
- **Don't log secret material.** `console.error(e)` on a caught exception
  is fine; logging a key, a derived AES key, or plaintext content is not.

---

## 4. Data format & versioning standards

- The packet's `v` field (currently `3`) exists so future format changes
  can be detected and rejected cleanly rather than silently misinterpreted.
  **Any breaking change to the packet shape must bump `v`**, and
  `decrypt()`'s format check (`packet.v !== 3`) must be updated to handle
  (or explicitly reject with a clear error) old versions.
- The large-file streaming format (`LARGE_FORMAT_MAGIC` + line-based
  fields) is a separate, parallel format from the in-memory packet — if you
  change the packet shape, update `buildLargeExportParts` /
  `streamingParseLargeFile` to match, and re-run the round-trip test (§5)
  for both the small and large paths.
- Changing `CHUNK_BYTES`, `IMPORT_WINDOW`, or any threshold is safe at any
  time (they're not part of the wire format), but changing anything that
  ends up inside the exported bytes (magic token, header shape, mask
  constant) is a breaking change for anyone who exported a message with the
  old version and imports it with the new one. Document breaking changes in
  `docs.md`.

---

## 5. UI & accessibility standards

- **Theme via CSS custom properties only.** Every color used in new UI
  must come from a `var(--...)` defined in both `:root` and
  `[data-theme="light"]` in `style.css` — never a hardcoded hex value —
  so it adapts automatically to both themes.
- **Respect `prefers-reduced-motion`** for any new animation, the way the
  progress ring does. Motion should be decorative, not load-bearing (a
  user with animations disabled should still be able to tell an operation
  is in progress from the label/percentage text).
- **Don't block the main thread on large input.** If you add a new
  operation that processes user-supplied bytes at scale, give it the same
  treatment as encrypt/decrypt: yield periodically, and show the
  `Progress` indicator above `SPINNER_THRESHOLD`.
- **Every private-key-revealing action needs a visible, honest warning**
  (see §1) — don't rely on the confirm dialog alone; the private key field
  itself should stay masked by default on every code path.

---

## 6. Testing procedures

There's no test framework or build step in this project, and that's fine
for its size — but that means testing is a discipline, not a `npm test`
away. Two layers are expected: automated logic tests (Node) and manual
browser QA (things Node can't see: real rendering, real file pickers, real
clipboard permissions).

### 6.1 Automated tests — Node + a stubbed DOM

Each file under `js/` is a classic (non-module) script that references
`document`, `window`, and/or `crypto.subtle` directly, so none of them can
be `require()`-d as-is. The recommended pattern (used to verify the
changes in this project so far) is:

1. Build a **minimal stub** for `document`/`window`/`navigator` — just
   enough that top-level side effects (the theme IIFE, the
   `beforeunload`/`DOMContentLoaded` listeners) don't throw. A fake element
   needs at minimum: `value`, `textContent`, `style.setProperty`, a
   `classList` with `add`/`remove`/`contains`, `appendChild`, and
   `addEventListener`.
2. Use Node's **global `crypto.subtle`** (Node 19+) directly — it
   implements the same algorithms (ECDH P-256, HKDF, HMAC, AES-GCM,
   SHA-256) the browser does, so the real crypto code runs unmodified.
   Also provide `btoa`/`atob`/`Blob`/`TextEncoder`/`TextDecoder`/`Buffer`
   in the sandbox.
3. Run the four `js/` files **concatenated, in load order (`constants.js`,
   `crypto-core.js`, `large-payload.js`, `ui.js`), together with test
   code**, through `vm.runInContext()` as a single script (not separate
   `vm.Script` runs per file) — this matters because each file uses
   top-level `let`/`const`/`function`, which are scoped to that one
   evaluation, the same way separate classic `<script>` tags in a real
   page share one global lexical scope only when they execute in that
   same order. Concatenating means the test code can call
   `RatchetSession`, `bytesToBase64Chunks`, `encodeOpaquePacket`, etc.
   directly, exactly as if it were a fifth `<script>` tag sharing the
   page's scope.
4. `crypto.getRandomValues()` caps at 65536 bytes per call in both the
   browser and Node — fill larger test buffers in a loop, not one call.
5. `maskBytes`, `encodeOpaquePacket`, `decodeOpaquePacket`, and
   `buildLargeExportParts` are all `async` (they call `crypto.subtle.digest`
   internally) — remember to `await` them in test code, same as production.

### 6.2 Required automated coverage before merging a crypto/format change

Treat these as a checklist, not a suggestion, for anything touching
`RatchetSession`, the packet format, or the large-file helpers:

- [ ] Basic encrypt → decrypt round trip (small message).
- [ ] At least one **reply**, to exercise the DH ratchet re-key
      (initiator encrypts, responder decrypts, responder encrypts back,
      initiator decrypts).
- [ ] **Out-of-order delivery**: encrypt messages N and N+1 in the same
      chain, decrypt N+1 first, then N — both must succeed, using the
      skipped-key cache.
- [ ] **Tamper detection**: flip a byte in the ciphertext, the iv, or the
      header of a valid packet and confirm `decrypt()` throws rather than
      returning garbage.
- [ ] **Large payload**: a plaintext spanning multiple `CHUNK_BYTES`
      chunks, round-tripped through `encrypt`/`decrypt`, verified
      byte-for-byte equal, with the `onProgress` callback firing once per
      chunk and reaching `1.0`.
- [ ] **Streaming large-file format**: build via `buildLargeExportParts`,
      parse via `streamingParseLargeFile`, confirm the reconstructed
      header/iv match exactly (this is the case most likely to silently
      break the AAD match — see §3) and that the reconstructed packet
      still decrypts.
- [ ] **Opaque codec round trip**: `encodeOpaquePacket` →
      `decodeOpaquePacket` reproduces the original packet exactly, and
      `decodeOpaquePacket` throws (doesn't silently return garbage) on
      non-base64 or non-JSON-after-unmasking input.
- [ ] **`maskBytes` is its own inverse** (masking twice returns the
      original bytes) whenever the mask constant or algorithm changes.

### 6.3 Manual / browser QA checklist

Things the Node harness fundamentally can't verify — do these in an actual
browser (ideally Chrome, Firefox, and Safari, since `Blob.slice`/`.text()`
and Web Crypto have had subtle behavioral differences historically) before
shipping a UI or large-file change:

- [ ] Generate keys, export identity, reload the page, import identity —
      session should be usable again.
- [ ] Full round trip with two browser tabs/profiles standing in for two
      people, including reading the session fingerprint match.
- [ ] Encrypt/decrypt a small text message — instant, no progress
      indicator.
- [ ] Encrypt/decrypt a file comfortably above `SPINNER_THRESHOLD` (a few
      MB) — progress indicator should appear, animate smoothly (tab stays
      responsive, you can still interact with other controls), and show a
      believable percentage.
- [ ] Encrypt/decrypt a file above `STREAMING_EXPORT_THRESHOLD` (~200MB,
      or temporarily lower the constant for testing) — Export should
      produce a `.scl` file via the streaming path, and importing it back
      should work via `streamingParseLargeFile`.
- [ ] Toggle light/dark theme with each of the above open — check the
      progress indicator, danger-red crossout icon, and all panels render
      correctly in both.
- [ ] Copy-to-clipboard and Export for both `cipherOut` and `plainOut`,
      including the size-limit warnings for clipboard on large content.
- [ ] Resize to a mobile-width viewport — the `.row` two-column layout
      should collapse to one column (`@media (max-width: 800px)`).
- [ ] With OS-level "reduce motion" enabled, confirm the progress
      indicator's spin/pulse animations are suppressed but the label/
      percentage text is still legible and updating.

### 6.4 Before opening a PR

- Run the full automated suite (§6.2) and the relevant parts of the manual
  checklist (§6.3) for whatever you touched.
- If you changed anything in §3 or §4 (security-critical code or the wire
  format), say so explicitly in the PR description, and call out which
  checklist items you re-verified.
- Update `docs.md` if the change affects behavior a user or future
  contributor would need to know about (a new threshold, a format change,
  a new security property or caveat).
