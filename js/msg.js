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

/* ---------- Inline messages (showInlineMessage) ---------- */

const MSG_CLIPBOARD_FAILED       = "⚠️ Could not read from clipboard. Please paste manually.";
const MSG_CLIPBOARD_WRITE_FAILED = "⚠️ Could not write to clipboard. Use Export below to save as a file instead.";
const MSG_NOTHING_TO_COPY        = "⚠️ Nothing here to copy yet";
const MSG_TOO_LARGE_TO_COPY      = "⚠️ This message is too large to copy to the clipboard. Use Export below to save it as a file instead.";
const MSG_NOTHING_DECRYPTED      = "⚠️ Nothing decrypted yet";
const MSG_FILE_USE_EXPORT        = "This decrypted content is a file — use Export below to save it, not Copy.";
const MSG_NOTHING_TO_EXPORT      = "⚠️ Nothing here to export yet";
const MSG_GENERATE_KEYS_FIRST    = "⚠️ Generate a key pair first";
const MSG_INVALID_IDENTITY_FILE  = "⚠️ That file doesn't look like a valid identity backup.";
const MSG_CANT_READ_PEER_KEY     = "⚠️ Can't read this as a key yet";
const MSG_PASTE_PEER_KEY_FIRST   = "Paste a peer key to see this";

/* ---------- Encrypt / Decrypt output messages ---------- */

const MSG_NO_SESSION             = "⚠️ No shared secret — set up a session first";
const MSG_CANT_READ_FILE         = "❌ Couldn't read the attached file (see console).";
const MSG_NOTHING_TO_ENCRYPT     = "⚠️ Nothing to encrypt — type a message or import a file first";
const MSG_ENCRYPTED_LARGE        = (size) => `🔒 Encrypted — approx. ${size}. Too large to display here. Use Export or Copy below.`;
const MSG_CANT_SEND_YET          = "⚠️ You can't send yet — your peer needs to send the first message in this session before you can reply. (Whoever's public key sorts first becomes the initiator and sends first.)";
const MSG_ENCRYPT_FAILED         = "❌ Encryption failed unexpectedly (see console).";
const MSG_DECRYPT_FILE_PROMPT    = (name, size) => `🔓 [File: ${name} — ${size}] Use Export below to save it.`;
const MSG_DECRYPTED_LARGE        = (size) => `🔓 Decrypted — ${size} of text. Too large to display here. Use Export or Copy below.`;
const MSG_DECRYPTED_PREFIX        = "🔓 ";
const MSG_DECRYPT_FAILED         = "❌ Couldn't decrypt this message — ";
const MSG_DECRYPT_BAD_FORMAT     = "it isn't in a format this tool recognizes (wrong version, or not from this tool at all).";
const MSG_DECRYPT_MISSING_FIELDS = "the message header is missing required fields.";
const MSG_DECRYPT_CORRUPTED      = "it may be corrupted, tampered with, encrypted for someone else, or already read.";
const MSG_INVALID_CIPHER         = "❌ That doesn't look like a valid encrypted message — check you copied the whole thing.";

/* ---------- Key generation / session status messages ---------- */

const STATUS_KEYS_GENERATED      = "✅ Keys generated. Awaiting peer...";
const STATUS_IDENTITY_RESTORED   = "✅ Identity restored. Awaiting peer...";
const STATUS_GENERATE_FIRST      = "⚠️ Generate your key pair first";
const STATUS_PASTE_PEER_KEY      = "⚠️ Paste a peer public key first";
const STATUS_INVALID_PEER_KEY    = "⚠️ That doesn't look like a valid public key — check for missing characters or extra text";
const STATUS_OWN_KEY             = "⚠️ That's your own public key, not a peer's — you need a key from the other person";
const STATUS_SESSION_ESTABLISHED = (canSend) => "🔐 Secure session established. You can " + (canSend ? "send right away." : "reply once your peer sends the first message.");
const STATUS_SESSION_FAILED      = "❌ Couldn't set up the session (see browser console for details). Double-check the pasted key and try again.";
const STATUS_NOTHING_TO_RESET    = "Nothing to reset — no session is active.";
const STATUS_SESSION_RESET       = "🔄 Session reset. Create a new shared secret to keep talking.";

/* ---------- Confirmation warning messages & button labels ---------- */

const CONFIRM_PRIVKEY_EXPOSURE   = (action) =>
  `⚠️ You're about to ${action} your PRIVATE key. ` +
  `Anyone who obtains it can read your messages and impersonate you. ` +
  `Only continue if you're sure of where it's going (or who's looking at your screen).`;
const CONFIRM_SESSION_RESET      = "This will end the current secure session. You won't be able to decrypt any messages from this conversation afterward (though your keys stay intact). Continue?";
const CONFIRM_KEY_REPLACEMENT    = "You already have a key pair. Generating a new one will replace it — any encrypted messages sent to you with the old key won't be decryptable anymore. Continue?";
const CONFIRM_LARGE_IMPORT       = (size) => `⚠️ File is ${size} — too large to import safely. The browser may crash or become unresponsive.`;
const CONFIRM_LARGE_ENCRYPT      = (size) => `⚠️ File is ${size}. Your browser will need roughly twice that much RAM to encrypt and download it. Continue?`;
const MSG_STREAMING_UNAVAILABLE  = "⚠️ Your browser doesn't support direct-to-disk saving. The encrypted file will be buffered in memory — may use a lot of RAM.";
const BTN_CONTINUE               = "✅ Continue";
const BTN_CANCEL                 = "❌ Cancel";
const BTN_IMPORT_ANYWAY          = "✅ Import anyway";
const BTN_RESET_SESSION          = "✅ Reset session";
const BTN_GENERATE_NEW_KEYS      = "✅ Generate new keys";

/* ---------- Progress labels ---------- */

const PROGRESS_WORKING           = "Working…";
const PROGRESS_READING           = "Reading file…";
const PROGRESS_ENCRYPTING        = "Encrypting…";
const PROGRESS_DECRYPTING        = "Decrypting…";

/* ---------- UI labels ---------- */

const LABEL_SHOW                 = "Show";
const LABEL_HIDE                 = "Hide";
const LABEL_THEME_DARK           = "🌙 Dark";
const LABEL_THEME_LIGHT          = "☀️ Light";
const MSG_FILE_ATTACHED          = (name, size) => `📎 Attached: ${name} (${size}) — click Encrypt to send it, or type here to replace it with text.`;

/* ---------- Import / file errors ---------- */

const MSG_WRONG_FORMAT_LARGE     = (size) =>
  `⚠️ This file is ${size} and isn't in this tool's format — ` +
  `it may fail to load. If it came from this tool's Export, that's unexpected; otherwise it wasn't meant for direct import this large.`;
const MSG_CANT_READ_CIPHER_FILE  = (name) => `❌ Couldn't read ${name} as an encrypted message (see console).`;
const MSG_CIPHER_IMPORTED        = (name, size) => `📎 Imported: ${name} (${size}) — click Decrypt to process it, or edit/paste here to replace it.`;
