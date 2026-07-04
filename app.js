import {
    generateDHKXKeyPair,
    deriveSharedSecret,
    encryptMessage,
    decryptMessage,
    generateSigningKeyPair,
    signMessage,
    verifySignature,
    hashSHA256,
    randomBytes
} from "./crypto.js";

/**
 * -----------------------------
 * TAB HANDLING
 * -----------------------------
 */
function setupTabs() {
    const buttons = document.querySelectorAll("nav button");
    const tabs = document.querySelectorAll(".tab");

    buttons.forEach(btn => {
        btn.addEventListener("click", () => {
            const target = btn.dataset.tab;

            tabs.forEach(t => t.classList.remove("active"));
            document.getElementById(target).classList.add("active");
        });
    });
}

/**
 * -----------------------------
 * HELPERS
 * -----------------------------
 */
function $(id) {
    return document.getElementById(id);
}

function setText(id, value) {
    $(id).value = value;
}

/**
 * -----------------------------
 * KEY GENERATION (ECDH / X25519)
 * -----------------------------
 */
async function setupKeyGen() {
    $("generateKeys").onclick = async () => {
        const kp = await generateDHKXKeyPair();

        setText("publicKey", kp.publicKey);
        setText("privateKey", kp.privateKey);
    };
}

/**
 * -----------------------------
 * SHARED SECRET
 * -----------------------------
 */
async function setupExchange() {
    $("deriveSecret").onclick = async () => {
        const priv = $("exchangePrivate").value;
        const pub = $("exchangePublic").value;

        try {
            const secret = await deriveSharedSecret(priv, pub);
            setText("sharedSecret", secret);
        } catch (e) {
            setText("sharedSecret", "ERROR: " + e.message);
        }
    };
}

/**
 * -----------------------------
 * ENCRYPT
 * -----------------------------
 */
async function setupEncrypt() {
    $("encryptButton").onclick = async () => {
        const key = $("aesEncryptKey").value;
        const text = $("plaintext").value;

        try {
            const result = await encryptMessage(key, text);

            setText("ivOutput", result.iv);
            setText("ciphertext", result.ciphertext);
        } catch (e) {
            setText("ciphertext", "ERROR: " + e.message);
        }
    };
}

/**
 * -----------------------------
 * DECRYPT
 * -----------------------------
 */
async function setupDecrypt() {
    $("decryptButton").onclick = async () => {
        const key = $("aesDecryptKey").value;
        const iv = $("decryptIV").value;
        const ct = $("decryptCiphertext").value;

        try {
            const result = await decryptMessage(key, iv, ct);
            setText("decryptedText", result);
        } catch (e) {
            setText("decryptedText", "ERROR: " + e.message);
        }
    };
}

/**
 * -----------------------------
 * SIGNING
 * -----------------------------
 */
let signingKeyPair = null;

async function setupSigning() {
    $("generateSignKeys").onclick = async () => {
        signingKeyPair = await generateSigningKeyPair();
        alert("Signing keys generated (stored in memory for this session).");
    };

    $("signButton").onclick = async () => {
        if (!signingKeyPair) {
            alert("Generate signing keys first.");
            return;
        }

        const msg = $("signMessage").value;
        const sig = await signMessage(signingKeyPair.privateKey, msg);

        setText("signature", sig);
    };
}

/**
 * -----------------------------
 * VERIFY
 * -----------------------------
 */
async function setupVerify() {
    $("verifyButton").onclick = async () => {
        if (!signingKeyPair) {
            $("verifyResult").innerText = "No public key available (generate signing keys first).";
            return;
        }

        const msg = $("verifyMessage").value;
        const sig = $("verifySignature").value;

        const ok = await verifySignature(
            signingKeyPair.publicKey,
            msg,
            sig
        );

        $("verifyResult").innerText = ok
            ? "✔ Signature valid"
            : "✖ Signature invalid";
    };
}

/**
 * -----------------------------
 * HASHING
 * -----------------------------
 */
async function setupHash() {
    $("hashButton").onclick = async () => {
        const algo = $("hashAlgorithm").value;
        const input = $("hashInput").value;

        if (algo !== "SHA-256") {
            $("hashOutput").value = "Only SHA-256 wired in demo (libsodium limitation).";
            return;
        }

        const hash = await hashSHA256(input);
        $("hashOutput").value = hash;
    };
}

/**
 * -----------------------------
 * RANDOM
 * -----------------------------
 */
async function setupRandom() {
    $("randomButton").onclick = async () => {
        const n = parseInt($("randomLength").value, 10);
        const out = await randomBytes(n);
        $("randomOutput").value = out;
    };
}

/**
 * -----------------------------
 * INIT
 * -----------------------------
 */
window.addEventListener("load", async () => {
    setupTabs();

    await setupKeyGen();
    await setupExchange();
    await setupEncrypt();
    await setupDecrypt();
    await setupSigning();
    await setupVerify();
    await setupHash();
    await setupRandom();

    console.log("Secure Channel Assistant ready 🔐");
}); 
