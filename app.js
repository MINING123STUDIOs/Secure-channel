const cryptoAPI = window.cryptoAPI;

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

function $(id) {
    return document.getElementById(id);
}

function setText(id, value) {
    $(id).value = value;
}

/**
 * -----------------------------
 * KEY GEN
 * -----------------------------
 */
async function setupKeyGen() {
    $("generateKeys").onclick = async () => {
        const kp = await cryptoAPI.generateDHKXKeyPair();

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
        try {
            const priv = $("exchangePrivate").value.trim();
            const pub = $("exchangePublic").value.trim();

            const secret = await cryptoAPI.deriveSharedSecret(priv, pub);
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
        try {
            const key = $("aesEncryptKey").value.trim();
            const text = $("plaintext").value;

            const result = await cryptoAPI.encryptMessage(key, text);

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
        try {
            const key = $("aesDecryptKey").value.trim();
            const iv = $("decryptIV").value.trim();
            const ct = $("decryptCiphertext").value.trim();

            const result = await cryptoAPI.decryptMessage(key, iv, ct);
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
        signingKeyPair = await cryptoAPI.generateSigningKeyPair();
        alert("Signing keys generated (stored in memory for this session).");
    };

    $("signButton").onclick = async () => {
        if (!signingKeyPair) {
            alert("Generate signing keys first.");
            return;
        }

        const msg = $("signMessage").value;

        const sig = await cryptoAPI.signMessage(
            signingKeyPair.privateKey,
            msg
        );

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
            $("verifyResult").innerText =
                "No keypair loaded (generate signing keys first).";
            return;
        }

        const msg = $("verifyMessage").value;
        const sig = $("verifySignature").value;

        try {
            const ok = await cryptoAPI.verifySignature(
                signingKeyPair.publicKey,
                msg,
                sig
            );

            $("verifyResult").innerText = ok
                ? "✔ Signature valid"
                : "✖ Signature invalid";
        } catch (e) {
            $("verifyResult").innerText = "ERROR: " + e.message;
        }
    };
}

/**
 * -----------------------------
 * HASH
 * -----------------------------
 */
async function setupHash() {
    $("hashButton").onclick = async () => {
        const algo = $("hashAlgorithm").value;
        const input = $("hashInput").value;

        if (algo !== "SHA-256") {
            $("hashOutput").value = "Only SHA-256 implemented in this demo.";
            return;
        }

        const hash = await cryptoAPI.hashSHA256(input);
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

        try {
            const out = await cryptoAPI.randomBytes(n);
            $("randomOutput").value = out;
        } catch (e) {
            $("randomOutput").value = "ERROR: " + e.message;
        }
    };
}

/**
 * -----------------------------
 * INIT
 * -----------------------------
 */
window.addEventListener("load", async () => {
    setupTabs();

    setupKeyGen();
    setupExchange();
    setupEncrypt();
    setupDecrypt();
    setupSigning();
    setupVerify();
    setupHash();
    setupRandom();

    console.log("🔐 Secure Channel Assistant ready");
}); 
