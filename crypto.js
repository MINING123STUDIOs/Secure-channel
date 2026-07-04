let sodiumReady = false;

/**
 * Initialize libsodium safely
 */
async function initSodium() {
    if (sodiumReady) return;

    await sodium.ready;
    sodiumReady = true;
}

/**
 * -----------------------------
 * KEY PAIRS
 * -----------------------------
 */

export async function generateDHKXKeyPair() {
    await initSodium();

    const keypair = sodium.crypto_box_keypair();

    return {
        publicKey: sodium.to_base64(keypair.publicKey),
        privateKey: sodium.to_base64(keypair.privateKey),
    };
}

/**
 * -----------------------------
 * DHKX SHARED SECRET
 * -----------------------------
 */
export async function deriveSharedSecret(privateKeyB64, publicKeyB64) {
    await initSodium();

    const privateKey = sodium.from_base64(privateKeyB64);
    const publicKey = sodium.from_base64(publicKeyB64);

    const shared = sodium.crypto_scalarmult(privateKey, publicKey);

    // Derive symmetric key (32 bytes)
    const kdf = sodium.crypto_generichash(32, shared);

    return sodium.to_base64(kdf);
}

/**
 * -----------------------------
 * ENCRYPTION (XChaCha20-Poly1305)
 * -----------------------------
 */
export async function encryptMessage(keyB64, plaintext) {
    await initSodium();

    const key = sodium.from_base64(keyB64);
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        null,
        null,
        nonce,
        key
    );

    return {
        iv: sodium.to_base64(nonce),
        ciphertext: sodium.to_base64(ciphertext),
    };
}

/**
 * -----------------------------
 * DECRYPTION
 * -----------------------------
 */
export async function decryptMessage(keyB64, ivB64, ciphertextB64) {
    await initSodium();

    const key = sodium.from_base64(keyB64);
    const nonce = sodium.from_base64(ivB64);
    const ciphertext = sodium.from_base64(ciphertextB64);

    try {
        const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null,
            ciphertext,
            null,
            nonce,
            key
        );

        return sodium.to_string(plaintext);
    } catch (e) {
        throw new Error("Decryption failed (tampered or invalid key)");
    }
}

/**
 * -----------------------------
 * SIGNING (Ed25519)
 * -----------------------------
 */
export async function generateSigningKeyPair() {
    await initSodium();

    const kp = sodium.crypto_sign_keypair();

    return {
        publicKey: sodium.to_base64(kp.publicKey),
        privateKey: sodium.to_base64(kp.privateKey),
    };
}

export async function signMessage(privateKeyB64, message) {
    await initSodium();

    const sk = sodium.from_base64(privateKeyB64);
    const signature = sodium.crypto_sign_detached(message, sk);

    return sodium.to_base64(signature);
}

export async function verifySignature(publicKeyB64, message, signatureB64) {
    await initSodium();

    const pk = sodium.from_base64(publicKeyB64);
    const sig = sodium.from_base64(signatureB64);

    return sodium.crypto_sign_verify_detached(sig, message, pk);
}

/**
 * -----------------------------
 * HASHING
 * -----------------------------
 */
export async function hashSHA256(input) {
    await initSodium();
    const hash = sodium.crypto_hash_sha256(input);
    return sodium.to_hex(hash);
}

/**
 * -----------------------------
 * RANDOM
 * -----------------------------
 */
export async function randomBytes(n) {
    await initSodium();
    return sodium.to_hex(sodium.randombytes_buf(n));
} 
