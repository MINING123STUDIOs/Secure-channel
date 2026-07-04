let sodiumReady = false;

async function initSodium() {
    if (!sodiumReady) {
        await sodium.ready;
        sodiumReady = true;
    }
}

async function generateDHKXKeyPair() {
    await initSodium();
    const kp = sodium.crypto_box_keypair();

    return {
        publicKey: sodium.to_base64(kp.publicKey),
        privateKey: sodium.to_base64(kp.privateKey),
    };
}

async function deriveSharedSecret(privateKeyB64, publicKeyB64) {
    await initSodium();

    const sk = sodium.from_base64(privateKeyB64);
    const pk = sodium.from_base64(publicKeyB64);

    const shared = sodium.crypto_scalarmult(sk, pk);
    return sodium.to_base64(
        sodium.crypto_generichash(32, shared)
    );
}

async function encryptMessage(keyB64, plaintext) {
    await initSodium();

    const key = sodium.from_base64(keyB64);
    const nonce = sodium.randombytes_buf(
        sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    );

    const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        null,
        null,
        nonce,
        key
    );

    return {
        iv: sodium.to_base64(nonce),
        ciphertext: sodium.to_base64(ct),
    };
}

async function decryptMessage(keyB64, ivB64, ctB64) {
    await initSodium();

    const key = sodium.from_base64(keyB64);
    const nonce = sodium.from_base64(ivB64);
    const ct = sodium.from_base64(ctB64);

    const pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ct,
        null,
        nonce,
        key
    );

    return sodium.to_string(pt);
}

async function generateSigningKeyPair() {
    await initSodium();
    const kp = sodium.crypto_sign_keypair();

    return {
        publicKey: sodium.to_base64(kp.publicKey),
        privateKey: sodium.to_base64(kp.privateKey),
    };
}

async function signMessage(skB64, msg) {
    await initSodium();

    const sk = sodium.from_base64(skB64);
    return sodium.to_base64(
        sodium.crypto_sign_detached(msg, sk)
    );
}

async function verifySignature(pkB64, msg, sigB64) {
    await initSodium();

    return sodium.crypto_sign_verify_detached(
        sodium.from_base64(sigB64),
        msg,
        sodium.from_base64(pkB64)
    );
}

async function hashSHA256(input) {
    await initSodium();
    return sodium.to_hex(sodium.crypto_hash_sha256(input));
}

async function randomBytes(n) {
    await initSodium();
    return sodium.to_hex(sodium.randombytes_buf(n));
} 
