// frontend/crypto/vault_crypto.js
(function () {
  "use strict";

  function requireFace() {
    if (!window.Face) throw new Error("Face.js not loaded. Ensure /frontend/mfa/face/face.js is included BEFORE vault_crypto.js");
  }

  function isProbablyEncrypted(b64) {
    try {
      const raw = Uint8Array.from(atob(String(b64 || "")), (c) => c.charCodeAt(0));
      return raw.length >= 13; // 12 iv + >=1 cipher
    } catch {
      return false;
    }
  }

  async function getDekKey(usages) {
    requireFace();
    const username = sessionStorage.getItem("username");
    const password = sessionStorage.getItem("password_tmp");
    if (!username || !password) throw new Error("Missing login session (username/password_tmp). Please login again.");

    const dekU8 = await window.Face.getDekFromServerBundle(username, password);
    return await window.Face.importAesKeyRaw(dekU8, usages);
  }

  async function encryptSecret(plain) {
    requireFace();
    const key = await getDekKey(["encrypt"]);
    const u8 = new TextEncoder().encode(String(plain ?? ""));
    const enc = await window.Face.aesGcmEncryptRaw(key, u8);
    if (!isProbablyEncrypted(enc)) throw new Error("Encryption failed (invalid AES-GCM payload).");
    return enc;
  }

  async function decryptSecret(enc_b64) {
    requireFace();
    if (!isProbablyEncrypted(enc_b64)) throw new Error("secret_enc is not encrypted (invalid AES-GCM base64).");
    const key = await getDekKey(["decrypt"]);
    const u8 = await window.Face.aesGcmDecryptRaw(key, enc_b64);
    return new TextDecoder().decode(u8);
  }

  window.VaultCrypto = { isProbablyEncrypted, getDekKey, encryptSecret, decryptSecret };
})();
