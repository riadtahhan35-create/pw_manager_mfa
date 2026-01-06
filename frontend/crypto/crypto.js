// frontend/crypto/crypto.js

window.SimpleCrypto = {
  generatePassword({ length, upper, lower, digits, symbols }) {
    const U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const L = "abcdefghijklmnopqrstuvwxyz";
    const D = "0123456789";
    const S = "!@#$%^&*()-_=+[]{}<>?";

    let pool = "";
    if (upper) pool += U;
    if (lower) pool += L;
    if (digits) pool += D;
    if (symbols) pool += S;

    if (!pool) return "";

    let out = "";
    const rand = crypto.getRandomValues(new Uint32Array(length));
    for (let i = 0; i < length; i++) {
      out += pool[rand[i] % pool.length];
    }
    return out;
  }
};
