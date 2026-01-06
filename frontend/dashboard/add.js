// frontend/dashboard/add.js
const $ = (id) => document.getElementById(id);

const statusEl = $("status");
const siteEl = $("site");
const userEl = $("siteUsername");
const secretEl = $("secret");

const btnSave = $("btnSave");
const btnBack = $("btnBack");
const btnGen = $("btnGen");
const btnToggle = $("btnToggle");

function setStatus(msg, type = "") {
  statusEl.className = "status " + (type || "");
  statusEl.textContent = msg || "";
}

function mustSession(key, msg) {
  const v = sessionStorage.getItem(key);
  if (!v) throw new Error(msg);
  return v;
}

function randomChar(set) {
  const u8 = new Uint32Array(1);
  crypto.getRandomValues(u8);
  return set[u8[0] % set.length];
}

function generatePassword(len, opt) {
  let pool = "";
  const U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const L = "abcdefghijklmnopqrstuvwxyz";
  const D = "0123456789";
  const S = "!@#$%^&*()-_=+[]{};:,.?/|~";

  if (opt.upper) pool += U;
  if (opt.lower) pool += L;
  if (opt.digits) pool += D;
  if (opt.symbols) pool += S;
  if (!pool) throw new Error("Select at least one character set.");

  const out = [];
  if (opt.upper) out.push(randomChar(U));
  if (opt.lower) out.push(randomChar(L));
  if (opt.digits) out.push(randomChar(D));
  if (opt.symbols) out.push(randomChar(S));

  while (out.length < len) out.push(randomChar(pool));

  for (let i = out.length - 1; i > 0; i--) {
    const r = new Uint32Array(1);
    crypto.getRandomValues(r);
    const j = r[0] % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join("");
}

async function apiAddVault(username, payload) {
  const r = await fetch(`/vault/add?username=${encodeURIComponent(username)}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.detail || "Failed to add vault item");
  return d;
}

document.addEventListener("DOMContentLoaded", () => {
  // Session guard
  try {
    mustSession("username", "Session expired. Please login again.");
    mustSession("password_tmp", "Session expired. Please login again.");
  } catch (e) {
    setStatus(e.message, "err");
    setTimeout(() => (window.location.href = "/frontend/auth/login/index.html"), 800);
    return;
  }

  // length UI
  const len = $("len");
  const lenVal = $("lenVal");
  lenVal.textContent = len.value;
  len.addEventListener("input", () => (lenVal.textContent = len.value));

  // show/hide
  let shown = false;
  btnToggle.onclick = () => {
    shown = !shown;
    secretEl.type = shown ? "text" : "password";
    btnToggle.textContent = shown ? "🙈 Hide" : "👁️ Show";
  };

  // generate
  btnGen.onclick = () => {
    try {
      const pwd = generatePassword(parseInt(len.value, 10), {
        upper: $("optUpper").checked,
        lower: $("optLower").checked,
        digits: $("optDigits").checked,
        symbols: $("optSymbols").checked,
      });
      secretEl.value = pwd;
      setStatus("Generated ✅", "ok");
    } catch (e) {
      setStatus("Error: " + (e?.message || String(e)), "err");
    }
  };

  // back
  btnBack.onclick = () => {
    window.location.href = "/frontend/dashboard/index.html";
  };

  // save
  btnSave.onclick = async () => {
    try {
      const site = siteEl.value.trim();
      const account = userEl.value.trim();
      const passwordValue = secretEl.value;

      if (!site || !account || !passwordValue) {
        setStatus("All fields are required", "err");
        return;
      }

      const username = mustSession("username", "Session expired. Please login again.");

      if (!window.Face) throw new Error("Face.js not loaded (check add.html includes ../mfa/face/face.js).");
      if (!window.VaultCrypto) throw new Error("vault_crypto.js not loaded.");

      setStatus("Encrypting (DEK)...");

      // 1) Encrypt
      const secret_enc = await window.VaultCrypto.encryptSecret(passwordValue);

      // 2) Local round-trip verify (نهائي)
      const testPlain = await window.VaultCrypto.decryptSecret(secret_enc);
      if (testPlain !== passwordValue) throw new Error("Encryption verification failed (round-trip mismatch).");

      setStatus("Saving...");
      await apiAddVault(username, { site, site_username: account, secret_enc });

      setStatus("Saved ✅", "ok");
      window.location.href = "/frontend/dashboard/index.html";
    } catch (e) {
      console.error(e);
      setStatus("Error: " + (e?.message || String(e)), "err");
    }
  };
});
