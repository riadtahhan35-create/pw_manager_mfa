// frontend/dashboard/change_card_password.js
// ==================================================
// Change Card Password
// - Uses existing DEK from VaultCrypto
// - Same encryption flow as add.js
// ==================================================

const $ = (id) => document.getElementById(id);

// Elements
const passwordEl = $("password");
const confirmEl  = $("confirm");
const toggle1    = $("toggle");
const toggle2    = $("toggle2");

const genBtn   = $("gen");
const saveBtn  = $("save");
const backBtn  = $("back");

const lenInput = $("len");
const lenVal   = $("lenVal");

const optUpper   = $("optUpper");
const optLower   = $("optLower");
const optDigits  = $("optDigits");
const optSymbols = $("optSymbols");

const matchBadge = $("matchBadge");
const statusEl   = $("status");

// ==================================================
// Helpers
// ==================================================
function setStatus(msg, type = "") {
  statusEl.className = "status-line " + (type || "");
  statusEl.textContent = msg || "";
}

function mustSession(key, msg) {
  const v = sessionStorage.getItem(key);
  if (!v) throw new Error(msg);
  return v;
}

function toggleVisibility(input, btn) {
  const isHidden = input.type === "password";
  input.type = isHidden ? "text" : "password";
  btn.textContent = isHidden ? "🙈 Hide" : "👁 Show";
}

// ==================================================
// Password match check
// ==================================================
function checkMatch() {
  const p = passwordEl.value;
  const c = confirmEl.value;

  if (!p && !c) {
    matchBadge.textContent = "—";
    matchBadge.style.color = "";
    return;
  }

  if (c.length === 0) {
    matchBadge.textContent = "Waiting…";
    matchBadge.style.color = "#f7b731";
    return;
  }

  if (p === c) {
    matchBadge.textContent = "Matched ✅";
    matchBadge.style.color = "#2ecc71";
  } else {
    matchBadge.textContent = "Not matched ❌";
    matchBadge.style.color = "#ff6b6b";
  }
}

// ==================================================
// Secure password generator (same logic as add.js)
// ==================================================
function randomChar(set) {
  const u = new Uint32Array(1);
  crypto.getRandomValues(u);
  return set[u[0] % set.length];
}

function generatePassword(len, opt) {
  const U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const L = "abcdefghijklmnopqrstuvwxyz";
  const D = "0123456789";
  const S = "!@#$%^&*()-_=+[]{};:,.?/|~";

  let pool = "";
  const out = [];

  if (opt.upper) { pool += U; out.push(randomChar(U)); }
  if (opt.lower) { pool += L; out.push(randomChar(L)); }
  if (opt.digits){ pool += D; out.push(randomChar(D)); }
  if (opt.symbols){ pool += S; out.push(randomChar(S)); }

  if (!pool) throw new Error("Select at least one character set.");

  while (out.length < len) out.push(randomChar(pool));

  // Shuffle
  for (let i = out.length - 1; i > 0; i--) {
    const r = new Uint32Array(1);
    crypto.getRandomValues(r);
    const j = r[0] % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }

  return out.join("");
}

// ==================================================
// API
// ==================================================
async function apiUpdatePassword(username, cardId, secret_enc) {
  const r = await fetch(
    `/vault/${cardId}/password?username=${encodeURIComponent(username)}`,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret_enc }),
    }
  );

  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.detail || "Failed to update password");
  return d;
}

// ==================================================
// Init
// ==================================================
document.addEventListener("DOMContentLoaded", () => {
  try {
    mustSession("username", "Session expired. Please login again.");
    mustSession("password_tmp", "Session expired. Please login again.");
  } catch (e) {
    setStatus(e.message, "err");
    setTimeout(() => {
      window.location.href = "/frontend/auth/login/index.html";
    }, 800);
    return;
  }

  lenVal.textContent = lenInput.value;
  setStatus("");
  checkMatch();
});

// ==================================================
// Events
// ==================================================
passwordEl.addEventListener("input", checkMatch);
confirmEl.addEventListener("input", checkMatch);

toggle1.onclick = () => toggleVisibility(passwordEl, toggle1);
toggle2.onclick = () => toggleVisibility(confirmEl, toggle2);

lenInput.oninput = () => {
  lenVal.textContent = lenInput.value;
};

// Generate
genBtn.onclick = () => {
  try {
    const pwd = generatePassword(parseInt(lenInput.value, 10), {
      upper: optUpper.checked,
      lower: optLower.checked,
      digits: optDigits.checked,
      symbols: optSymbols.checked,
    });

    passwordEl.value = pwd;
    confirmEl.value  = pwd;
    checkMatch();

    setStatus("Password generated ✅", "ok");
  } catch (e) {
    setStatus(e.message || String(e), "err");
  }
};

// Back
backBtn.onclick = () => history.back();

// Save
saveBtn.onclick = async () => {
  try {
    const username = mustSession("username", "Session expired.");
    const params = new URLSearchParams(window.location.search);
    const cardId = params.get("id");

    if (!cardId) throw new Error("Missing card id in URL.");

    const p = passwordEl.value;
    const c = confirmEl.value;

    if (!p || p.length < 8)
      throw new Error("Password must be at least 8 characters.");

    if (p !== c)
      throw new Error("Passwords do not match.");

    if (!window.VaultCrypto)
      throw new Error("vault_crypto.js not loaded.");

    setStatus("Encrypting (DEK)...");

    // 🔐 Encrypt with existing DEK
    const secret_enc = await VaultCrypto.encryptSecret(p);

    setStatus("Saving...");
    saveBtn.disabled = true;

    await apiUpdatePassword(username, cardId, secret_enc);

    setStatus("Password updated successfully ✅", "ok");
    setTimeout(() => history.back(), 800);

  } catch (e) {
    console.error(e);
    setStatus(e.message || String(e), "err");
  } finally {
    saveBtn.disabled = false;
  }
};
