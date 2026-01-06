// frontend/dashboard/script.js

// =============== helpers ===============
const qs = (id) => document.getElementById(id);
const vaultList = qs("vaultList");
const emptyState = qs("empty");
const statusEl = qs("status");

function setStatus(msg, type = "") {
  statusEl.className = "status " + (type || "");
  statusEl.textContent = msg || "";
  if (msg) {
    setTimeout(() => {
      statusEl.textContent = "";
      statusEl.className = "status";
    }, 1600);
  }
}

function mustSession(key, msg) {
  const v = sessionStorage.getItem(key);
  if (!v) throw new Error(msg);
  return v;
}

function safeText(s) {
  return String(s || "").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function normalizeUrl(site) {
  let url = (site || "").trim();
  if (!url) return "";
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;
  return url;
}

// =============== api ===============
async function apiListVault(username) {
  const r = await fetch(`/vault/list?username=${encodeURIComponent(username)}`);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.detail || "Failed to load vault list");
  return d;
}

async function apiDeleteVault(username, id) {
  const r = await fetch(`/vault/${id}?username=${encodeURIComponent(username)}`, { method: "DELETE" });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.detail || "Failed to delete");
  return d;
}

async function apiUpdateVault(username, id, payload) {
  const r = await fetch(`/vault/${id}?username=${encodeURIComponent(username)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.detail || "Failed to update");
  return d;
}

// =============== render ===============
async function renderVault() {
  try {
    vaultList.innerHTML = "";
    emptyState.style.display = "none";

    const username = mustSession("username", "Missing session username. Please login again.");
    mustSession("password_tmp", "Missing session password. Please login again.");

    setStatus("Loading vault...");

    const list = await apiListVault(username);

    if (!Array.isArray(list) || list.length === 0) {
      emptyState.style.display = "block";
      setStatus("");
      return;
    }

    let shownCount = 0;

    for (const item of list) {
      if (!window.VaultCrypto?.isProbablyEncrypted?.(item.secret_enc)) {
        console.warn("Skipped non-encrypted item id=", item.id);
        continue;
      }

      const secret = await window.VaultCrypto.decryptSecret(item.secret_enc);

      vaultList.appendChild(
        createCard(
          {
            id: item.id,
            site: item.site,
            account: item.site_username,
            secret,
          },
          username
        )
      );

      shownCount++;
    }

    if (shownCount === 0) emptyState.style.display = "block";
    setStatus("");
  } catch (e) {
    setStatus("Error: " + (e?.message || String(e)), "err");
  }
}

function createCard(item, username) {
  const card = document.createElement("div");
  card.className = "card vault-card";

  card.innerHTML = `
    <div class="vault-header">
      <h3>${safeText(item.site)}</h3>
      <span class="tag">Encrypted</span>
    </div>

    <div class="vault-body">
      <p><strong>Account:</strong> <span class="acc">${safeText(item.account)}</span></p>

      <p class="password-line">
        <strong>Password:</strong>
        <span class="secret masked">••••••••</span>
        <button class="icon eye" title="Show / Hide" type="button">👁️</button>
      </p>

      <div class="edit hidden">
        <input class="e-site" value="${safeText(item.site)}" disabled>
        <input class="e-account" value="${safeText(item.account)}" disabled>
      </div>
    </div>

    <div class="vault-actions grid-actions">
      <button class="secondary open">🌐 Open</button>
      <button class="secondary copy-user">📋 User</button>
      <button class="secondary copy-pass">🔑 Pass</button>
      <button class="secondary edit-btn">✏️ Edit</button>
      <button class="primary save hidden">💾 Save</button>
      <button class="secondary change-pass">🔐 Change Password</button>
      <button class="secondary delete">🗑️ Delete</button>
    </div>
  `;

  const secretText = card.querySelector(".secret");
  const eyeBtn = card.querySelector(".eye");
  const editBox = card.querySelector(".edit");
  const btnEdit = card.querySelector(".edit-btn");
  const btnSave = card.querySelector(".save");

  const inSite = card.querySelector(".e-site");
  const inAcc = card.querySelector(".e-account");

  let revealed = false;

  eyeBtn.onclick = () => {
    revealed = !revealed;
    secretText.textContent = revealed ? item.secret : "••••••••";
  };

  card.querySelector(".open").onclick = () => {
    const url = normalizeUrl(item.site);
    if (!url) return setStatus("Missing site URL", "err");
    window.open(url, "_blank", "noopener,noreferrer");
  };

  card.querySelector(".copy-user").onclick = async () => {
    await navigator.clipboard.writeText(item.account || "");
    setStatus("Username copied 📋", "ok");
  };

  card.querySelector(".copy-pass").onclick = async () => {
    await navigator.clipboard.writeText(item.secret || "");
    setStatus("Password copied 🔑", "ok");
  };

  btnEdit.onclick = () => {
    const isEditing = !editBox.classList.contains("hidden");
    if (isEditing) {
      editBox.classList.add("hidden");
      btnSave.classList.add("hidden");
      btnEdit.textContent = "✏️ Edit";
      inSite.disabled = true;
      inAcc.disabled = true;
      inSite.value = item.site;
      inAcc.value = item.account;
    } else {
      editBox.classList.remove("hidden");
      btnSave.classList.remove("hidden");
      btnEdit.textContent = "❌ Cancel";
      inSite.disabled = false;
      inAcc.disabled = false;
      inSite.focus();
    }
  };

  btnSave.onclick = async () => {
    try {
      setStatus("Saving...");
      await apiUpdateVault(username, item.id, {
        site: inSite.value.trim(),
        site_username: inAcc.value.trim(),
      });
      setStatus("Updated ✅", "ok");
      await renderVault();
    } catch (e) {
      setStatus("Error: " + e.message, "err");
    }
  };

  card.querySelector(".change-pass").onclick = () => {
    window.location.href = `/frontend/dashboard/change_card_password.html?id=${item.id}`;
  };

  card.querySelector(".delete").onclick = async () => {
    if (!confirm(`Delete ${item.site}?`)) return;
    setStatus("Deleting...");
    await apiDeleteVault(username, item.id);
    setStatus("Deleted 🗑️", "ok");
    await renderVault();
  };

  return card;
}

// =============== Admin Button ===============
async function checkAdmin() {
  const btn = document.getElementById("adminPanelBtn");
  if (!btn) return;

  btn.classList.add("hidden");
  btn.style.display = "none";

  try {
    const username = sessionStorage.getItem("username");
    if (!username) return;

    const r = await fetch(`/admin/me?username=${encodeURIComponent(username)}`);
    if (!r.ok) return;

    const d = await r.json();
    if (d?.is_admin === true) {
      btn.classList.remove("hidden");
      btn.style.display = "";
      btn.onclick = () => (window.location.href = "/frontend/admin/index.html");
    }
  } catch {}
}

document.addEventListener("DOMContentLoaded", () => {
  renderVault();
  checkAdmin();
});
