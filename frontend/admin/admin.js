// frontend/admin/admin.js (FINAL)
// - Fix Refresh button reliably
// - Fix Lock/Unlock UI update (optimistic + full refresh)
// - Use event delegation (no re-bind problems)
// - Safer HTML rendering (escape)

// ================= Helpers =================
const qs = (id) => document.getElementById(id);

const usersTbody = qs("usersTable");
const auditTbody = qs("auditTable");
const statusEl = qs("status");

const searchUsersEl = qs("searchUsers");
const searchAuditEl = qs("searchAudit");

const btnBack = qs("btnBack");
const btnRefresh = qs("btnRefresh");
const btnLogout = qs("btnLogout");
const adminNameEl = qs("adminName");

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function setStatus(msg, type = "") {
  statusEl.className = "status " + (type || "");
  statusEl.textContent = msg || "";
  if (msg) {
    setTimeout(() => {
      statusEl.textContent = "";
      statusEl.className = "status";
    }, 2200);
  }
}

function go(path) {
  window.location.href = path;
}

function mustSession(key) {
  const v = sessionStorage.getItem(key);
  if (!v) {
    sessionStorage.clear();
    go("/frontend/auth/login/index.html");
    throw new Error("Session expired");
  }
  return v;
}

function logout() {
  sessionStorage.clear();
  go("/frontend/auth/login/index.html");
}
window.logout = logout;

function fmtTime(t) {
  if (!t) return "-";
  const d = new Date(t);
  if (isNaN(d.getTime())) return String(t);
  return d.toLocaleString();
}

function uParam(username) {
  return encodeURIComponent(username);
}

// ================= API =================
async function api(path, options = {}) {
  const r = await fetch(path, options);
  const d = await r.json().catch(() => ({}));

  if (!r.ok) {
    const detail = d?.detail || d?.message || "Request failed";
    if (r.status === 401) throw new Error("Unauthorized (please login again).");
    if (r.status === 403) throw new Error("Forbidden (admin only).");
    if (r.status === 404) throw new Error("Not Found (endpoint missing).");
    throw new Error(detail);
  }
  return d;
}

// ================= State =================
let USERS_CACHE = [];
let AUDIT_CACHE = [];
let BUSY = false;

// ================= Stats =================
async function loadStats() {
  const username = mustSession("username");
  const data = await api(`/admin/stats?username=${uParam(username)}`);

  qs("statTotal").textContent = data.total_users ?? 0;
  qs("statActive").textContent = data.active_users ?? 0;
  qs("statLocked").textContent = data.locked_users ?? 0;
}

// ================= Users =================
function renderUsers(list) {
  usersTbody.innerHTML = "";

  if (!Array.isArray(list) || list.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="6" style="opacity:.8;text-align:center;padding:18px">No users</td>`;
    usersTbody.appendChild(tr);
    return;
  }

  for (const u of list) {
    const isLocked = !!u.is_locked;
    const role = (u.role || "user").toLowerCase();

    const tr = document.createElement("tr");
    tr.dataset.userId = String(u.id);

    tr.innerHTML = `
      <td>${escapeHtml(u.id)}</td>
      <td>${escapeHtml(u.username)}</td>
      <td>${escapeHtml(u.email || "-")}</td>
      <td>
        <select data-action="role" data-id="${escapeHtml(u.id)}" class="role">
          <option value="user" ${role === "user" ? "selected" : ""}>User</option>
          <option value="admin" ${role === "admin" ? "selected" : ""}>Admin</option>
        </select>
      </td>
      <td>
        <span class="badge ${isLocked ? "err" : "ok"}" data-field="statusBadge">
          ${isLocked ? "🔒 Locked" : "✅ Active"}
        </span>
      </td>
      <td>
        <button class="secondary lock" data-action="lock" data-id="${escapeHtml(u.id)}">
          ${isLocked ? "Unlock" : "Lock"}
        </button>
      </td>
    `;

    usersTbody.appendChild(tr);
  }
}

async function loadUsers() {
  const username = mustSession("username");
  const users = await api(`/admin/users?username=${uParam(username)}`);
  USERS_CACHE = Array.isArray(users) ? users : [];
  applyUsersFilter();
}

function applyUsersFilter() {
  const q = (searchUsersEl?.value || "").trim().toLowerCase();
  if (!q) return renderUsers(USERS_CACHE);

  const filtered = USERS_CACHE.filter((u) => {
    const a = String(u.username || "").toLowerCase();
    const b = String(u.email || "").toLowerCase();
    return a.includes(q) || b.includes(q);
  });

  renderUsers(filtered);
}

// تحديث فوري للصف (بدون انتظار reload) — احترافي
function patchUserRowUI(userId, patch) {
  const row = usersTbody.querySelector(`tr[data-user-id="${CSS.escape(String(userId))}"]`);
  if (!row) return;

  // status
  if (typeof patch.is_locked === "boolean") {
    const badge = row.querySelector('[data-field="statusBadge"]');
    const btn = row.querySelector('button[data-action="lock"]');
    if (badge) {
      badge.classList.remove("ok", "err");
      badge.classList.add(patch.is_locked ? "err" : "ok");
      badge.textContent = patch.is_locked ? "🔒 Locked" : "✅ Active";
    }
    if (btn) btn.textContent = patch.is_locked ? "Unlock" : "Lock";
  }

  // role
  if (patch.role) {
    const sel = row.querySelector('select[data-action="role"]');
    if (sel) sel.value = patch.role;
  }
}

// ================= Audit =================
function renderAudit(list) {
  auditTbody.innerHTML = "";

  if (!Array.isArray(list) || list.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="6" style="opacity:.8;text-align:center;padding:18px">No logs</td>`;
    auditTbody.appendChild(tr);
    return;
  }

  for (const l of list) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(fmtTime(l.time))}</td>
      <td>${escapeHtml(l.action || "-")}</td>
      <td>${escapeHtml(l.admin || "-")}</td>
      <td>${escapeHtml(l.target || "-")}</td>
      <td>${escapeHtml(l.details || "-")}</td>
      <td>${escapeHtml(l.ip || "-")}</td>
    `;
    auditTbody.appendChild(tr);
  }
}

async function loadAudit() {
  const username = mustSession("username");
  const logs = await api(`/admin/audit?username=${uParam(username)}`);
  AUDIT_CACHE = Array.isArray(logs) ? logs : [];
  applyAuditFilter();
}

function applyAuditFilter() {
  const q = (searchAuditEl?.value || "").trim().toLowerCase();
  if (!q) return renderAudit(AUDIT_CACHE);

  const filtered = AUDIT_CACHE.filter((l) => {
    const a = String(l.action || "").toLowerCase();
    const b = String(l.admin || "").toLowerCase();
    const c = String(l.target || "").toLowerCase();
    const d = String(l.details || "").toLowerCase();
    const ip = String(l.ip || "").toLowerCase();
    return a.includes(q) || b.includes(q) || c.includes(q) || d.includes(q) || ip.includes(q);
  });

  renderAudit(filtered);
}

// ================= Actions (Event Delegation) =================
async function handleRoleChange(selectEl) {
  const username = mustSession("username");
  const userId = selectEl.dataset.id;
  const newRole = selectEl.value;

  // backup previous
  const original = USERS_CACHE.find((u) => String(u.id) === String(userId));
  const prevRole = (original?.role || "user").toLowerCase();

  try {
    setStatus("Updating role...", "");
    selectEl.disabled = true;

    await api(`/admin/users/${encodeURIComponent(userId)}/role?username=${uParam(username)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role: newRole }),
    });

    // UI patch now
    patchUserRowUI(userId, { role: newRole });
    setStatus("Role updated ✅", "ok");

    // full refresh to ensure server truth
    await refreshAll();
  } catch (e) {
    setStatus(e.message, "err");
    selectEl.value = prevRole;
  } finally {
    selectEl.disabled = false;
  }
}

async function handleLockToggle(btnEl) {
  const username = mustSession("username");
  const userId = btnEl.dataset.id;

  // Determine desired action from current cache, NOT from button text (more reliable)
  const u = USERS_CACHE.find((x) => String(x.id) === String(userId));
  const currentlyLocked = !!u?.is_locked;
  const wantLock = !currentlyLocked;

  try {
    setStatus(wantLock ? "Locking user..." : "Unlocking user...", "");
    btnEl.disabled = true;

    // Optimistic UI patch
    patchUserRowUI(userId, { is_locked: wantLock });

    await api(`/admin/users/${encodeURIComponent(userId)}/lock?username=${uParam(username)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ locked: wantLock }),
    });

    setStatus("User updated 🔐", "ok");

    // Refresh everything to update stats + logs + cache
    await refreshAll();
  } catch (e) {
    // rollback UI patch
    patchUserRowUI(userId, { is_locked: currentlyLocked });
    setStatus(e.message, "err");
  } finally {
    btnEl.disabled = false;
  }
}

// ================= Init / Refresh =================
async function refreshAll(force = false) {
  if (BUSY && !force) return;
  BUSY = true;

  try {
    const username = mustSession("username");
    if (adminNameEl) adminNameEl.textContent = username;

    setStatus("Loading...", "");

    // Load in sequence to reduce race conditions
    await loadStats();
    await loadUsers();
    await loadAudit();

    setStatus("", "");
  } catch (e) {
    setStatus(e.message || String(e), "err");
  } finally {
    BUSY = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  // Sidebar buttons (robust addEventListener)
  if (btnBack) btnBack.addEventListener("click", () => go("/frontend/dashboard/index.html"));
  if (btnLogout) btnLogout.addEventListener("click", () => logout());

  // ✅ Refresh button fixed: always triggers refreshAll even if busy
  if (btnRefresh) {
    btnRefresh.addEventListener("click", (e) => {
      e.preventDefault();
      refreshAll(true);
    });
  }

  // Search filters
  if (searchUsersEl) searchUsersEl.addEventListener("input", applyUsersFilter);
  if (searchAuditEl) searchAuditEl.addEventListener("input", applyAuditFilter);

  // ✅ Event delegation for users actions (no bind issues)
  usersTbody.addEventListener("change", (e) => {
    const t = e.target;
    if (t && t.matches('select[data-action="role"]')) {
      handleRoleChange(t);
    }
  });

  usersTbody.addEventListener("click", (e) => {
    const t = e.target;
    if (t && t.matches('button[data-action="lock"]')) {
      handleLockToggle(t);
    }
  });

  // Initial load
  refreshAll(true);
});
