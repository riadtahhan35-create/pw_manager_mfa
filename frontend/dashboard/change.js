// frontend/dashboard/change.js
const $ = (id) => document.getElementById(id);

const statusEl = $("status");
const pwBar = $("pwBar");
const pwHint = $("pwHint");

function setStatus(msg, type = "") {
  statusEl.className = "status " + (type || "");
  statusEl.textContent = msg || "";
}

function mustSession(key, msg) {
  const v = sessionStorage.getItem(key);
  if (!v) throw new Error(msg);
  return v;
}

function scorePassword(pw) {
  let score = 0;
  if (!pw) return 0;
  if (pw.length >= 8) score += 25;
  if (pw.length >= 12) score += 15;
  if (/[A-Z]/.test(pw)) score += 15;
  if (/[a-z]/.test(pw)) score += 10;
  if (/\d/.test(pw)) score += 15;
  if (/[^A-Za-z0-9]/.test(pw)) score += 20;
  return Math.min(score, 100);
}

function updateMeter(pw) {
  const s = scorePassword(pw);
  pwBar.style.width = s + "%";
  if (s < 40) pwHint.textContent = "Weak: add length + numbers + symbols.";
  else if (s < 70) pwHint.textContent = "Good: consider adding symbols and more length.";
  else pwHint.textContent = "Strong ✅";
}

function bindEyeButtons() {
  document.querySelectorAll("button.eye").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-eye");
      const input = document.getElementById(id);
      input.type = input.type === "password" ? "text" : "password";
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  bindEyeButtons();

  const btnBack = $("btnBack");
  const btnUpdate = $("btnUpdate");

  $("newPassword").addEventListener("input", (e) => updateMeter(e.target.value));

  btnBack.addEventListener("click", () => {
    window.location.href = "/frontend/dashboard/index.html";
  });

  btnUpdate.addEventListener("click", async () => {
    try {
      const username = mustSession("username", "Session expired. Please login again.");

      const old_password = $("currentPassword").value;
      const new_password = $("newPassword").value;
      const confirm = $("confirmPassword").value;

      if (!old_password || !new_password || !confirm) {
        setStatus("All fields are required.", "err");
        return;
      }
      if (new_password !== confirm) {
        setStatus("New passwords do not match.", "err");
        return;
      }
      if (new_password.length < 8) {
        setStatus("New password must be at least 8 characters.", "err");
        return;
      }

      setStatus("Updating password...");

      const r = await fetch(`/auth/change-password?username=${encodeURIComponent(username)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ old_password, new_password }),
      });

      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.detail || "Failed to update password.");

      // ✅ احترافي: فرض إعادة تسجيل الدخول
      setStatus("Password updated ✅ Redirecting to login...", "ok");
      setTimeout(() => {
        sessionStorage.clear();
        window.location.href = "/frontend/auth/login/index.html";
      }, 1100);

    } catch (e) {
      setStatus(e?.message || String(e), "err");
    }
  });
});
