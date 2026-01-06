const $ = (id) => document.getElementById(id);
const statusEl = $("status");
function setStatus(msg, type = "") {
  statusEl.className = "status " + type;
  statusEl.textContent = msg;
}
$("btnRegister").addEventListener("click", async () => {
  const u = $("username").value.trim();
  const e = $("email").value.trim();
  const p = $("password").value;
  const c = $("confirm").value;
  if (!u || !e || !p || !c) {
    setStatus("All fields are required", "err");
    return;
  }
  if (p !== c) {
    setStatus("Passwords do not match", "err");
    return;
  }
  const strong =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
  if (!strong.test(p)) {
    setStatus("Password must be strong (8+, A-Z, a-z, 0-9, symbol)", "err");
    return;
  }
  try {
    setStatus("Registering...");
    const r = await fetch(
      `/auth/register?username=${encodeURIComponent(u)}&email=${encodeURIComponent(e)}&password=${encodeURIComponent(p)}`,
      { method: "POST" }
    );
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.detail || "Registration failed");
    // حفظ مؤقت للمرحلة التالية
    sessionStorage.clear();
    sessionStorage.setItem("username", u);
    sessionStorage.setItem("password_tmp", p);
    setStatus("Account created ✅ Redirecting...", "ok");
    window.location.href = "../../mfa/face_register/index.html";
  } catch (e) {
    setStatus("Error: " + e.message, "err");
  }
});