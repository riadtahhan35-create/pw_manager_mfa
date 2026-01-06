// frontend/auth/login/script.js

document.addEventListener("DOMContentLoaded", () => {
  const usernameEl = document.getElementById("username");
  const passwordEl = document.getElementById("password");
  const btnLogin = document.getElementById("btnLogin");
  const statusEl = document.getElementById("status");

  function setStatus(msg) {
    statusEl.textContent = msg || "";
  }

  btnLogin.addEventListener("click", async () => {
    try {
      const username = (usernameEl.value || "").trim();
      const password = passwordEl.value || "";

      if (!username || !password) {
        setStatus("Please enter username and password.");
        return;
      }

      setStatus("Starting secure login (SRP)...");

      const client = new SRP.Client(username, password);
      const { A_b64 } = await client.start();

      const r1 = await fetch(
        `/auth/login_start?username=${encodeURIComponent(username)}&A_b64=${encodeURIComponent(A_b64)}`,
        { method: "POST" }
      );

      const d1 = await r1.json().catch(() => ({}));
      if (!r1.ok) {
        setStatus(d1.detail || "Login failed (step 1).");
        return;
      }

      const salt_b64 = d1.salt;
      const B_b64 = d1.B;
      const session_id = d1.session_id;

      if (!salt_b64 || !B_b64 || !session_id) {
        setStatus("Invalid server response (missing SRP data).");
        return;
      }

      setStatus("Verifying credentials...");

      const { M_b64, K_b64 } = await client.processChallenge(salt_b64, B_b64);

      const r2 = await fetch(
        `/auth/login_verify?username=${encodeURIComponent(username)}&session_id=${encodeURIComponent(session_id)}&M_b64=${encodeURIComponent(M_b64)}`,
        { method: "POST" }
      );

      const d2 = await r2.json().catch(() => ({}));
      if (!r2.ok) {
        setStatus(d2.detail || "Login failed (step 2).");
        return;
      }

      if (d2.server_proof_b64) {
        const ok = client.verifyServerProof(d2.server_proof_b64);
        if (!ok) {
          setStatus("Security error: server proof mismatch.");
          return;
        }
      }

      // ✅ Session
      sessionStorage.clear();
      sessionStorage.setItem("authenticated", "true");
      sessionStorage.setItem("username", username);

      // ✅ مهم: هذا المفتاح سيستخدمه face_verify لإرسال HMAC proof
      sessionStorage.setItem("srp_K_b64", K_b64);

      // ✅ مهم: كلمة المرور مؤقتًا لفك DEK محليًا (حسب تصميمك الحالي)
      sessionStorage.setItem("password_tmp", password);

      if (d2.mfa_required) {
        sessionStorage.setItem("mfa_session_id", d2.mfa_session_id || "");
        sessionStorage.setItem("challenge_b64", d2.challenge_b64 || "");
        setStatus("SRP OK ✅ Redirecting to Face Verification...");
        window.location.href = "/frontend/mfa/face_verify/index.html";
        return;
      }

      setStatus("Login successful ✅");
      window.location.href = "/frontend/dashboard/index.html";

    } catch (e) {
      console.error(e);
      setStatus("Unexpected error: " + (e?.message || String(e)));
    }
  });
});
