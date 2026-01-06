const $ = (id) => document.getElementById(id);
const statusEl = $("status");
const video = $("cam");

function setStatus(msg, type = "") {
  statusEl.className = "status " + type;
  statusEl.textContent = msg;
}

async function startCam() {
  const stream = await navigator.mediaDevices.getUserMedia({ video: true });
  video.srcObject = stream;
}

(async () => {
  try {
    const username = sessionStorage.getItem("username");
    const password = sessionStorage.getItem("password_tmp");

    if (!username || !password) {
      setStatus("Missing registration session", "err");
      return;
    }

    setStatus("Loading face models...");
    await Face.loadModels();        // ← FIXED

    setStatus("Starting camera...");
    await startCam();

    setStatus("Ready to capture ✅");
  } catch (e) {
    setStatus("Error: " + e.message, "err");
  }
})();

$("btnCancel").onclick = () => {
  window.location.href = "../../auth/login/index.html";
};

$("btnCapture").onclick = async () => {
  try {
    const username = sessionStorage.getItem("username");
    const password = sessionStorage.getItem("password_tmp");

    if (!username || !password) throw new Error("Session expired");

    setStatus("Capturing face...");
    const emb = await Face.getEmbedding(video);   // ← FIXED

    // اشتقاق DEK
    const dekU8 = await Face.getDekFromServerBundle(username, password);
    const dekKey = await Face.importAesKeyRaw(dekU8, ["encrypt"]);

    const enc_b64 = await Face.aesGcmEncryptRaw(
      dekKey,
      new Uint8Array(emb.buffer)
    );

    setStatus("Saving encrypted template...");

    const r = await fetch("/mfa/face/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        face_template_enc_b64: enc_b64
      })
    });

    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.detail || "Failed to store face template");

    setStatus("Face registered ✅ Redirecting...", "ok");

    sessionStorage.clear();
    window.location.href = "../../auth/login/index.html";

  } catch (e) {
    setStatus("Error: " + e.message, "err");
  }
};
