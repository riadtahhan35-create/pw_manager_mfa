// frontend/mfa/face_verify/script.js

const $ = (id) => document.getElementById(id);

const statusEl = $("status");
const video = $("cam");
const btnVerify = $("btnVerify");
const btnBack = $("btnBack");

function setStatus(msg, type = "") {
  statusEl.className = "status " + (type || "");
  statusEl.textContent = msg || "";
}

async function startCam() {
  const stream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: "user", width: { ideal: 640 }, height: { ideal: 480 } },
    audio: false,
  });
  video.srcObject = stream;
}

function b64ToWA(b64) { return CryptoJS.enc.Base64.parse(b64); }
function waToB64(wa) { return CryptoJS.enc.Base64.stringify(wa); }

async function sendMfaProof() {
  const username = sessionStorage.getItem("username");
  const mfa_session_id = sessionStorage.getItem("mfa_session_id");
  const challenge_b64 = sessionStorage.getItem("challenge_b64");
  const K_b64 = sessionStorage.getItem("srp_K_b64");

  if (!username || !mfa_session_id || !challenge_b64 || !K_b64) {
    throw new Error("Missing session data. Please login again.");
  }

  // proof = HMAC-SHA1(K, challenge)
  const proofWA = CryptoJS.HmacSHA1(b64ToWA(challenge_b64), b64ToWA(K_b64));
  const proof_b64 = waToB64(proofWA);

  const r = await fetch(
    `/auth/mfa_complete?username=${encodeURIComponent(username)}&mfa_session_id=${encodeURIComponent(mfa_session_id)}&proof_b64=${encodeURIComponent(proof_b64)}`,
    { method: "POST" }
  );

  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.detail || "MFA proof failed");

  return true;
}

function sleep(ms) {
  return new Promise((res) => setTimeout(res, ms));
}

function median(arr) {
  const a = [...arr].sort((x, y) => x - y);
  const mid = Math.floor(a.length / 2);
  return a.length % 2 ? a[mid] : (a[mid - 1] + a[mid]) / 2;
}

// Init
(async () => {
  try {
    const username = sessionStorage.getItem("username");
    const password = sessionStorage.getItem("password_tmp");

    if (!username || !password) {
      setStatus("Missing login session. Redirecting...", "err");
      setTimeout(() => (window.location.href = "/frontend/auth/login/index.html"), 800);
      return;
    }

    setStatus("Loading models...");
    await window.Face.loadModels();

    setStatus("Starting camera...");
    await startCam();

    setStatus("Ready ✅");
  } catch (e) {
    setStatus("Error: " + (e?.message || String(e)), "err");
  }
})();

btnBack.addEventListener("click", () => {
  window.location.href = "/frontend/auth/login/index.html";
});

btnVerify.addEventListener("click", async () => {
  try {
    const username = sessionStorage.getItem("username");
    const password = sessionStorage.getItem("password_tmp");
    if (!username || !password) throw new Error("Missing login session.");

    setStatus("Fetching encrypted face template...");
    const rTpl = await fetch(`/mfa/face/template?username=${encodeURIComponent(username)}`);
    const tpl = await rTpl.json().catch(() => ({}));
    if (!rTpl.ok) throw new Error(tpl.detail || "Template not found");

    setStatus("Deriving DEK locally...");
    const dekU8 = await window.Face.getDekFromServerBundle(username, password);
    const dekKey = await window.Face.importAesKeyRaw(dekU8, ["decrypt"]);

    setStatus("Decrypting stored embedding...");
    const storedU8 = await window.Face.aesGcmDecryptRaw(dekKey, tpl.face_template_enc_b64);
    const stored = window.Face.bytesToFloat32(storedU8);

    setStatus("Capturing live embeddings (3 samples)...");
    const distances = [];

    for (let i = 0; i < 3; i++) {
      const live = await window.Face.getEmbedding(video);
      const dist = window.Face.euclideanDistance(stored, live);
      distances.push(dist);
      setStatus(`Sample ${i + 1}/3 distance: ${dist.toFixed(4)} ...`);
      await sleep(250);
    }

    const distMed = median(distances);
    const THRESHOLD = 0.55;

    setStatus(`Distance (median): ${distMed.toFixed(4)} (<= ${THRESHOLD} PASS)`);

    if (distMed > THRESHOLD) throw new Error("Face mismatch");

    setStatus("Face matched ✅ Sending MFA proof...");
    await sendMfaProof();

    setStatus("MFA Completed ✅ Redirecting...", "ok");
    window.location.href = "/frontend/dashboard/index.html";
  } catch (e) {
    setStatus("Error: " + (e?.message || String(e)), "err");
  }
});
