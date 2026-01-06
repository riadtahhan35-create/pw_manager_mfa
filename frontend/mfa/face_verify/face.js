// ===== Base64 helpers =====
function b64ToU8(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
function u8ToB64(u8) {
  return btoa(String.fromCharCode(...u8));
}

// ===== SHA-256 (CryptoJS) -> Uint8Array =====
function sha256U8(u8) {
  const wa = CryptoJS.lib.WordArray.create(u8);
  const h = CryptoJS.SHA256(wa).toString(CryptoJS.enc.Hex);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

// ===== WebCrypto AES-GCM =====
async function importAesKeyRaw(rawBytes, usages) {
  return crypto.subtle.importKey("raw", rawBytes, "AES-GCM", false, usages);
}

async function aesGcmDecryptRaw(key, b64) {
  const raw = b64ToU8(b64);
  if (raw.length < 13) throw new Error("Invalid AES-GCM payload");
  const iv = raw.slice(0, 12);
  const ct = raw.slice(12);
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(ptBuf);
}

async function aesGcmEncryptRaw(key, plainU8) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plainU8);
  const ct = new Uint8Array(ctBuf);
  return u8ToB64(new Uint8Array([...iv, ...ct]));
}

// ===== face-api models =====
async function loadModels() {
  const base = "/frontend/models";
  await faceapi.nets.tinyFaceDetector.loadFromUri(base);
  await faceapi.nets.faceLandmark68Net.loadFromUri(base);
  await faceapi.nets.faceRecognitionNet.loadFromUri(base);
}

// IMPORTANT: tighten detector options to reduce false matches
function _detectorOptions() {
  return new faceapi.TinyFaceDetectorOptions({
    inputSize: 320,
    scoreThreshold: 0.5,
  });
}

async function getEmbedding(videoEl) {
  const det = await faceapi
    .detectSingleFace(videoEl, _detectorOptions())
    .withFaceLandmarks()
    .withFaceDescriptor();

  if (!det) throw new Error("No face detected. Put your face inside the frame.");

  // extra guard (sometimes det exists but weak)
  if (det.detection && typeof det.detection.score === "number" && det.detection.score < 0.5) {
    throw new Error("Face detection confidence too low. Improve lighting and try again.");
  }

  const desc = new Float32Array(det.descriptor);

  if (desc.length !== 128) throw new Error("Invalid face descriptor length");
  for (let i = 0; i < desc.length; i++) {
    if (!Number.isFinite(desc[i])) throw new Error("Invalid face descriptor values");
  }

  return desc;
}

// ===== Distance metrics (recommended for face-api) =====
// face-api commonly uses Euclidean distance; smaller is better.
function euclideanDistance(a, b) {
  if (!a || !b || a.length !== b.length) throw new Error("Embedding size mismatch");
  let sum = 0;
  for (let i = 0; i < a.length; i++) {
    const d = a[i] - b[i];
    sum += d * d;
  }
  return Math.sqrt(sum);
}

// Optional cosine similarity (kept for debugging)
function cosineSim(a, b) {
  if (!a || !b || a.length !== b.length) throw new Error("Embedding size mismatch");
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  const den = Math.sqrt(na) * Math.sqrt(nb);
  if (!den) return 0;
  return dot / den;
}

// ===== Derive KEK via Argon2id in browser (must match backend params) =====
async function deriveKekArgon2id(password, argon2SaltU8) {
  const res = await window.argon2.hash({
    pass: password,
    salt: argon2SaltU8,
    time: 3,
    mem: 65536,
    parallelism: 4,
    hashLen: 32,
    type: window.argon2.ArgonType.Argon2id,
  });
  return new Uint8Array(res.hash); // 32 bytes
}

// ===== Get DEK by unwrapping dek_wrapped using KEK derived from password+sha256(srp_salt) =====
async function getDekFromServerBundle(username, password) {
  const r = await fetch(`/auth/dek_bundle?username=${encodeURIComponent(username)}`);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.detail || "Failed to fetch dek bundle");

  const srpSaltU8 = b64ToU8(d.salt_b64);
  const argon2SaltU8 = sha256U8(srpSaltU8);

  const kekRaw = await deriveKekArgon2id(password, argon2SaltU8);
  const kekKey = await importAesKeyRaw(kekRaw, ["decrypt"]);

  const dekU8 = await aesGcmDecryptRaw(kekKey, d.dek_wrapped_b64);
  if (dekU8.length !== 32) {
    // إذا أنت مولّد DEK بطول مختلف عدّل هذا الشرط
    // لكن الأفضل 32 bytes لـ AES-256
    // ما رح نمنع التنفيذ، بس نحذر
    console.warn("DEK length is not 32 bytes:", dekU8.length);
  }
  return dekU8;
}

// ===== Convert decrypted bytes -> Float32 descriptor safely =====
function bytesToFloat32(u8) {
  if (!(u8 instanceof Uint8Array)) throw new Error("Invalid bytes");
  if (u8.byteLength % 4 !== 0) throw new Error("Invalid Float32 byte length");
  const f32 = new Float32Array(u8.buffer, u8.byteOffset, u8.byteLength / 4);
  if (f32.length !== 128) throw new Error("Stored embedding length invalid");
  for (let i = 0; i < f32.length; i++) {
    if (!Number.isFinite(f32[i])) throw new Error("Stored embedding contains invalid values");
  }
  return new Float32Array(f32); // copy
}

window.Face = {
  loadModels,
  getEmbedding,
  cosineSim,
  euclideanDistance,
  aesGcmEncryptRaw,
  aesGcmDecryptRaw,
  getDekFromServerBundle,
  importAesKeyRaw,
  bytesToFloat32,
};
