import { qs, setStatus } from "../../assets/js/ui.js";
import { S } from "../../assets/js/storage.js";
const statusEl = qs("status");
function requireForFace() {
  // بعد التسجيل يجب أن يوجد username + dek_b64
  const u = S.get("username");
  const dek = S.get("dek_b64");
  if (!u || !dek) throw new Error("Missing session data (username/dek_b64). Go back to Register/Login.");
}
qs("btnFaceReg").addEventListener("click", () => {
  try {
    requireForFace();
    window.location.href = "../face_register/index.html";
  } catch (e) {
    setStatus(statusEl, e.message, "err");
  }
});
qs("btnFaceVerify").addEventListener("click", () => {
  // التحقق يحتاج لاحقاً: username + dek_b64 + (mfa_session_id + challenge + K) من تسجيل الدخول
  const u = S.get("username");
  if (!u) return setStatus(statusEl, "Please login first.", "err");
  window.location.href = "../face_verify/index.html";
});