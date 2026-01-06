export function setStatus(el, msg, type="") {
  el.textContent = msg;
  el.classList.remove("err","ok");
  if (type) el.classList.add(type);
}
export function qs(id) {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element #${id}`);
  return el;
}