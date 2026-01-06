export const S = {
  set(k, v) { sessionStorage.setItem(k, v); },
  get(k) { return sessionStorage.getItem(k); },
  del(k) { sessionStorage.removeItem(k); },
  clear() { sessionStorage.clear(); },
  must(k, msg) {
    const v = sessionStorage.getItem(k);
    if (!v) throw new Error(msg || `Missing session data (${k}).`);
    return v;
  }
};