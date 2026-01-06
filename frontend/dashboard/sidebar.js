// frontend/dashboard/sidebar.js
document.addEventListener("DOMContentLoaded", () => {
  const go = (p) => (window.location.href = p);

  const btnAdd = document.getElementById("btnAdd");
  const btnAddTop = document.getElementById("btnAddTop");
  const btnChangePassword = document.getElementById("btnChangePassword");
  const btnChangeFace = document.getElementById("btnChangeFace");
  const btnLogout = document.getElementById("btnLogout");

  const ensureAuth = () => {
    const u = sessionStorage.getItem("username");
    const a = sessionStorage.getItem("authenticated");
    if (!u || a !== "true") {
      sessionStorage.clear();
      go("/frontend/auth/login/index.html");
      return false;
    }
    return true;
  };

  if (btnAdd) btnAdd.onclick = () => { if (ensureAuth()) go("/frontend/dashboard/add.html"); };
  if (btnAddTop) btnAddTop.onclick = () => { if (ensureAuth()) go("/frontend/dashboard/add.html"); };

  if (btnChangePassword) btnChangePassword.onclick = () => {
    if (ensureAuth()) go("/frontend/dashboard/change.html");
  };

  if (btnChangeFace) btnChangeFace.onclick = () => {
    if (ensureAuth()) go("/frontend/mfa/face_register/index.html");
  };

  if (btnLogout) btnLogout.onclick = () => {
    sessionStorage.clear();
    go("/frontend/auth/login/index.html");
  };
});
