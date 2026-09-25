// SPDX-License-Identifier: AGPL-3.0-only
// Adds the session's CSRF token to every htmx request, so htmx-enhanced forms
// pass check_csrf() the same way a plain POST does (hidden "csrf" field).
// Loaded as an external script (never inline) to satisfy the CSP
// (default-src 'self', no 'unsafe-inline').
document.body.addEventListener("htmx:configRequest", function (event) {
  var meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) {
    event.detail.headers["X-CSRF-Token"] = meta.content;
  }
});

// Copy buttons: navigator.clipboard needs HTTPS or localhost, so over a plain
// LAN address fall back to selecting the field and execCommand("copy").
document.addEventListener("click", function (event) {
  var button = event.target.closest("[data-copy]");
  if (!button) return;
  var field = document.getElementById(button.getAttribute("data-copy"));
  if (!field) return;
  var done = function () {
    button.textContent = "Copied";
    setTimeout(function () { button.textContent = "Copy"; }, 1500);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(field.value).then(done);
  } else {
    field.select();
    if (document.execCommand("copy")) done();
  }
});
