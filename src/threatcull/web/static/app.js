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
