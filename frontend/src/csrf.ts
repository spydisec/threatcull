// SPDX-License-Identifier: AGPL-3.0-only
// Adds the session's CSRF token to every htmx request, so htmx-enhanced forms
// pass check_csrf() the same way a plain POST does (hidden "csrf" field).
// htmx events bubble to document, so this works from a deferred script too.

export function initCsrf(): void {
  document.addEventListener("htmx:configRequest", (event) => {
    const meta = document.querySelector<HTMLMetaElement>('meta[name="csrf-token"]');
    const detail = (event as CustomEvent<{ headers: Record<string, string> }>).detail;
    if (meta) detail.headers["X-CSRF-Token"] = meta.content;
  });
}
