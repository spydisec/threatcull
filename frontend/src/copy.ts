// SPDX-License-Identifier: AGPL-3.0-only
// Copy buttons: navigator.clipboard needs HTTPS or localhost, so over a plain
// LAN address fall back to selecting the field and execCommand("copy").

export function initCopy(): void {
  document.addEventListener("click", (event) => {
    const button = (event.target as HTMLElement | null)?.closest<HTMLButtonElement>("[data-copy]");
    if (!button) return;
    const field = document.getElementById(button.dataset.copy ?? "");
    if (!(field instanceof HTMLInputElement)) return;
    const done = (): void => {
      button.textContent = "Copied";
      window.setTimeout(() => {
        button.textContent = "Copy";
      }, 1500);
    };
    if (navigator.clipboard && window.isSecureContext) {
      void navigator.clipboard.writeText(field.value).then(done);
    } else {
      field.select();
      if (document.execCommand("copy")) done();
    }
  });
}
