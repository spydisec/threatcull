// SPDX-License-Identifier: AGPL-3.0-only
// Table search. A toolbar marked data-filter-for="<table id>" stays hidden
// until this runs, so pages without JavaScript show the full table and no
// dead controls. Rows can carry data-state="enabled failed ..." for the
// optional state dropdown.

const normalise = (text: string): string => text.replace(/\s+/g, " ").trim().toLowerCase();

function apply(toolbar: HTMLElement): void {
  const table = document.getElementById(toolbar.dataset.filterFor ?? "");
  if (!table) return;
  const text = toolbar.querySelector<HTMLInputElement>("[data-filter-text]");
  const state = toolbar.querySelector<HTMLSelectElement>("[data-filter-state]");
  const count = toolbar.querySelector<HTMLElement>("[data-filter-count]");
  const words = normalise(text?.value ?? "").split(" ").filter(Boolean);
  const wanted = state?.value ?? "";

  const rows = Array.from(table.querySelectorAll<HTMLTableRowElement>("tbody > tr"));
  let shown = 0;
  for (const row of rows) {
    const haystack = normalise(row.textContent ?? "");
    const states = (row.dataset.state ?? "").split(" ");
    const visible =
      words.every((word) => haystack.includes(word)) && (!wanted || states.includes(wanted));
    row.hidden = !visible;
    if (visible) shown += 1;
  }
  if (count) {
    count.textContent =
      words.length || wanted ? `${shown} of ${rows.length}` : `${rows.length} total`;
  }
}

export function initFilters(): void {
  for (const toolbar of document.querySelectorAll<HTMLElement>("[data-filter-for]")) {
    toolbar.hidden = false;
    toolbar.addEventListener("input", () => apply(toolbar));
    apply(toolbar);
  }
  // htmx swaps a row in place (enable/disable a Source): keep it filtered.
  document.addEventListener("htmx:afterSwap", () => {
    for (const toolbar of document.querySelectorAll<HTMLElement>("[data-filter-for]")) {
      apply(toolbar);
    }
  });
  // "/" jumps to the page's search field, unless the user is already typing.
  document.addEventListener("keydown", (event) => {
    const target = event.target as HTMLElement | null;
    const typing = target?.closest("input, textarea, select, [contenteditable]");
    if (event.key !== "/" || typing || event.ctrlKey || event.metaKey || event.altKey) return;
    const field = document.querySelector<HTMLInputElement>("[data-filter-text]");
    if (field) {
      event.preventDefault();
      field.focus();
    }
  });
}
