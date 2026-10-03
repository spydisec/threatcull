// SPDX-License-Identifier: AGPL-3.0-only
// Run status: the server renders the elapsed time and htmx refreshes it every 3 s.
// In between, count it up every second. Counting from the server's value (not
// from a timestamp) keeps a wrong clock on the viewer's computer out of it.

const PER_UNIT = 60;

export function formatDuration(seconds: number): string {
  if (seconds < PER_UNIT) return `${seconds} s`;
  const minutes = Math.floor(seconds / PER_UNIT);
  const secs = seconds % PER_UNIT;
  if (minutes < PER_UNIT) return secs ? `${minutes} min ${secs} s` : `${minutes} min`;
  const hours = Math.floor(minutes / PER_UNIT);
  const mins = minutes % PER_UNIT;
  return mins ? `${hours} h ${mins} min` : `${hours} h`;
}

function tick(): void {
  const now = Date.now();
  for (const el of document.querySelectorAll<HTMLElement>("[data-elapsed]")) {
    const base = Number(el.dataset.elapsed);
    if (!Number.isFinite(base)) continue;
    // First sight of this element (a fresh htmx swap): remember when we saw it.
    el.dataset.seenAt ??= String(now);
    const passed = Math.floor((now - Number(el.dataset.seenAt)) / 1000);
    el.textContent = formatDuration(base + passed);
  }
}

export function initElapsed(): void {
  // Four times a second, so the shown value turns over close to each real second.
  window.setInterval(tick, 250);
}
