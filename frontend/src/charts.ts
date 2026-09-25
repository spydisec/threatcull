// SPDX-License-Identifier: AGPL-3.0-only
// Dashboard charts. The server embeds the numbers as JSON in #chart-data and marks
// each canvas with data-chart="<key>"; this draws them with Chart.js (bundled, never
// from a CDN). htmx swaps a fresh dashboard in every minute, so charts are redrawn
// after each swap, without animation after the first draw.
import {
  ArcElement,
  BarController,
  BarElement,
  CategoryScale,
  Chart,
  type ChartConfiguration,
  DoughnutController,
  Filler,
  Legend,
  LinearScale,
  LineController,
  LineElement,
  PointElement,
  Tooltip,
} from "chart.js";

Chart.register(
  ArcElement,
  BarController,
  BarElement,
  CategoryScale,
  DoughnutController,
  Filler,
  Legend,
  LinearScale,
  LineController,
  LineElement,
  PointElement,
  Tooltip,
);

interface Series {
  labels: string[];
  ip: (number | null)[];
  domain: (number | null)[];
  high: number[];
}

interface ChartData {
  tiers: { labels: string[]; kind: string; values: number[]; total: number };
  categories: { title: string; keys: string[]; labels: string[]; values: number[] };
  day: Series;
  month: Series;
}

// The spydisec.com colour key: Tiers run red (high) to yellow (low); each
// category keeps one colour everywhere.
const TIER_TOKENS = ["--c-red", "--c-orange", "--c-yellow"];
const CATEGORY_TOKENS: Record<string, string> = {
  malicious: "--c-red",
  spam: "--c-orange",
  ads_tracking: "--c-yellow",
  phishing: "--c-blue",
  c2: "--c-purple",
  scanner: "--c-green",
  infrastructure: "--muted",
};

let firstDraw = true;

function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function translucent(color: string, alpha: number): string {
  return `color-mix(in srgb, ${color} ${Math.round(alpha * 100)}%, transparent)`;
}

const num = (value: number | null | undefined): string =>
  value == null ? "-" : Number(value).toLocaleString();

const pct = (value: number, total: number): string =>
  total ? `${((value / total) * 100).toFixed(1)}%` : "0%";

function applyTheme(): void {
  Chart.defaults.font.family = token("--font");
  Chart.defaults.color = token("--muted");
  Chart.defaults.borderColor = token("--border");
  Chart.defaults.plugins.legend.labels.color = token("--fg");
  Chart.defaults.plugins.legend.labels.boxWidth = 14;
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  Chart.defaults.animation = reduced || !firstDraw ? false : { duration: 400 };
}

// Zoom a trend axis onto its data, as spydisec.com does, so hour-to-hour change shows.
function padded(values: (number | null)[], share: number, floor: number): { min?: number; max?: number } {
  const known = values.filter((v): v is number => v != null);
  if (!known.length) return {};
  const low = Math.min(...known);
  const high = Math.max(...known);
  const pad = Math.max(floor, Math.round((high - low) * share));
  return { min: Math.max(0, low - pad), max: high + pad };
}

function tiersChart(data: ChartData): ChartConfiguration<"bar"> {
  const { labels, values, total, kind } = data.tiers;
  return {
    type: "bar",
    data: {
      labels: labels.map((l) => `${l[0]?.toUpperCase() ?? ""}${l.slice(1)} (${kind})`),
      datasets: [{ data: values, backgroundColor: TIER_TOKENS.map(token), borderRadius: 6 }],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: (ctx) => `${num(ctx.raw as number)} (${pct(ctx.raw as number, total)})` } },
      },
      scales: {
        x: { beginAtZero: true, ticks: { precision: 0 } },
        y: { grid: { display: false }, ticks: { color: token("--fg") } },
      },
    },
  };
}

function categoriesChart(data: ChartData): ChartConfiguration<"doughnut"> {
  const total = data.categories.values.reduce((a, b) => a + b, 0);
  return {
    type: "doughnut",
    data: {
      labels: data.categories.labels,
      datasets: [
        {
          data: data.categories.values,
          backgroundColor: data.categories.keys.map((key) => token(CATEGORY_TOKENS[key] ?? "--muted")),
          borderColor: token("--surface"),
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "right" },
        tooltip: {
          callbacks: { label: (ctx) => `${ctx.label}: ${num(ctx.raw as number)} (${pct(ctx.raw as number, total)})` },
        },
      },
    },
  };
}

function line(label: string, values: (number | null)[], color: string, axis: string, points: boolean) {
  return {
    label,
    data: values,
    yAxisID: axis,
    borderColor: color,
    backgroundColor: translucent(color, 0.08),
    fill: true,
    tension: 0.28,
    pointRadius: points ? 2.5 : 0,
    spanGaps: true,
  };
}

function dayChart(series: Series): ChartConfiguration<"line"> {
  const green = token("--c-green");
  const red = token("--c-red");
  return {
    type: "line",
    data: {
      labels: series.labels,
      datasets: [
        line("Total IPs", series.ip, green, "y", false),
        line("High Tier", series.high, red, "y1", false),
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        x: { ticks: { maxTicksLimit: 8, maxRotation: 0 } },
        y: { position: "left", ...padded(series.ip, 0.15, 20), ticks: { color: green, precision: 0 } },
        y1: {
          position: "right",
          ...padded(series.high, 0.2, 5),
          ticks: { color: red, precision: 0 },
          grid: { drawOnChartArea: false },
        },
      },
    },
  };
}

function monthChart(series: Series): ChartConfiguration<"line"> {
  const green = token("--c-green");
  const blue = token("--c-blue");
  return {
    type: "line",
    data: {
      labels: series.labels,
      datasets: [
        line("Total IPs", series.ip, green, "y", true),
        line("Total domains", series.domain, blue, "y1", true),
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        x: { ticks: { maxRotation: 45 } },
        y: { position: "left", ticks: { color: green, precision: 0 }, title: { display: true, text: "IPs", color: green } },
        y1: {
          position: "right",
          ticks: { color: blue, precision: 0 },
          grid: { drawOnChartArea: false },
          title: { display: true, text: "Domains", color: blue },
        },
      },
    },
  };
}

function drawAll(): void {
  const source = document.getElementById("chart-data");
  if (!source?.textContent) return;
  const data = JSON.parse(source.textContent) as ChartData;
  applyTheme();
  type AnyConfig = ChartConfiguration<"bar"> | ChartConfiguration<"doughnut"> | ChartConfiguration<"line">;
  const builders: Record<string, () => AnyConfig> = {
    tiers: () => tiersChart(data),
    categories: () => categoriesChart(data),
    day: () => dayChart(data.day),
    month: () => monthChart(data.month),
  };
  for (const canvas of document.querySelectorAll<HTMLCanvasElement>("canvas[data-chart]")) {
    const build = builders[canvas.dataset.chart ?? ""];
    if (!build) continue;
    Chart.getChart(canvas)?.destroy();
    new Chart(canvas, build() as ChartConfiguration);
  }
  firstDraw = false;
}

export function initCharts(): void {
  drawAll();
  document.addEventListener("htmx:afterSwap", drawAll);
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", drawAll);
}
