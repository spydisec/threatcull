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
  tiers: { labels: string[]; ip: number[]; domain: number[] };
  categories: { title: string; labels: string[]; values: number[] };
  day: Series;
  month: Series;
}

const CATEGORY_TOKENS: Record<string, string> = {
  malicious: "--bad",
  c2: "--dup",
  phishing: "--keep",
  spam: "--out",
  ads_tracking: "--warn",
  scanner: "--ok",
  infrastructure: "--in",
};

let firstDraw = true;

function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function translucent(color: string, alpha: number): string {
  return `color-mix(in srgb, ${color} ${Math.round(alpha * 100)}%, transparent)`;
}

function applyTheme(): void {
  Chart.defaults.font.family = token("--font");
  Chart.defaults.color = token("--muted");
  Chart.defaults.borderColor = token("--border");
  Chart.defaults.plugins.legend.labels.boxWidth = 12;
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  Chart.defaults.animation = reduced || !firstDraw ? false : { duration: 400 };
}

function tiersChart(data: ChartData): ChartConfiguration<"bar"> {
  return {
    type: "bar",
    data: {
      labels: data.tiers.labels,
      datasets: [
        { label: "IPs", data: data.tiers.ip, backgroundColor: token("--keep"), borderRadius: 4 },
        { label: "Domains", data: data.tiers.domain, backgroundColor: token("--dup"), borderRadius: 4 },
      ],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false } } },
    },
  };
}

function categoriesChart(data: ChartData): ChartConfiguration<"doughnut"> {
  return {
    type: "doughnut",
    data: {
      labels: data.categories.labels,
      datasets: [
        {
          data: data.categories.values,
          backgroundColor: data.categories.labels.map((name) => token(CATEGORY_TOKENS[name] ?? "--in")),
          borderColor: token("--surface"),
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "58%",
      plugins: { legend: { position: "right" } },
    },
  };
}

function trendChart(series: Series): ChartConfiguration<"line"> {
  const line = (label: string, values: (number | null)[], color: string, axis: string) => ({
    label,
    data: values,
    yAxisID: axis,
    borderColor: color,
    backgroundColor: translucent(color, 0.12),
    fill: true,
    tension: 0.3,
    pointRadius: series.labels.length > 40 ? 0 : 2.5,
    spanGaps: true,
  });
  return {
    type: "line",
    data: {
      labels: series.labels,
      datasets: [
        line("IPs", series.ip, token("--keep"), "y"),
        line("Domains", series.domain, token("--dup"), "y2"),
        { ...line("High Tier", series.high, token("--bad"), "y"), fill: false },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        x: { ticks: { maxTicksLimit: 8, maxRotation: 0 } },
        y: { position: "left", title: { display: true, text: "IPs" }, ticks: { precision: 0 } },
        y2: {
          position: "right",
          title: { display: true, text: "Domains" },
          grid: { drawOnChartArea: false },
          ticks: { precision: 0 },
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
    day: () => trendChart(data.day),
    month: () => trendChart(data.month),
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
