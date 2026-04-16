/**
 * Chart primitive components for the honeypot dashboard.
 *
 * These components are the API contract for Phase 3 (LLM-generated UIs).
 * The Phase 3 system prompt includes this documentation verbatim.
 * Keep the prop surface small (4-6 props max per component).
 *
 * All components are pure — they receive data as props, never fetch it.
 * The host shell or dashboard component handles data fetching.
 */

const { createElement: h, Fragment } = React;

// ---------------------------------------------------------------------------
// Color palette
// ---------------------------------------------------------------------------

const COLORS = [
  "#3b82f6", "#ef4444", "#10b981", "#f59e0b", "#8b5cf6",
  "#ec4899", "#06b6d4", "#f97316", "#6366f1", "#14b8a6",
];

// ---------------------------------------------------------------------------
// StatCard
// ---------------------------------------------------------------------------

/**
 * StatCard — a single metric with label and optional subtitle.
 *
 * Props:
 *   label    (string)  — metric name, e.g. "Unique IPs"
 *   value    (string|number) — the metric value, e.g. 253 or "21,097"
 *   subtitle (string?) — optional secondary text, e.g. "96% from one IP"
 *   color    (string?) — accent color for the value, default "#3b82f6"
 */
function StatCard({ label, value, subtitle, color = "#3b82f6" }) {
  return h("div", { className: "stat-card" },
    h("div", { className: "stat-label" }, label),
    h("div", { className: "stat-value", style: { color } }, value),
    subtitle ? h("div", { className: "stat-subtitle" }, subtitle) : null
  );
}

// ---------------------------------------------------------------------------
// BarChart
// ---------------------------------------------------------------------------

/**
 * BarChart — horizontal bar chart for ranked data.
 *
 * Props:
 *   title  (string)           — chart heading
 *   data   (Array<{label: string, value: number}>) — bars to render
 *   color  (string?)          — bar fill color, default "#3b82f6"
 *   maxBars (number?)         — max bars to show, default 10
 */
function BarChart({ title, data, color = "#3b82f6", maxBars = 10 }) {
  const items = data.slice(0, maxBars);
  const max = Math.max(...items.map(d => d.value), 1);
  return h("div", { className: "chart-container" },
    h("h3", { className: "chart-title" }, title),
    h("div", { className: "bar-chart" },
      items.map((d, i) =>
        h("div", { key: i, className: "bar-row" },
          h("div", { className: "bar-label", title: d.label }, d.label),
          h("div", { className: "bar-track" },
            h("div", { className: "bar-fill", style: {
              width: `${(d.value / max) * 100}%`,
              backgroundColor: color,
            }}),
          ),
          h("div", { className: "bar-value" }, d.value.toLocaleString()),
        )
      )
    )
  );
}

// ---------------------------------------------------------------------------
// LineChart
// ---------------------------------------------------------------------------

/**
 * LineChart — SVG line/area chart for time-series data.
 *
 * Props:
 *   title  (string)           — chart heading
 *   data   (Array<{label: string, value: number}>) — points in order
 *   color  (string?)          — line/fill color, default "#3b82f6"
 *   height (number?)          — chart height in px, default 200
 */
function LineChart({ title, data, color = "#3b82f6", height = 200 }) {
  if (!data || data.length === 0) return null;
  const W = 700, H = height, pad = { t: 10, r: 10, b: 40, l: 50 };
  const plotW = W - pad.l - pad.r;
  const plotH = H - pad.t - pad.b;
  const max = Math.max(...data.map(d => d.value), 1);

  const points = data.map((d, i) => ({
    x: pad.l + (i / Math.max(data.length - 1, 1)) * plotW,
    y: pad.t + plotH - (d.value / max) * plotH,
  }));

  const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"}${p.x},${p.y}`).join(" ");
  const areaPath = linePath + ` L${points[points.length - 1].x},${pad.t + plotH} L${points[0].x},${pad.t + plotH} Z`;

  // Y-axis ticks
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map(f => ({
    y: pad.t + plotH - f * plotH,
    label: Math.round(f * max).toLocaleString(),
  }));

  // X-axis labels — show ~6 evenly spaced
  const step = Math.max(1, Math.floor(data.length / 6));
  const xLabels = data.filter((_, i) => i % step === 0).map((d, idx) => ({
    x: pad.l + ((idx * step) / Math.max(data.length - 1, 1)) * plotW,
    label: d.label.length > 5 ? d.label.slice(-5) : d.label, // show HH:MM
  }));

  return h("div", { className: "chart-container" },
    h("h3", { className: "chart-title" }, title),
    h("svg", { viewBox: `0 0 ${W} ${H}`, className: "line-chart" },
      // Grid lines
      yTicks.map((t, i) =>
        h("line", { key: `g${i}`, x1: pad.l, x2: W - pad.r, y1: t.y, y2: t.y,
          stroke: "#e5e7eb", strokeWidth: 1 })
      ),
      // Y labels
      yTicks.map((t, i) =>
        h("text", { key: `y${i}`, x: pad.l - 5, y: t.y + 4, textAnchor: "end",
          fontSize: 11, fill: "#6b7280" }, t.label)
      ),
      // X labels
      xLabels.map((t, i) =>
        h("text", { key: `x${i}`, x: t.x, y: H - 5, textAnchor: "middle",
          fontSize: 11, fill: "#6b7280" }, t.label)
      ),
      // Area
      h("path", { d: areaPath, fill: color, opacity: 0.15 }),
      // Line
      h("path", { d: linePath, fill: "none", stroke: color, strokeWidth: 2 }),
      // Dots
      points.map((p, i) =>
        h("circle", { key: `d${i}`, cx: p.x, cy: p.y, r: 3, fill: color })
      ),
    )
  );
}

// ---------------------------------------------------------------------------
// Table
// ---------------------------------------------------------------------------

/**
 * Table — simple data table with column headers.
 *
 * Props:
 *   title    (string)           — table heading
 *   columns  (Array<{key: string, label: string}>) — column definitions
 *   rows     (Array<Object>)    — row data, keyed by column keys
 *   maxRows  (number?)          — max rows to show, default 10
 */
function Table({ title, columns, rows, maxRows = 10 }) {
  const items = rows.slice(0, maxRows);
  return h("div", { className: "chart-container" },
    h("h3", { className: "chart-title" }, title),
    h("table", { className: "data-table" },
      h("thead", null,
        h("tr", null, columns.map((c, i) =>
          h("th", { key: i }, c.label)
        ))
      ),
      h("tbody", null,
        items.map((row, ri) =>
          h("tr", { key: ri }, columns.map((c, ci) =>
            h("td", { key: ci }, typeof row[c.key] === "number"
              ? row[c.key].toLocaleString()
              : row[c.key])
          ))
        )
      )
    )
  );
}

// ---------------------------------------------------------------------------
// TagChips
// ---------------------------------------------------------------------------

/**
 * TagChips — compact inline display of tag:count pairs.
 *
 * Props:
 *   tags    (Array<{label: string, value: number}>) — tag data
 *   title   (string?)  — optional heading, default none
 *   limit   (number?)  — max chips to show, default 12
 */
function TagChips({ tags, title, limit = 12 }) {
  const items = tags.slice(0, limit);

  function fmt(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
    if (n >= 1000) return (n / 1000).toFixed(1) + "k";
    return n.toString();
  }

  return h("div", { className: "tag-chips-container" },
    title ? h("h3", { className: "chart-title" }, title) : null,
    h("div", { className: "tag-chips" },
      items.map((t, i) =>
        h("span", { key: i, className: "tag-chip",
          style: { borderColor: COLORS[i % COLORS.length] } },
          h("span", { className: "tag-chip-label" }, t.label),
          h("span", { className: "tag-chip-value",
            style: { color: COLORS[i % COLORS.length] } }, fmt(t.value)),
        )
      )
    )
  );
}

// ---------------------------------------------------------------------------
// SparkBar
// ---------------------------------------------------------------------------

/**
 * SparkBar — tiny inline horizontal bar chart for embedding in strips.
 * No axis labels, no heading — just bars with tooltips.
 *
 * Props:
 *   data   (Array<{label: string, value: number}>) — items
 *   color  (string?)  — bar color, default "#3b82f6"
 *   max    (number?)  — max items, default 6
 */
function SparkBar({ data, color = "#3b82f6", max = 6 }) {
  const items = data.slice(0, max);
  const peak = Math.max(...items.map(d => d.value), 1);
  return h("div", { className: "spark-bar" },
    items.map((d, i) =>
      h("div", { key: i, className: "spark-bar-item", title: `${d.label}: ${d.value.toLocaleString()}` },
        h("div", { className: "spark-bar-fill", style: {
          height: `${Math.max((d.value / peak) * 100, 4)}%`,
          backgroundColor: color,
        }}),
        h("div", { className: "spark-bar-label" }, d.label),
      )
    )
  );
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

window.__components = { StatCard, BarChart, LineChart, Table, TagChips, SparkBar, COLORS };
