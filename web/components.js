var __ignore2 = (() => {
  // web/components.jsx
  var { createElement: h, Fragment } = React;
  var COLORS = [
    "#3b82f6",
    "#ef4444",
    "#10b981",
    "#f59e0b",
    "#8b5cf6",
    "#ec4899",
    "#06b6d4",
    "#f97316",
    "#6366f1",
    "#14b8a6"
  ];
  function StatCard({ label, value, subtitle, color = "#3b82f6" }) {
    return h(
      "div",
      { className: "stat-card" },
      h("div", { className: "stat-label" }, label),
      h("div", { className: "stat-value", style: { color } }, value),
      subtitle ? h("div", { className: "stat-subtitle" }, subtitle) : null
    );
  }
  function BarChart({ title, data, color = "#3b82f6", maxBars = 10 }) {
    const items = data.slice(0, maxBars);
    const max = Math.max(...items.map((d) => d.value), 1);
    return h(
      "div",
      { className: "chart-container" },
      h("h3", { className: "chart-title" }, title),
      h(
        "div",
        { className: "bar-chart" },
        items.map(
          (d, i) => h(
            "div",
            { key: i, className: "bar-row" },
            h("div", { className: "bar-label", title: d.label }, d.label),
            h(
              "div",
              { className: "bar-track" },
              h("div", { className: "bar-fill", style: {
                width: `${d.value / max * 100}%`,
                backgroundColor: color
              } })
            ),
            h("div", { className: "bar-value" }, d.value.toLocaleString())
          )
        )
      )
    );
  }
  function LineChart({ title, data, color = "#3b82f6", height = 200 }) {
    if (!data || data.length === 0) return null;
    const W = 700, H = height, pad = { t: 10, r: 10, b: 40, l: 50 };
    const plotW = W - pad.l - pad.r;
    const plotH = H - pad.t - pad.b;
    const max = Math.max(...data.map((d) => d.value), 1);
    const points = data.map((d, i) => ({
      x: pad.l + i / Math.max(data.length - 1, 1) * plotW,
      y: pad.t + plotH - d.value / max * plotH
    }));
    const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"}${p.x},${p.y}`).join(" ");
    const areaPath = linePath + ` L${points[points.length - 1].x},${pad.t + plotH} L${points[0].x},${pad.t + plotH} Z`;
    const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => ({
      y: pad.t + plotH - f * plotH,
      label: Math.round(f * max).toLocaleString()
    }));
    const step = Math.max(1, Math.floor(data.length / 6));
    const xLabels = data.filter((_, i) => i % step === 0).map((d, idx) => ({
      x: pad.l + idx * step / Math.max(data.length - 1, 1) * plotW,
      label: d.label.length > 5 ? d.label.slice(-5) : d.label
      // show HH:MM
    }));
    return h(
      "div",
      { className: "chart-container" },
      h("h3", { className: "chart-title" }, title),
      h(
        "svg",
        { viewBox: `0 0 ${W} ${H}`, className: "line-chart" },
        // Grid lines
        yTicks.map(
          (t, i) => h("line", {
            key: `g${i}`,
            x1: pad.l,
            x2: W - pad.r,
            y1: t.y,
            y2: t.y,
            stroke: "#e5e7eb",
            strokeWidth: 1
          })
        ),
        // Y labels
        yTicks.map(
          (t, i) => h("text", {
            key: `y${i}`,
            x: pad.l - 5,
            y: t.y + 4,
            textAnchor: "end",
            fontSize: 11,
            fill: "#6b7280"
          }, t.label)
        ),
        // X labels
        xLabels.map(
          (t, i) => h("text", {
            key: `x${i}`,
            x: t.x,
            y: H - 5,
            textAnchor: "middle",
            fontSize: 11,
            fill: "#6b7280"
          }, t.label)
        ),
        // Area
        h("path", { d: areaPath, fill: color, opacity: 0.15 }),
        // Line
        h("path", { d: linePath, fill: "none", stroke: color, strokeWidth: 2 }),
        // Dots
        points.map(
          (p, i) => h("circle", { key: `d${i}`, cx: p.x, cy: p.y, r: 3, fill: color })
        )
      )
    );
  }
  function Table({ title, columns, rows, maxRows = 10 }) {
    const items = rows.slice(0, maxRows);
    return h(
      "div",
      { className: "chart-container" },
      h("h3", { className: "chart-title" }, title),
      h(
        "table",
        { className: "data-table" },
        h(
          "thead",
          null,
          h("tr", null, columns.map(
            (c, i) => h("th", { key: i }, c.label)
          ))
        ),
        h(
          "tbody",
          null,
          items.map(
            (row, ri) => h("tr", { key: ri }, columns.map(
              (c, ci) => h("td", { key: ci }, typeof row[c.key] === "number" ? row[c.key].toLocaleString() : row[c.key])
            ))
          )
        )
      )
    );
  }
  function TagChips({ tags, title, limit = 12 }) {
    const items = tags.slice(0, limit);
    function fmt(n) {
      if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
      if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
      return n.toString();
    }
    return h(
      "div",
      { className: "tag-chips-container" },
      title ? h("h3", { className: "chart-title" }, title) : null,
      h(
        "div",
        { className: "tag-chips" },
        items.map(
          (t, i) => h(
            "span",
            {
              key: i,
              className: "tag-chip",
              style: { borderColor: COLORS[i % COLORS.length] }
            },
            h("span", { className: "tag-chip-label" }, t.label),
            h("span", {
              className: "tag-chip-value",
              style: { color: COLORS[i % COLORS.length] }
            }, fmt(t.value))
          )
        )
      )
    );
  }
  function SparkBar({ data, color = "#3b82f6", max = 6 }) {
    const items = data.slice(0, max);
    const peak = Math.max(...items.map((d) => d.value), 1);
    return h(
      "div",
      { className: "spark-bar" },
      items.map(
        (d, i) => h(
          "div",
          { key: i, className: "spark-bar-item", title: `${d.label}: ${d.value.toLocaleString()}` },
          h("div", { className: "spark-bar-fill", style: {
            height: `${Math.max(d.value / peak * 100, 4)}%`,
            backgroundColor: color
          } }),
          h("div", { className: "spark-bar-label" }, d.label)
        )
      )
    );
  }
  window.__components = { StatCard, BarChart, LineChart, Table, TagChips, SparkBar, COLORS };
})();
