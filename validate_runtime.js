/**
 * Runtime validation for generated UI components.
 *
 * Loads the esbuild-bundled JS in a jsdom environment with mock React,
 * mock window.__components, and realistic endpoint data. Renders the
 * component and catches any runtime errors (prop shape mismatches,
 * undefined-is-not-a-function, etc.) that esbuild can't detect.
 *
 * Usage:  node validate_runtime.js <path-to-bundled-js> [summary-json-path]
 * Exit 0 = render succeeded, exit 1 = render threw, stderr has the error.
 */

const fs = require("fs");
const { JSDOM } = require("jsdom");

// ---------------------------------------------------------------------------
// Mock summary — realistic shape matching SchemaSummary.to_dict()
// ---------------------------------------------------------------------------

const MOCK_SUMMARY = {
  date_range: ["2026-04-15", "2026-04-15"],
  total_entries: 1247,
  unique_ips: 83,
  unique_urls: 214,
  unique_useragents: 47,
  entries_with_body: 89,
  methods: { GET: 980, POST: 210, HEAD: 57 },
  top_ips: [["192.168.1.100", 412], ["10.0.0.5", 198], ["172.16.0.3", 87]],
  top_urls: [["/wp-login.php", 312], ["/admin/", 98], ["/.env", 67], ["/", 54]],
  top_useragents: [["Mozilla/5.0", 890], ["curl/7.68", 120], ["python-requests/2.28", 45]],
  top_methods: [["GET", 980], ["POST", 210], ["HEAD", 57]],
  attack_tags: { wordpress: 312, credential_access: 67, path_traversal: 23, shell_injection: 8 },
  url_clusters: { "WordPress probes": 312, "Credential files": 67, "Root/index": 54 },
  time_buckets: {
    "00:00": 42, "01:00": 38, "02:00": 51, "03:00": 67, "04:00": 89,
    "05:00": 112, "06:00": 98, "07:00": 76, "08:00": 63, "09:00": 54,
    "10:00": 48, "11:00": 41, "12:00": 39, "13:00": 45, "14:00": 52,
    "15:00": 58, "16:00": 47, "17:00": 35, "18:00": 28, "19:00": 22,
    "20:00": 31, "21:00": 37, "22:00": 43, "23:00": 51,
  },
  signature_hits: { "2100000": 312, "2100001": 67 },
  signature_comments: { "2100000": "WordPress login probe", "2100001": "Credential file access" },
  target_ports: { "80": 890, "443": 210, "8080": 147 },
};

// ---------------------------------------------------------------------------
// Mock endpoint responses — match the actual server shapes exactly
// ---------------------------------------------------------------------------

const MOCK_ENDPOINTS = {
  "/api/data/top_ips": [
    { ip: "192.168.1.100", count: 412, pct: 33.0 },
    { ip: "10.0.0.5", count: 198, pct: 15.9 },
    { ip: "172.16.0.3", count: 87, pct: 7.0 },
  ],
  "/api/data/top_urls": [
    { url: "/wp-login.php", count: 312, pct: 25.0 },
    { url: "/admin/", count: 98, pct: 7.9 },
    { url: "/.env", count: 67, pct: 5.4 },
  ],
  "/api/data/top_useragents": [
    { useragent: "Mozilla/5.0", count: 890, pct: 71.4 },
    { useragent: "curl/7.68", count: 120, pct: 9.6 },
  ],
  "/api/data/top_methods": [
    { method: "GET", count: 980 },
    { method: "POST", count: 210 },
  ],
  "/api/data/time_buckets": [
    { bucket: "00:00", count: 42 }, { bucket: "06:00", count: 98 },
    { bucket: "12:00", count: 39 }, { bucket: "18:00", count: 28 },
  ],
  "/api/data/attack_tags": [
    { tag: "wordpress", count: 312 },
    { tag: "credential_access", count: 67 },
    { tag: "path_traversal", count: 23 },
  ],
  "/api/data/url_clusters": [
    { cluster: "WordPress probes", count: 312 },
    { cluster: "Credential files", count: 67 },
  ],
  "/api/data/signature_hits": [
    { sig_id: "2100000", comment: "WordPress login probe", count: 312 },
    { sig_id: "2100001", comment: "Credential file access", count: 67 },
  ],
  "/api/data/target_ports": [
    { port: "80", count: 890 },
    { port: "443", count: 210 },
  ],
  "/api/data/body_stats": { entries_with_body: 89, total_entries: 1247, pct: 7.1 },
  "/api/data/dominant_actor_detail": null,
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function run(bundledJsPath, summaryJsonPath) {
  const bundledJs = fs.readFileSync(bundledJsPath, "utf-8");

  let summary = MOCK_SUMMARY;
  if (summaryJsonPath) {
    summary = JSON.parse(fs.readFileSync(summaryJsonPath, "utf-8"));
  }

  // Create a jsdom environment with minimal React shim
  const dom = new JSDOM(`<!DOCTYPE html><html><body><div id="root"></div></body></html>`, {
    url: "http://localhost:8000",
    runScripts: "dangerously",
    pretendToBeVisual: true,
  });

  const { window } = dom;

  // --- Inject minimal React shim ---
  // We only need createElement, useState, useEffect, Fragment to survive
  // initial render. We don't need actual DOM updates.
  const renderLog = [];
  let effectCallbacks = [];

  function createElement(type, props, ...children) {
    // Track what was rendered for debugging
    const name = typeof type === "function" ? (type.name || "Anonymous") : type;
    renderLog.push(name);

    // If it's a function component, call it to check for runtime errors
    if (typeof type === "function") {
      try {
        return type(props || {});
      } catch (e) {
        throw new Error(`Runtime error in <${name}>: ${e.message}`);
      }
    }
    return { type, props, children };
  }

  function useState(init) {
    const val = typeof init === "function" ? init() : init;
    return [val, () => {}];
  }

  function useEffect(cb) {
    effectCallbacks.push(cb);
  }

  const React = {
    createElement,
    useState,
    useEffect,
    useCallback: (fn) => fn,
    useMemo: (fn) => fn(),
    useRef: (val) => ({ current: val }),
    Fragment: "Fragment",
  };

  window.React = React;
  window.ReactDOM = { createRoot: () => ({ render: () => {} }) };

  // --- Inject mock components that validate their props ---
  function makeChartComponent(name, requiredPropCheck) {
    const comp = function (props) {
      if (requiredPropCheck) requiredPropCheck(name, props);
      return { type: name, props };
    };
    Object.defineProperty(comp, "name", { value: name });
    return comp;
  }

  window.__components = {
    StatCard: makeChartComponent("StatCard"),
    BarChart: makeChartComponent("BarChart", (name, props) => {
      if (props.data !== undefined && props.data !== null && !Array.isArray(props.data)) {
        throw new Error(`${name}: data must be an array, got ${typeof props.data}`);
      }
    }),
    LineChart: makeChartComponent("LineChart", (name, props) => {
      if (props.data !== undefined && props.data !== null && !Array.isArray(props.data)) {
        throw new Error(`${name}: data must be an array, got ${typeof props.data}`);
      }
    }),
    Table: makeChartComponent("Table", (name, props) => {
      if (props.columns && !Array.isArray(props.columns)) {
        throw new Error(`${name}: columns must be an array, got ${typeof props.columns}`);
      }
      if (props.rows && !Array.isArray(props.rows)) {
        throw new Error(`${name}: rows must be an array, got ${typeof props.rows}`);
      }
    }),
    TagChips: makeChartComponent("TagChips"),
    SparkBar: makeChartComponent("SparkBar"),
    COLORS: ["#3b82f6", "#ef4444", "#10b981", "#f59e0b", "#8b5cf6",
             "#ec4899", "#06b6d4", "#f97316", "#6366f1", "#14b8a6"],
  };

  // --- Mock fetch that returns endpoint data ---
  window.fetch = function (url) {
    const urlObj = new URL(url, "http://localhost:8000");
    const path = urlObj.pathname;
    const data = MOCK_ENDPOINTS[path];
    return Promise.resolve({
      ok: data !== undefined,
      status: data !== undefined ? 200 : 404,
      json: () => Promise.resolve(data ?? null),
      text: () => Promise.resolve(JSON.stringify(data ?? null)),
    });
  };

  // --- Load the bundled component ---
  try {
    window.eval(bundledJs);
  } catch (e) {
    process.stderr.write(`Failed to evaluate bundled JS: ${e.message}\n`);
    process.exit(1);
  }

  const mod = window.__genUI;
  if (!mod) {
    process.stderr.write("Bundle did not set window.__genUI\n");
    process.exit(1);
  }

  const Component = mod.default || mod.Dashboard || mod;
  if (typeof Component !== "function") {
    process.stderr.write(`__genUI is not a function (got ${typeof Component})\n`);
    process.exit(1);
  }

  // --- Render the component ---
  try {
    createElement(Component, { summary });
  } catch (e) {
    process.stderr.write(`Runtime render error: ${e.message}\n`);
    process.exit(1);
  }

  // --- Run useEffect callbacks (triggers fetch calls) ---
  for (const cb of effectCallbacks) {
    try {
      const cleanup = cb();
      if (typeof cleanup === "function") cleanup();
    } catch (e) {
      process.stderr.write(`useEffect error: ${e.message}\n`);
      process.exit(1);
    }
  }

  // Success
  process.stderr.write(`OK — rendered ${renderLog.length} elements (${[...new Set(renderLog)].join(", ")})\n`);
  process.exit(0);
}

// --- CLI ---
const args = process.argv.slice(2);
if (args.length < 1) {
  process.stderr.write("Usage: node validate_runtime.js <bundled.js> [summary.json]\n");
  process.exit(1);
}

run(args[0], args[1]);
