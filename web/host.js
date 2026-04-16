/**
 * Host shell — fetches summary data and renders the dashboard.
 *
 * Phase 3: tries /api/ui for a generated component first, falls back to
 * FallbackDashboard on failure. Includes a "Regenerate" button to bust cache.
 */

(function () {
  const { createElement: h } = React;

  // Parse ?date=YYYY-MM-DD from URL, default to today
  function getDateParam() {
    const params = new URLSearchParams(window.location.search);
    const d = params.get("date");
    if (d && /^\d{4}-\d{2}-\d{2}$/.test(d)) return d;
    return new Date().toISOString().slice(0, 10);
  }

  /**
   * Try to load a generated UI component from /api/ui.
   * Returns the default-exported component, or null on failure.
   */
  async function loadGeneratedUI(date) {
    try {
      const res = await fetch(`/api/ui?date=${date}`);
      if (!res.ok) return null;

      const jsText = await res.text();

      // Execute the bundled IIFE in a Function scope.
      // The bundle assigns to __genUI; we extract the default export.
      const fn = new Function(jsText + "\n; return __genUI;");
      const mod = fn();

      // esbuild IIFE wraps the default export — find it
      const component = mod && (mod.default || mod.Dashboard || mod);
      if (typeof component === "function") return component;

      return null;
    } catch (e) {
      console.warn("Failed to load generated UI:", e);
      return null;
    }
  }

  function App() {
    const [date, setDate] = React.useState(getDateParam);
    const [summary, setSummary] = React.useState(null);
    const [error, setError] = React.useState(null);
    const [loading, setLoading] = React.useState(true);
    const [generatedComponent, setGeneratedComponent] = React.useState(null);
    const [uiSource, setUiSource] = React.useState(null); // 'generated' | 'fallback'
    const [regenerating, setRegenerating] = React.useState(false);

    React.useEffect(() => {
      setLoading(true);
      setError(null);
      setGeneratedComponent(null);
      setUiSource(null);

      // Fetch summary and generated UI in parallel
      Promise.all([
        fetch(`/api/summary?date=${date}`)
          .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }),
        loadGeneratedUI(date),
      ])
        .then(([summaryData, genComponent]) => {
          setSummary(summaryData);
          if (genComponent) {
            setGeneratedComponent(() => genComponent);
            setUiSource("generated");
          } else {
            setUiSource("fallback");
          }
          setLoading(false);
        })
        .catch(err => {
          setError(err.message);
          setLoading(false);
        });

      // Update URL without reload
      const url = new URL(window.location);
      url.searchParams.set("date", date);
      window.history.replaceState({}, "", url);
    }, [date]);

    function shiftDate(days) {
      const d = new Date(date + "T00:00:00");
      d.setDate(d.getDate() + days);
      setDate(d.toISOString().slice(0, 10));
    }

    function handleRegenerate() {
      setRegenerating(true);
      fetch(`/api/ui/regenerate?date=${date}`, { method: "POST" })
        .then(r => r.json())
        .then(result => {
          setRegenerating(false);
          if (result.status === "ok" || result.status === "retry_ok") {
            // Reload the generated UI
            loadGeneratedUI(date).then(comp => {
              if (comp) {
                setGeneratedComponent(() => comp);
                setUiSource("generated");
              }
            });
          }
        })
        .catch(() => setRegenerating(false));
    }

    const sourceLabel = uiSource === "generated"
      ? "AI-generated dashboard"
      : "Static fallback dashboard";

    const DashboardComponent = generatedComponent || window.__FallbackDashboard;

    return h("div", null,
      h("nav", { className: "date-nav" },
        h("button", { onClick: () => shiftDate(-1), className: "nav-btn" }, "\u2190 Prev"),
        h("input", {
          type: "date",
          value: date,
          onChange: e => setDate(e.target.value),
          className: "date-input",
        }),
        h("button", { onClick: () => shiftDate(1), className: "nav-btn" }, "Next \u2192"),
        h("span", {
          style: {
            marginLeft: "16px", fontSize: "12px", color: "#94a3b8",
            display: "inline-flex", alignItems: "center", gap: "8px",
          },
        },
          sourceLabel,
          h("button", {
            onClick: handleRegenerate,
            disabled: regenerating,
            className: "nav-btn",
            style: { fontSize: "11px", padding: "2px 8px" },
          }, regenerating ? "Generating..." : "Regenerate"),
        ),
      ),
      loading
        ? h("div", { className: "dashboard-empty" }, "Loading...")
        : error
          ? h("div", { className: "dashboard-empty" }, "Error: " + error)
          : h(DashboardComponent, { summary }),
    );
  }

  const root = ReactDOM.createRoot(document.getElementById("root"));
  root.render(h(App));
})();
