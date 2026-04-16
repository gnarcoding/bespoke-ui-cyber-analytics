/**
 * Host shell — fetches summary data and renders the dashboard.
 *
 * In Phase 3+, this will first try /api/ui to get a generated component,
 * falling back to FallbackDashboard on failure. For now, always uses fallback.
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

  // Date navigation wrapper
  function App() {
    const [date, setDate] = React.useState(getDateParam);
    const [summary, setSummary] = React.useState(null);
    const [error, setError] = React.useState(null);
    const [loading, setLoading] = React.useState(true);

    React.useEffect(() => {
      setLoading(true);
      setError(null);
      fetch(`/api/summary?date=${date}`)
        .then(r => {
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          return r.json();
        })
        .then(data => {
          setSummary(data);
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
      ),
      loading
        ? h("div", { className: "dashboard-empty" }, "Loading...")
        : error
          ? h("div", { className: "dashboard-empty" }, "Error: " + error)
          : h(window.__FallbackDashboard, { summary }),
    );
  }

  const root = ReactDOM.createRoot(document.getElementById("root"));
  root.render(h(App));
})();
