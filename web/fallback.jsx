/**
 * Fallback dashboard — static, no LLM.
 *
 * Renders a reasonable dashboard from any SchemaSummary. Conditional panels
 * appear only when relevant attack tags are present. This is the safety net
 * for when Phase 3 generation fails, and the baseline for judging whether
 * generated UIs are actually better.
 *
 * Data contract: receives `summary` (SchemaSummary JSON) as a prop.
 * Chart data comes from the summary directly — no /api/data/ calls needed
 * for the fallback since SchemaSummary already has everything.
 */

const { createElement: h, Fragment } = React;
const { StatCard, BarChart, LineChart, Table, TagChips, SparkBar, COLORS } =
  window.__components;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fmt(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
  if (n >= 1000) return (n / 1000).toFixed(1) + "k";
  return n.toLocaleString();
}

function pct(n, total) {
  if (!total) return "0%";
  return ((n / total) * 100).toFixed(1) + "%";
}

function hasTag(summary, tag) {
  return (summary.attack_tags[tag] || 0) > 0;
}

/**
 * Detect whether the day has a single dominant "story" that should get
 * hero treatment:
 *  - A single IP contributing >50% of traffic (DominantActor threshold), OR
 *  - A single attack tag contributing >80% of total traffic.
 *
 * Returns { type, label, detail, ratio } or null.
 */
function detectHero(summary) {
  // Check dominant IP
  if (summary.top_ips && summary.top_ips.length > 0) {
    const [topIP, topCount] = summary.top_ips[0];
    const ipRatio = topCount / summary.total_entries;
    if (ipRatio > 0.65) {
      // Find the target URL/port for narrative
      const targetUrl = summary.top_urls.find(([u]) => u !== "/");
      const topPort = Object.entries(summary.target_ports)
        .sort((a, b) => b[1] - a[1])[0];
      return {
        type: "dominant_actor",
        ip: topIP,
        ipCount: topCount,
        ratio: ipRatio,
        targetUrl: targetUrl ? targetUrl[0] : null,
        targetUrlCount: targetUrl ? targetUrl[1] : 0,
        port: topPort ? topPort[0] : null,
        portCount: topPort ? topPort[1] : 0,
      };
    }
  }

  // Check dominant attack tag (>80% of total traffic)
  const totalEntries = summary.total_entries;
  const tagEntries = Object.entries(summary.attack_tags)
    .sort((a, b) => b[1] - a[1]);
  if (tagEntries.length > 0) {
    const [topTag, topTagCount] = tagEntries[0];
    const tagRatio = topTagCount / totalEntries;
    if (tagRatio > 0.8) {
      return {
        type: "dominant_tag",
        tag: topTag,
        tagLabel: topTag.replace(/_/g, " "),
        tagCount: topTagCount,
        ratio: tagRatio,
      };
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Always-on: At-a-Glance strip
// ---------------------------------------------------------------------------

function AtAGlance({ summary }) {
  const methodData = Object.entries(summary.methods)
    .sort((a, b) => b[1] - a[1])
    .map(([label, value]) => ({ label, value }));

  const portData = Object.entries(summary.target_ports)
    .sort((a, b) => b[1] - a[1])
    .map(([label, value]) => ({ label: ":" + label, value }));

  return h("div", { className: "at-a-glance" },
    h("div", { className: "at-a-glance-stats" },
      h(StatCard, { label: "Total Requests", value: fmt(summary.total_entries) }),
      h(StatCard, { label: "Unique IPs", value: fmt(summary.unique_ips), color: "#ef4444" }),
      h(StatCard, { label: "Unique URLs", value: fmt(summary.unique_urls), color: "#10b981" }),
      h(StatCard, { label: "Unique UAs", value: fmt(summary.unique_useragents), color: "#f59e0b" }),
    ),
    h("div", { className: "at-a-glance-sparks" },
      h("div", { className: "spark-section" },
        h("div", { className: "spark-title" }, "Methods"),
        h(SparkBar, { data: methodData, color: "#8b5cf6" }),
      ),
      h("div", { className: "spark-section" },
        h("div", { className: "spark-title" }, "Target Ports"),
        h(SparkBar, { data: portData, color: "#06b6d4" }),
      ),
    ),
  );
}

// ---------------------------------------------------------------------------
// Always-on: Attack Tags (compact chip row)
// ---------------------------------------------------------------------------

function AttackTagStrip({ summary }) {
  const tags = Object.entries(summary.attack_tags)
    .sort((a, b) => b[1] - a[1])
    .map(([label, value]) => ({ label: label.replace(/_/g, " "), value }));

  if (tags.length === 0) return null;

  return h(TagChips, { tags, title: "Attack Signatures Detected" });
}

// ---------------------------------------------------------------------------
// Always-on: Request Timeline
// ---------------------------------------------------------------------------

function RequestTimeline({ summary }) {
  const data = Object.entries(summary.time_buckets)
    .map(([label, value]) => ({ label, value }));

  if (data.length === 0) return null;

  return h(LineChart, {
    title: "Requests Over Time",
    data,
    color: "#3b82f6",
  });
}

// ---------------------------------------------------------------------------
// Always-on: Top Source IPs
// ---------------------------------------------------------------------------

function TopSourceIPs({ summary }) {
  const rows = summary.top_ips.map(([ip, count]) => ({
    ip,
    count,
    pct: pct(count, summary.total_entries),
  }));

  return h(Table, {
    title: "Top Source IPs",
    columns: [
      { key: "ip", label: "IP Address" },
      { key: "count", label: "Hits" },
      { key: "pct", label: "% Total" },
    ],
    rows,
  });
}

// ---------------------------------------------------------------------------
// Always-on: Top URLs
// ---------------------------------------------------------------------------

function TopURLs({ summary }) {
  const data = summary.top_urls.map(([label, value]) => ({ label, value }));
  return h(BarChart, { title: "Top Requested URLs", data, color: "#10b981" });
}

// ---------------------------------------------------------------------------
// Always-on: URL Cluster Breakdown
// ---------------------------------------------------------------------------

function URLClusters({ summary }) {
  const data = Object.entries(summary.url_clusters)
    .sort((a, b) => b[1] - a[1])
    .map(([label, value]) => ({ label, value }));

  return h(BarChart, { title: "Traffic by Category", data, color: "#8b5cf6", maxBars: 12 });
}

// ---------------------------------------------------------------------------
// Always-on: Signature Hits
// ---------------------------------------------------------------------------

function SignatureHits({ summary }) {
  const rows = Object.entries(summary.signature_hits)
    .sort((a, b) => b[1] - a[1])
    .map(([id, count]) => ({
      id: "#" + id,
      comment: summary.signature_comments[id] || "\u2014",
      count,
    }));

  if (rows.length === 0) return null;

  return h(Table, {
    title: "Honeypot Signature Hits",
    columns: [
      { key: "id", label: "Sig ID" },
      { key: "comment", label: "Rule" },
      { key: "count", label: "Hits" },
    ],
    rows,
  });
}

// ---------------------------------------------------------------------------
// Hero Section — full-width top panel for days with a dominant story
// ---------------------------------------------------------------------------

function HeroSection({ summary, hero }) {
  if (hero.type === "dominant_actor") {
    // Build a narrative sentence
    const pctStr = (hero.ratio * 100).toFixed(0);
    const urlDisplay = hero.targetUrl
      ? (hero.targetUrl.length > 40 ? hero.targetUrl.slice(0, 40) + "..." : hero.targetUrl)
      : null;

    // Find the dominant attack tag (likely matches this actor)
    const dominantTag = Object.entries(summary.attack_tags)
      .sort((a, b) => b[1] - a[1])[0];

    return h("div", { className: "hero-section" },
      h("div", { className: "hero-label" }, "Dominant Actor"),
      h("div", { className: "hero-ip" }, hero.ip),
      h("div", { className: "hero-stat-line" },
        h("span", { className: "hero-big-pct" }, pctStr + "%"),
        " of all traffic",
        h("span", { className: "hero-sep" }, "\u00b7"),
        fmt(hero.ipCount) + " of " + fmt(summary.total_entries) + " requests",
      ),
      h("div", { className: "hero-details" },
        urlDisplay ? h("div", { className: "hero-detail" },
          h("span", { className: "hero-detail-label" }, "Target"),
          h("span", { className: "hero-detail-value" }, urlDisplay),
        ) : null,
        hero.port ? h("div", { className: "hero-detail" },
          h("span", { className: "hero-detail-label" }, "Port"),
          h("span", { className: "hero-detail-value" }, ":" + hero.port),
        ) : null,
        dominantTag ? h("div", { className: "hero-detail" },
          h("span", { className: "hero-detail-label" }, "Pattern"),
          h("span", { className: "hero-detail-value" }, dominantTag[0].replace(/_/g, " ")),
        ) : null,
        h("div", { className: "hero-detail" },
          h("span", { className: "hero-detail-label" }, "Method"),
          h("span", { className: "hero-detail-value" },
            Object.entries(summary.methods).sort((a, b) => b[1] - a[1])[0][0]),
        ),
      ),
    );
  }

  if (hero.type === "dominant_tag") {
    const pctStr = (hero.ratio * 100).toFixed(0);

    return h("div", { className: "hero-section hero-tag" },
      h("div", { className: "hero-label" }, "Dominant Pattern"),
      h("div", { className: "hero-ip" }, hero.tagLabel),
      h("div", { className: "hero-stat-line" },
        h("span", { className: "hero-big-pct" }, pctStr + "%"),
        " of all traffic",
        h("span", { className: "hero-sep" }, "\u00b7"),
        fmt(hero.tagCount) + " of " + fmt(summary.total_entries) + " requests",
      ),
    );
  }

  return null;
}

// ---------------------------------------------------------------------------
// Conditional: Dominant Actor (non-hero, for moderate dominance 50-80%)
// Used only when hero is NOT rendering — the hero replaces this.
// ---------------------------------------------------------------------------

function DominantActor({ summary, heroActive }) {
  if (heroActive) return null;
  if (!summary.top_ips || summary.top_ips.length === 0) return null;

  const [topIP, topCount] = summary.top_ips[0];
  const ratio = topCount / summary.total_entries;
  if (ratio <= 0.5) return null;

  const targetUrl = summary.top_urls.find(([u]) => u !== "/");
  const targetUrlStr = targetUrl ? targetUrl[0] : "/";

  const topPort = Object.entries(summary.target_ports)
    .sort((a, b) => b[1] - a[1])[0];

  return h("div", { className: "chart-container panel-alert" },
    h("h3", { className: "chart-title" }, "Dominant Actor Detected"),
    h("div", { className: "dominant-actor" },
      h("div", { className: "dominant-actor-grid" },
        h(StatCard, {
          label: "Source IP",
          value: topIP,
          color: "#ef4444",
        }),
        h(StatCard, {
          label: "Request Count",
          value: fmt(topCount),
          subtitle: pct(topCount, summary.total_entries) + " of all traffic",
          color: "#ef4444",
        }),
        h(StatCard, {
          label: "Target URL",
          value: targetUrlStr.length > 30
            ? targetUrlStr.slice(0, 30) + "..."
            : targetUrlStr,
          color: "#f59e0b",
        }),
        topPort ? h(StatCard, {
          label: "Target Port",
          value: ":" + topPort[0],
          subtitle: fmt(topPort[1]) + " hits",
          color: "#f59e0b",
        }) : null,
      ),
    ),
  );
}

// ---------------------------------------------------------------------------
// Conditional: Appliance Login Flood
// ---------------------------------------------------------------------------

function ApplianceLoginFlood({ summary }) {
  if (!hasTag(summary, "appliance_login")) return null;

  const count = summary.attack_tags.appliance_login;

  // Find matching signature
  const sigComment = Object.entries(summary.signature_comments)
    .find(([, c]) => /fortinet|sonicwall|palo alto|vpn/i.test(c));

  return h("div", { className: "chart-container panel-warn" },
    h("h3", { className: "chart-title" }, "Appliance Login Brute Force"),
    h("div", { className: "panel-body" },
      h(StatCard, {
        label: "Login Attempts",
        value: fmt(count),
        subtitle: sigComment
          ? "Matched: " + sigComment[1]
          : pct(count, summary.total_entries) + " of traffic",
        color: "#ef4444",
      }),
    ),
  );
}

// ---------------------------------------------------------------------------
// Conditional: Credential Harvesting
// ---------------------------------------------------------------------------

function CredentialHarvesting({ summary }) {
  if (!hasTag(summary, "credential_access")) return null;

  const count = summary.attack_tags.credential_access;

  // Pull credential-related URLs from top_urls
  const credUrls = summary.top_urls
    .filter(([u]) => /\.(env|git|aws|ssh|npm|pg|htpasswd|svn)|credentials|secrets|serviceAccount|appsettings|id_rsa/i.test(u))
    .map(([label, value]) => ({ label, value }));

  return h("div", { className: "chart-container" },
    h("h3", { className: "chart-title" },
      "Credential / Secret Harvesting",
      h("span", { className: "panel-count" }, " \u2014 " + fmt(count) + " hits"),
    ),
    credUrls.length > 0
      ? h(BarChart, { title: "", data: credUrls, color: "#ef4444", maxBars: 8 })
      : h("p", { className: "panel-note" }, fmt(count) + " attempts to access credential files (.env, .git/config, secrets.json, etc.)"),
  );
}

// ---------------------------------------------------------------------------
// Conditional: RCE Attempts (shell_injection + phpunit_rce + known_cve)
// ---------------------------------------------------------------------------

function RCEAttempts({ summary }) {
  const tags = ["shell_injection", "phpunit_rce", "known_cve"];
  const present = tags.filter(t => hasTag(summary, t));
  if (present.length === 0) return null;

  const data = present.map(t => ({
    label: t.replace(/_/g, " "),
    value: summary.attack_tags[t],
  })).sort((a, b) => b.value - a.value);

  const total = data.reduce((s, d) => s + d.value, 0);

  return h("div", { className: "chart-container panel-warn" },
    h("h3", { className: "chart-title" },
      "Remote Code Execution Attempts",
      h("span", { className: "panel-count" }, " \u2014 " + fmt(total) + " total"),
    ),
    h(BarChart, { title: "", data, color: "#ef4444" }),
  );
}

// ---------------------------------------------------------------------------
// Conditional: WordPress Probes
// ---------------------------------------------------------------------------

function WordPressProbes({ summary }) {
  if (!hasTag(summary, "wordpress")) return null;

  const count = summary.attack_tags.wordpress;
  const wpUrls = summary.top_urls
    .filter(([u]) => /wp-|xmlrpc|wp-json/i.test(u))
    .map(([label, value]) => ({ label, value }));

  return h("div", { className: "chart-container" },
    h("h3", { className: "chart-title" },
      "WordPress Probes",
      h("span", { className: "panel-count" }, " \u2014 " + fmt(count) + " hits"),
    ),
    wpUrls.length > 0
      ? h(BarChart, { title: "", data: wpUrls, color: "#f59e0b" })
      : h("p", { className: "panel-note" }, fmt(count) + " requests targeting WordPress endpoints"),
  );
}

// ---------------------------------------------------------------------------
// Conditional: Path Traversal
// ---------------------------------------------------------------------------

function PathTraversal({ summary }) {
  if (!hasTag(summary, "path_traversal")) return null;

  const count = summary.attack_tags.path_traversal;
  const travUrls = summary.top_urls
    .filter(([u]) => /\.\.\//i.test(u) || /%2e%2e/i.test(u))
    .map(([label, value]) => ({ label, value }));

  return h("div", { className: "chart-container" },
    h("h3", { className: "chart-title" },
      "Path Traversal Attempts",
      h("span", { className: "panel-count" }, " \u2014 " + fmt(count) + " hits"),
    ),
    travUrls.length > 0
      ? h(BarChart, { title: "", data: travUrls, color: "#f97316", maxBars: 5 })
      : h("p", { className: "panel-note" }, fmt(count) + " path traversal attempts (../ sequences)"),
  );
}

// ---------------------------------------------------------------------------
// Conditional: IoT / Router Exploits
// ---------------------------------------------------------------------------

function IoTExploits({ summary }) {
  if (!hasTag(summary, "iot_exploit")) return null;

  const count = summary.attack_tags.iot_exploit;
  return h("div", { className: "chart-container" },
    h("h3", { className: "chart-title" },
      "IoT / Router Exploits",
      h("span", { className: "panel-count" }, " \u2014 " + fmt(count) + " hits"),
    ),
    h("p", { className: "panel-note" },
      fmt(count) + " requests targeting IoT/router devices (GPON, Boa, HNAP)"),
  );
}

// ---------------------------------------------------------------------------
// Conditional: Cloud Metadata / SSRF
// ---------------------------------------------------------------------------

function CloudSSRF({ summary }) {
  const hasMeta = hasTag(summary, "cloud_metadata");
  const hasSSRF = hasTag(summary, "ssrf");
  if (!hasMeta && !hasSSRF) return null;

  const data = [];
  if (hasSSRF) data.push({ label: "SSRF (proxy requests)", value: summary.attack_tags.ssrf });
  if (hasMeta) data.push({ label: "Cloud metadata (169.254.169.254)", value: summary.attack_tags.cloud_metadata });

  const total = data.reduce((s, d) => s + d.value, 0);

  return h("div", { className: "chart-container" },
    h("h3", { className: "chart-title" },
      "SSRF / Cloud Metadata",
      h("span", { className: "panel-count" }, " \u2014 " + fmt(total) + " hits"),
    ),
    h(BarChart, { title: "", data, color: "#06b6d4" }),
  );
}

// ---------------------------------------------------------------------------
// Main Dashboard
// ---------------------------------------------------------------------------

function FallbackDashboard({ summary }) {
  if (!summary) {
    return h("div", { className: "dashboard-empty" }, "No data loaded.");
  }

  const dateLabel = summary.date_range[0] === summary.date_range[1]
    ? summary.date_range[0]
    : summary.date_range[0] + " \u2013 " + summary.date_range[1];

  const hero = detectHero(summary);

  // When a hero fires, the remaining panels go into a compressed 2-col grid.
  // When no hero, the original single-column flow is used.
  const remainingPanels = [
    h(AttackTagStrip, { summary, key: "tags" }),
    h(RequestTimeline, { summary, key: "timeline" }),
    h(DominantActor, { summary, heroActive: !!hero, key: "dom" }),
    h(ApplianceLoginFlood, { summary, key: "appliance" }),
    h(RCEAttempts, { summary, key: "rce" }),
    h(CredentialHarvesting, { summary, key: "cred" }),
    h(TopSourceIPs, { summary, key: "ips" }),
    h(TopURLs, { summary, key: "urls" }),
    h(URLClusters, { summary, key: "clusters" }),
    h(SignatureHits, { summary, key: "sigs" }),
    h(WordPressProbes, { summary, key: "wp" }),
    h(PathTraversal, { summary, key: "trav" }),
    h(IoTExploits, { summary, key: "iot" }),
    h(CloudSSRF, { summary, key: "ssrf" }),
  ];

  return h("div", { className: "dashboard" + (hero ? " dashboard-hero-mode" : "") },
    h("header", { className: "dashboard-header" },
      h("h1", null, "DShield Webhoneypot"),
      h("h2", null, dateLabel),
    ),

    // Hero takes over the top when present
    hero ? h(HeroSection, { summary, hero }) : null,

    // At-a-glance always shows, but gets compact class in hero mode
    h(AtAGlance, { summary }),

    // Remaining panels: compressed grid in hero mode, normal flow otherwise
    hero
      ? h("div", { className: "compressed-grid" }, remainingPanels)
      : h(Fragment, null, ...remainingPanels),

    h("footer", { className: "dashboard-footer" },
      "Fallback dashboard \u2014 static render from SchemaSummary"
    ),
  );
}

window.__FallbackDashboard = FallbackDashboard;
