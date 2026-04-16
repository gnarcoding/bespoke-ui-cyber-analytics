# Phase 2 — Static Fallback Dashboard (locked)

Baseline dashboard that renders any `SchemaSummary` without an LLM. This is the safety net for Phase 3 and the comparison baseline for judging whether generated UIs are better.

## File layout

```
├── CLAUDE.md              project spec
├── PHASE2.md              this file
├── .gitignore
├── .env                   ANTHROPIC_API_KEY (gitignored)
├── requirements.txt       fastapi, uvicorn, python-dotenv
├── ingest.py              JSONL reader, yields dicts per day/range
├── analyze.py             SchemaSummary dataclass + analysis (no LLM)
├── server.py              FastAPI — /api/summary, /api/dates, static files
├── cache.db               (gitignored, Phase 3)
├── web/
│   ├── index.html         shell — loads React UMD, components, fallback, host
│   ├── styles.css         all dashboard CSS including hero + compressed grid
│   ├── components.jsx     7 chart primitives (source)
│   ├── components.js      esbuild bundle of components.jsx
│   ├── fallback.jsx       fallback dashboard (source)
│   ├── fallback.js        esbuild bundle of fallback.jsx
│   └── host.js            date nav + data fetching shell
├── tests/
│   ├── test_analyze.py
│   ├── test_injection.py
│   └── fixtures/
│       └── sample_logs.jsonl
```

Build step: `npx esbuild web/fallback.jsx --bundle --format=iife --global-name=__ignore --outfile=web/fallback.js --external:react --external:react-dom` (same pattern for components.jsx).

## Panel inventory

The fallback dashboard has two categories of panels:

### Always-on panels
| Panel | Component | Description |
|-------|-----------|-------------|
| At-a-Glance strip | `AtAGlance` | StatCards for total requests, unique IPs/URLs/UAs + SparkBars for methods and ports |
| Attack Tag strip | `AttackTagStrip` | TagChips row of all detected attack pattern tags |
| Request Timeline | `RequestTimeline` | LineChart of hourly request counts |
| Top Source IPs | `TopSourceIPs` | Table with IP, hit count, % of total |
| Top URLs | `TopURLs` | BarChart of most-requested paths |
| URL Clusters | `URLClusters` | BarChart of traffic by category (WordPress, cred files, etc.) |
| Signature Hits | `SignatureHits` | Table of honeypot signature rule matches |

### Conditional panels (render only when relevant tags are present)
| Panel | Component | Fires when |
|-------|-----------|-----------|
| Dominant Actor | `DominantActor` | Top IP > 50% of traffic (non-hero version) |
| Appliance Login Flood | `ApplianceLoginFlood` | `appliance_login` tag > 0 |
| RCE Attempts | `RCEAttempts` | Any of `shell_injection`, `phpunit_rce`, `known_cve` > 0 |
| Credential Harvesting | `CredentialHarvesting` | `credential_access` tag > 0 |
| WordPress Probes | `WordPressProbes` | `wordpress` tag > 0 |
| Path Traversal | `PathTraversal` | `path_traversal` tag > 0 |
| IoT / Router Exploits | `IoTExploits` | `iot_exploit` tag > 0 |
| Cloud SSRF | `CloudSSRF` | `cloud_metadata` or `ssrf` tag > 0 |

### Hero section (full-width layout takeover)
| Component | Fires when | Effect |
|-----------|-----------|--------|
| `HeroSection` (dominant_actor) | Top IP > **65%** of traffic | Full-width hero with IP, %, target URL, port, pattern, method. All other panels move to a compressed 2-column grid below. |
| `HeroSection` (dominant_tag) | Top attack tag > **80%** of traffic | Full-width hero with tag name and %. Same compressed grid below. |
| `DominantActor` (panel) | Top IP > **50%** but hero not active | Normal-sized alert panel in the regular flow. |

Across 32 days of logs (2026-03-16 to 2026-04-16), 7 days trigger hero mode. 25 days use the standard grid layout.

## Chart primitives (Phase 3 API contract)

These are the components available to LLM-generated UIs. Exposed via `window.__components`.

### `StatCard`
Single metric display.
```
label:    string        — metric name
value:    string|number — the metric value
subtitle: string?       — optional secondary text
color:    string?       — accent color for value (default "#3b82f6")
```

### `BarChart`
Horizontal bar chart for ranked data.
```
title:   string                              — chart heading
data:    Array<{label: string, value: number}> — bars to render
color:   string?                              — bar fill color (default "#3b82f6")
maxBars: number?                              — max bars shown (default 10)
```

### `LineChart`
SVG line/area chart for time-series data.
```
title:  string                              — chart heading
data:   Array<{label: string, value: number}> — points in order
color:  string?                              — line/fill color (default "#3b82f6")
height: number?                              — chart height in px (default 200)
```

### `Table`
Data table with column headers.
```
title:   string                                   — table heading
columns: Array<{key: string, label: string}>       — column definitions
rows:    Array<Object>                             — row data keyed by column keys
maxRows: number?                                   — max rows shown (default 10)
```

### `TagChips`
Compact inline tag:count pairs.
```
tags:  Array<{label: string, value: number}> — tag data
title: string?                               — optional heading
limit: number?                               — max chips shown (default 12)
```

### `SparkBar`
Tiny inline bar chart for embedding in strips. No heading or axis labels.
```
data:  Array<{label: string, value: number}> — items
color: string?                               — bar color (default "#3b82f6")
max:   number?                               — max items (default 6)
```

### `COLORS`
Array of 10 hex color strings for consistent palette across components:
`["#3b82f6", "#ef4444", "#10b981", "#f59e0b", "#8b5cf6", "#ec4899", "#06b6d4", "#f97316", "#6366f1", "#14b8a6"]`
