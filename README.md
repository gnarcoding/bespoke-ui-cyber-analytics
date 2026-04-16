# Generative-UI Honeypot Dashboard

A honeypot dashboard that **writes its own UI**. Instead of a fixed layout with static charts, this dashboard uses an LLM to analyze your [DShield](https://dshield.org/) webhoneypot logs and generate a React dashboard tailored to whatever attack patterns are actually happening.

WordPress brute force day? You get a WordPress-focused dashboard. Cloud metadata SSRF probes? The UI reshapes to surface that. The dashboard follows the attacks.

![Dashboard on April 15 — dominant IP hero mode with attack signature breakdown](screenshot_apr15.png)

![Dashboard on March 27 — remote code execution attempts highlighted](screenshot_mar27.png)

![Dashboard on March 22 — broader attack mix, different layout](screenshot_mar22.png)

> Each screenshot is from a **different day of logs** — same codebase, same server, completely different dashboards generated automatically.

## How It Works

1. **Ingest** -- reads DShield webhoneypot JSONL log files
2. **Analyze** -- pure Python analysis extracts attack patterns, clusters URLs, tags signatures (no LLM, no raw log strings)
3. **Generate** -- sends the structured summary to Claude, gets back a single-file React component shaped to that day's attacks
4. **Cache** -- generated UIs are cached by structural hash in SQLite, so the dashboard stays stable until the attack profile meaningfully changes
5. **Serve** -- FastAPI backend serves the generated UI inside a sandboxed iframe; the UI fetches aggregated data at render time

The LLM **never sees raw log content** (attackers control User-Agent, URLs, headers, and body -- prompt injection is a real threat). It only sees sanitized structural summaries: categories, counts, and pattern labels.

## Quick Start

```bash
# Clone and set up
git clone <repo-url> && cd hpot-ui
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
npm install

# Add your Anthropic API key
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# Run
python server.py
# Open http://localhost:8000
```

### Requirements

- Python 3.11+
- Node.js (for esbuild validation of generated components)
- An [Anthropic API key](https://console.anthropic.com/)
- DShield webhoneypot log files (JSONL format, one entry per line)

## Architecture

```
webhoneypot logs (JSONL)
        |
    ingest.py          -- read & parse log files
        |
    analyze.py         -- extract patterns, cluster URLs, tag attacks (NO LLM)
        |
   SchemaSummary       -- structured summary (never raw log strings)
        |
   generate_ui.py      -- Claude generates a React component from the summary
        |
    server.py          -- FastAPI serves UI + data endpoints
        |
   sandboxed iframe    -- generated UI renders, fetches data via postMessage
```

### Key Files

| File | What it does |
|---|---|
| `ingest.py` | Reads JSONL log files, yields dicts, skips malformed lines |
| `analyze.py` | Pure Python log analysis -- URL clustering, attack tagging, field cardinalities |
| `generate_ui.py` | Calls Claude to generate a React dashboard component, caches in SQLite |
| `server.py` | FastAPI backend -- summary, UI, data, and raw log endpoints |
| `web/index.html` | Minimal host shell that renders the generated component in a sandboxed iframe |
| `web/fallback.jsx` | Static fallback dashboard if generation fails |
| `prompts/ui_generator.txt` | System prompt that tells Claude how to build the UI |
| `validate_runtime.js` | Validates generated components compile and render correctly |

## Security Model

This is a honeypot dashboard -- the data it visualizes is **attacker-controlled by definition**. The security approach:

- **Sanitization layer**: The analyzer produces structured summaries, never raw log strings. The LLM never sees verbatim attacker input.
- **Sandboxed rendering**: Generated UI runs in an iframe with `sandbox="allow-scripts"` (no `allow-same-origin`). Even malicious generated code can't access parent cookies or make same-origin requests.
- **No baked-in data**: The generated UI component contains no log data. It fetches aggregated data at render time via `/api/data/*` endpoints. React handles escaping.
- **Server-side escaping**: The raw log endpoint HTML-escapes every field before returning.
- **Validation**: Generated components are validated through esbuild before serving. Failures retry once, then fall back to the static dashboard.

## DShield Webhoneypot Log Format

Each line is a JSON object:

```json
{
  "time": "2026-03-22T14:30:00Z",
  "sip": "192.168.1.100",
  "dip": "10.0.0.1",
  "method": "GET",
  "url": "/wp-login.php",
  "headers": { "Host": "example.com", "User-Agent": "..." },
  "useragent": "Mozilla/5.0 ...",
  "data": "",
  "version": "HTTP/1.1",
  "response_id": 200,
  "signature_id": { "rule": "..." }
}
```

Logs are expected at `/srv/log/webhoneypot_YYYY-MM-DD.json` (configurable in `ingest.py`).

## Built With

- [Claude](https://anthropic.com) (claude-sonnet-4-5) -- UI generation
- [FastAPI](https://fastapi.tiangolo.com/) -- backend API
- [React](https://react.dev/) -- generated dashboard components
- [DShield](https://dshield.org/) -- honeypot log source
- [Claude Code](https://claude.ai/code) -- used to build this entire project

## Subscribe

If you found this project interesting, check out the video walkthrough and subscribe:

**[youtube.com/@gnarcoding](https://youtube.com/@gnarcoding)**

## License

ISC
