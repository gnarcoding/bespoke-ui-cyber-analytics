"""
Backend API server for the honeypot dashboard.

Phase 3: serves SchemaSummary JSON, data endpoints for generated UIs,
UI generation/caching, and static files.
"""

import html
import logging
from collections import Counter
from datetime import date as date_cls, datetime
from pathlib import Path

from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from ingest import read_day, available_dates
from analyze import analyze, _sanitize_string

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="DShield Honeypot Dashboard")

WEB_DIR = Path(__file__).parent / "web"
LOG_DIR = Path(__file__).parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_summary(date_str: str):
    """Parse date, read logs, return SchemaSummary. Raises HTTPException on error."""
    try:
        day = date_cls.fromisoformat(date_str)
    except ValueError:
        raise HTTPException(400, f"Invalid date: {date_str}")

    entries = list(read_day(day, log_dir=LOG_DIR))
    if not entries:
        raise HTTPException(404, f"No log data for {date_str}")

    return analyze(iter(entries), date_str, date_str), entries


def _get_summary_only(date_str: str):
    """Like _get_summary but doesn't return raw entries."""
    summary, _ = _get_summary(date_str)
    return summary


def _escape(val) -> str:
    """HTML-escape a string value for safe browser consumption."""
    return html.escape(str(val)) if val else ""


# ---------------------------------------------------------------------------
# Core endpoints
# ---------------------------------------------------------------------------

@app.get("/api/summary")
def get_summary(date: str = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")):
    """Return SchemaSummary as JSON for a given date."""
    summary = _get_summary_only(date)
    return summary.to_dict()


@app.get("/api/dates")
def get_dates():
    """Return list of available log dates."""
    dates = available_dates(log_dir=LOG_DIR)
    return [d.isoformat() for d in dates]


# ---------------------------------------------------------------------------
# /api/data/* endpoints — the menu the generated UI picks from
# ---------------------------------------------------------------------------

@app.get("/api/data/top_ips")
def data_top_ips(date: str = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")):
    summary = _get_summary_only(date)
    return [
        {"ip": _escape(ip), "count": count, "pct": round(count / summary.total_entries * 100, 1)}
        for ip, count in summary.top_ips
    ]


@app.get("/api/data/top_urls")
def data_top_urls(date: str = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")):
    summary = _get_summary_only(date)
    return [
        {"url": _escape(url), "count": count, "pct": round(count / summary.total_entries * 100, 1)}
        for url, count in summary.top_urls
    ]


@app.get("/api/data/top_useragents")
def data_top_useragents(date: str = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")):
    summary = _get_summary_only(date)
    return [
        {"useragent": _escape(ua), "count": count, "pct": round(count / summary.total_entries * 100, 1)}
        for ua, count in summary.top_useragents
    ]


@app.get("/api/data/top_methods")
def data_top_methods(date: str = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")):
    summary = _get_summary_only(date)
    return [
        {"method": _escape(m), "count": count}
        for m, count in summary.top_methods
    ]


@app.get("/api/data/time_buckets")
def data_time_buckets(date: str = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")):
    summary = _get_summary_only(date)
    return [
        {"bucket": bucket, "count": count}
        for bucket, count in sorted(summary.time_buckets.items())
    ]


@app.get("/api/data/attack_tags")
def data_attack_tags(date: str = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")):
    summary = _get_summary_only(date)
    return [
        {"tag": _escape(tag), "count": count}
        for tag, count in sorted(summary.attack_tags.items(), key=lambda x: -x[1])
    ]


@app.get("/api/data/url_clusters")
def data_url_clusters(date: str = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")):
    summary = _get_summary_only(date)
    return [
        {"cluster": _escape(cluster), "count": count}
        for cluster, count in sorted(summary.url_clusters.items(), key=lambda x: -x[1])
    ]


@app.get("/api/data/signature_hits")
def data_signature_hits(date: str = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")):
    summary = _get_summary_only(date)
    return [
        {
            "sig_id": _escape(sid),
            "comment": _escape(summary.signature_comments.get(sid, "")),
            "count": count,
        }
        for sid, count in sorted(summary.signature_hits.items(), key=lambda x: -x[1])
    ]


@app.get("/api/data/target_ports")
def data_target_ports(date: str = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")):
    summary = _get_summary_only(date)
    return [
        {"port": _escape(port), "count": count}
        for port, count in sorted(summary.target_ports.items(), key=lambda x: -x[1])
    ]


@app.get("/api/data/body_stats")
def data_body_stats(date: str = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")):
    summary = _get_summary_only(date)
    return {
        "entries_with_body": summary.entries_with_body,
        "total_entries": summary.total_entries,
        "pct": round(summary.entries_with_body / max(summary.total_entries, 1) * 100, 1),
    }


@app.get("/api/data/dominant_actor_detail")
def data_dominant_actor_detail(date: str = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")):
    """Return detailed info about a dominant actor (>50% of traffic), or null."""
    summary, entries = _get_summary(date)

    if not summary.top_ips:
        return None

    top_ip, top_count = summary.top_ips[0]
    if top_count / summary.total_entries <= 0.5:
        return None

    # Compute detail from raw entries for this IP
    target_urls: Counter = Counter()
    target_ports: Counter = Counter()
    timestamps = []
    user_agents: Counter = Counter()

    for entry in entries:
        if entry.get("sip") != top_ip:
            continue

        url = entry.get("url", "")
        if url:
            target_urls[url] += 1

        ua = entry.get("useragent", "")
        if ua:
            user_agents[ua] += 1

        ts = entry.get("time", "")
        if ts:
            timestamps.append(ts)

        headers = entry.get("headers", {})
        if isinstance(headers, dict):
            host = headers.get("Host", headers.get("host", ""))
            if ":" in host:
                port = host.rsplit(":", 1)[-1]
                if port.isdigit():
                    target_ports[port] += 1

    # Sort timestamps for first/last seen
    timestamps.sort()
    top_ua = user_agents.most_common(1)

    return {
        "ip": _escape(top_ip),
        "total_count": top_count,
        "pct": round(top_count / summary.total_entries * 100, 1),
        "target_urls": [
            {"url": _escape(_sanitize_string(u, 80)), "count": c}
            for u, c in target_urls.most_common(10)
        ],
        "target_ports": [
            {"port": _escape(p), "count": c}
            for p, c in target_ports.most_common(5)
        ],
        "first_seen": timestamps[0] if timestamps else None,
        "last_seen": timestamps[-1] if timestamps else None,
        "user_agent": _escape(_sanitize_string(top_ua[0][0], 80)) if top_ua else None,
    }


# ---------------------------------------------------------------------------
# UI generation endpoints
# ---------------------------------------------------------------------------

@app.get("/api/ui")
def get_ui(date: str = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")):
    """Return generated UI component JS for a given date, or 404 if none exists."""
    from generate_ui import generate

    summary = _get_summary_only(date)
    js, status = generate(summary)

    if js:
        return PlainTextResponse(js, media_type="application/javascript")
    else:
        raise HTTPException(404, "No generated UI available; use fallback")


@app.post("/api/ui/regenerate")
def regenerate_ui(date: str = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")):
    """Force-regenerate the UI for a given date, busting the cache."""
    from generate_ui import generate

    summary = _get_summary_only(date)
    js, status = generate(summary, force=True)

    return {
        "status": status,
        "size": len(js) if js else 0,
        "structural_hash": summary.structural_hash(),
    }


# ---------------------------------------------------------------------------
# Static files & index
# ---------------------------------------------------------------------------

app.mount("/web", StaticFiles(directory=str(WEB_DIR)), name="web")


@app.get("/")
def index():
    """Serve the dashboard shell."""
    return FileResponse(WEB_DIR / "index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
