"""
Backend API server for the honeypot dashboard.

Phase 2: serves SchemaSummary JSON and static files (fallback dashboard).
"""

import logging
from datetime import date
from pathlib import Path

from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from ingest import read_day, available_dates
from analyze import analyze

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="DShield Honeypot Dashboard")

WEB_DIR = Path(__file__).parent / "web"
LOG_DIR = Path(__file__).parent


@app.get("/api/summary")
def get_summary(date: str = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")):
    """Return SchemaSummary as JSON for a given date."""
    try:
        day = date_obj = __import__("datetime").date.fromisoformat(date)
    except ValueError:
        raise HTTPException(400, f"Invalid date: {date}")

    entries = list(read_day(day, log_dir=LOG_DIR))
    if not entries:
        raise HTTPException(404, f"No log data for {date}")

    summary = analyze(iter(entries), date, date)
    return summary.to_dict()


@app.get("/api/dates")
def get_dates():
    """Return list of available log dates."""
    dates = available_dates(log_dir=LOG_DIR)
    return [d.isoformat() for d in dates]


# Static files
app.mount("/web", StaticFiles(directory=str(WEB_DIR)), name="web")


@app.get("/")
def index():
    """Serve the dashboard shell."""
    return FileResponse(WEB_DIR / "index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
