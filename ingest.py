"""
Ingester for DShield webhoneypot JSONL log files.

Reads webhoneypot_YYYY-MM-DD.json files, yields one dict per valid line.
Handles multi-day date ranges. Skips malformed lines with a warning.
"""

import json
import logging
import os
from datetime import date, timedelta
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

DEFAULT_LOG_DIR = Path(__file__).parent


def _log_path(log_dir: Path, day: date) -> Path:
    return log_dir / f"webhoneypot_{day.isoformat()}.json"


def read_day(day: date, log_dir: Path = DEFAULT_LOG_DIR) -> Iterator[dict]:
    """Yield parsed log entries for a single day. Skips malformed lines."""
    path = _log_path(log_dir, day)
    if not path.exists():
        logger.warning("Log file not found: %s", path)
        return

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if not isinstance(entry, dict):
                    logger.warning("%s:%d — not a JSON object, skipping", path.name, lineno)
                    continue
                yield entry
            except json.JSONDecodeError as e:
                logger.warning("%s:%d — malformed JSON, skipping: %s", path.name, lineno, e)


def read_range(start: date, end: date, log_dir: Path = DEFAULT_LOG_DIR) -> Iterator[dict]:
    """Yield parsed log entries for every day in [start, end] inclusive."""
    current = start
    while current <= end:
        yield from read_day(current, log_dir)
        current += timedelta(days=1)


def available_dates(log_dir: Path = DEFAULT_LOG_DIR) -> list[date]:
    """Return sorted list of dates that have log files."""
    dates = []
    prefix = "webhoneypot_"
    suffix = ".json"
    for name in os.listdir(log_dir):
        if name.startswith(prefix) and name.endswith(suffix):
            datestr = name[len(prefix):-len(suffix)]
            try:
                dates.append(date.fromisoformat(datestr))
            except ValueError:
                continue
    return sorted(dates)
