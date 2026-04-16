"""
UI generator — calls Claude to produce a React component from a SchemaSummary.

Validation pipeline:
  1. Generate JSX from SchemaSummary via Claude API
  2. Check size (20KB cap)
  3. Bundle with esbuild to validate syntax
  4. On failure: retry ONCE with fresh API call including the error
  5. On double failure: fall back to static dashboard
  6. Cache every attempt (ok, retry_ok, failed) in SQLite
"""

import hashlib
import json
import logging
import os
import sqlite3
import subprocess
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from analyze import SchemaSummary

load_dotenv()

logger = logging.getLogger(__name__)

PROMPT_PATH = Path(__file__).parent / "prompts" / "ui_generator.txt"
DB_PATH = Path(__file__).parent / "cache.db"
MAX_JSX_BYTES = 20 * 1024  # 20KB cap
MODEL = "claude-sonnet-4-5"


def _init_db():
    """Create the generated_ui table if it doesn't exist."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS generated_ui (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            structural_hash TEXT NOT NULL,
            summary_json TEXT NOT NULL,
            component_jsx TEXT NOT NULL,
            component_js TEXT,
            status TEXT NOT NULL,
            error_log TEXT,
            created_at TEXT NOT NULL,
            model TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_generated_ui_hash_status
        ON generated_ui (structural_hash, status)
    """)
    conn.commit()
    conn.close()


def _get_cached(structural_hash: str) -> str | None:
    """Return cached bundled JS if a successful generation exists for this hash."""
    conn = sqlite3.connect(str(DB_PATH))
    row = conn.execute(
        "SELECT component_js FROM generated_ui "
        "WHERE structural_hash = ? AND status IN ('ok', 'retry_ok') "
        "ORDER BY created_at DESC LIMIT 1",
        (structural_hash,),
    ).fetchone()
    conn.close()
    return row[0] if row else None


def _store_attempt(structural_hash: str, summary_json: str, jsx: str,
                   js: str | None, status: str, error_log: str | None):
    """Store a generation attempt (success or failure)."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO generated_ui "
        "(structural_hash, summary_json, component_jsx, component_js, status, error_log, created_at, model) "
        "VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)",
        (structural_hash, summary_json, jsx, js, status, error_log, MODEL),
    )
    conn.commit()
    conn.close()


def _load_system_prompt() -> str:
    """Load the UI generator system prompt."""
    return PROMPT_PATH.read_text(encoding="utf-8")


def _call_claude(system_prompt: str, user_message: str) -> str:
    """Make a fresh Claude API call and return the text response."""
    client = anthropic.Anthropic()
    response = client.messages.create(
        model=MODEL,
        max_tokens=8192,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}],
    )
    # Extract text from response
    text = ""
    for block in response.content:
        if block.type == "text":
            text += block.text
    return text.strip()


def _strip_fences(jsx: str) -> str:
    """Strip markdown code fences if the model wraps output in them."""
    lines = jsx.split("\n")
    # Strip leading ```jsx or ```
    if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
    # Strip trailing ```
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _validate_with_esbuild(jsx: str) -> tuple[bool, str | None, str | None]:
    """Run esbuild on JSX string. Returns (success, bundled_js, error_msg)."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsx", delete=False, encoding="utf-8"
    ) as f:
        f.write(jsx)
        jsx_path = f.name

    js_path = jsx_path.replace(".jsx", ".js")

    try:
        result = subprocess.run(
            [
                "npx", "esbuild", jsx_path,
                "--bundle", "--format=iife",
                "--global-name=__genUI",
                "--outfile=" + js_path,
                "--external:react", "--external:react-dom",
                "--log-level=error",
            ],
            capture_output=True, text=True, timeout=30,
            cwd=str(Path(__file__).parent),
            shell=True,
        )

        if result.returncode == 0 and os.path.exists(js_path):
            bundled = Path(js_path).read_text(encoding="utf-8")
            return True, bundled, None
        else:
            return False, None, result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, None, "esbuild timed out after 30s"
    finally:
        for p in [jsx_path, js_path]:
            try:
                os.unlink(p)
            except OSError:
                pass


VALIDATOR_SCRIPT = Path(__file__).parent / "validate_runtime.js"


def _validate_runtime(bundled_js: str, summary_json: str | None = None) -> tuple[bool, str | None]:
    """Run the generated bundle through jsdom to catch runtime errors.

    Returns (success, error_msg).
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".js", delete=False, encoding="utf-8"
    ) as f:
        f.write(bundled_js)
        js_path = f.name

    summary_path = None
    if summary_json:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            f.write(summary_json)
            summary_path = f.name

    try:
        cmd = ["node", str(VALIDATOR_SCRIPT), js_path]
        if summary_path:
            cmd.append(summary_path)

        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=15,
            cwd=str(Path(__file__).parent),
        )

        if result.returncode == 0:
            logger.info("Runtime validation passed: %s", result.stderr.strip())
            return True, None
        else:
            error = result.stderr.strip()
            logger.warning("Runtime validation failed: %s", error)
            return False, error
    except subprocess.TimeoutExpired:
        return False, "Runtime validation timed out after 15s"
    finally:
        try:
            os.unlink(js_path)
        except OSError:
            pass
        if summary_path:
            try:
                os.unlink(summary_path)
            except OSError:
                pass


def generate(summary: SchemaSummary, force: bool = False) -> tuple[str | None, str]:
    """Generate a UI component for the given summary.

    Args:
        summary: The SchemaSummary to generate UI for.
        force: If True, skip cache and regenerate.

    Returns:
        (bundled_js, status) where status is one of:
        'cached', 'ok', 'retry_ok', 'failed'
        bundled_js is None on failure.
    """
    _init_db()

    structural_hash = summary.structural_hash()
    summary_json = summary.to_json()

    # Check cache unless forced
    if not force:
        cached = _get_cached(structural_hash)
        if cached:
            logger.info("Cache hit for hash %s", structural_hash)
            return cached, "cached"

    logger.info("Cache miss for hash %s — generating UI", structural_hash)

    system_prompt = _load_system_prompt()
    user_message = (
        "Here is today's honeypot traffic summary. Generate a dashboard component for it.\n\n"
        + summary_json
    )

    # --- First attempt ---
    try:
        raw_jsx = _call_claude(system_prompt, user_message)
    except Exception as e:
        logger.error("Claude API call failed: %s", e)
        _store_attempt(structural_hash, summary_json, "", None, "failed", str(e))
        return None, "failed"

    jsx = _strip_fences(raw_jsx)

    # Size check
    if len(jsx.encode("utf-8")) > MAX_JSX_BYTES:
        error_msg = f"Generated JSX exceeds 20KB cap ({len(jsx.encode('utf-8'))} bytes)"
        logger.warning(error_msg)
        _store_attempt(structural_hash, summary_json, jsx, None, "failed", error_msg)
        return None, "failed"

    # esbuild validation
    ok, bundled_js, error_msg = _validate_with_esbuild(jsx)

    if ok:
        # Runtime validation — catch prop shape mismatches, missing fields, etc.
        rt_ok, rt_error = _validate_runtime(bundled_js, summary_json)
        if rt_ok:
            logger.info("First attempt compiled and rendered successfully")
            _store_attempt(structural_hash, summary_json, jsx, bundled_js, "ok", None)
            return bundled_js, "ok"
        else:
            error_msg = f"esbuild OK but runtime failed: {rt_error}"
            logger.warning("First attempt: %s", error_msg)
    else:
        logger.warning("First attempt failed esbuild: %s", error_msg)

    _store_attempt(structural_hash, summary_json, jsx, None, "failed", error_msg)

    # --- Retry: fresh API call with error context ---
    retry_message = (
        "The component you generated failed validation. Here is the error:\n\n"
        + (error_msg or "Unknown error")
        + "\n\nHere is the original summary again:\n\n"
        + summary_json
        + "\n\nGenerate a corrected component. Same rules apply."
    )

    try:
        raw_jsx_2 = _call_claude(system_prompt, retry_message)
    except Exception as e:
        logger.error("Retry Claude API call failed: %s", e)
        _store_attempt(structural_hash, summary_json, "", None, "failed", f"retry API error: {e}")
        return None, "failed"

    jsx_2 = _strip_fences(raw_jsx_2)

    # Size check on retry
    if len(jsx_2.encode("utf-8")) > MAX_JSX_BYTES:
        error_msg_2 = f"Retry JSX exceeds 20KB cap ({len(jsx_2.encode('utf-8'))} bytes)"
        logger.warning(error_msg_2)
        _store_attempt(structural_hash, summary_json, jsx_2, None, "failed", error_msg_2)
        return None, "failed"

    ok_2, bundled_js_2, error_msg_2 = _validate_with_esbuild(jsx_2)

    if ok_2:
        # Runtime validation on retry
        rt_ok_2, rt_error_2 = _validate_runtime(bundled_js_2, summary_json)
        if rt_ok_2:
            logger.info("Retry attempt compiled and rendered successfully")
            _store_attempt(structural_hash, summary_json, jsx_2, bundled_js_2, "retry_ok", None)
            return bundled_js_2, "retry_ok"
        else:
            error_msg_2 = f"esbuild OK but runtime failed: {rt_error_2}"
            logger.error("Retry: %s", error_msg_2)
    else:
        logger.error("Retry also failed esbuild: %s", error_msg_2)

    _store_attempt(structural_hash, summary_json, jsx_2, None, "failed", error_msg_2)
    return None, "failed"


if __name__ == "__main__":
    """Quick test: generate UI for a date passed as argv[1]."""
    import sys
    from datetime import date
    from ingest import read_day
    from analyze import analyze

    logging.basicConfig(level=logging.INFO)

    d = sys.argv[1] if len(sys.argv) > 1 else "2026-04-15"
    day = date.fromisoformat(d)
    entries = list(read_day(day))
    summary = analyze(iter(entries), d, d)

    print(f"Summary: {summary.total_entries} entries, hash={summary.structural_hash()}")

    js, status = generate(summary)
    print(f"Status: {status}")
    if js:
        print(f"Bundled JS size: {len(js)} bytes")
    else:
        print("Generation failed — would serve fallback")
