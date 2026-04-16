"""
Analyzer for DShield webhoneypot log entries.

Pure Python, no LLM. Produces a SchemaSummary dataclass from a batch of
log dicts. This is the critical sanitization layer — the LLM never sees
raw log strings, only categories, counts, and pattern labels.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Iterator


# ---------------------------------------------------------------------------
# Attack-pattern detection rules (regex / substring)
# ---------------------------------------------------------------------------

ATTACK_PATTERNS: list[tuple[str, re.Pattern | str, str]] = [
    # (tag, pattern, field)  — field is "url", "data", or "useragent"
    # Path traversal
    ("path_traversal", re.compile(r"\.\./"), "url"),
    ("path_traversal", re.compile(r"%2e%2e[/%]", re.I), "url"),
    # Shell injection
    ("shell_injection", re.compile(r";\s*(wget|curl|chmod|sh|bash|nc|python|perl|tftp)\b", re.I), "url"),
    ("shell_injection", re.compile(r";\s*(wget|curl|chmod|sh|bash|nc|python|perl|tftp)\b", re.I), "data"),
    ("shell_injection", re.compile(r"\|\s*(wget|curl|sh|bash)\b", re.I), "url"),
    ("shell_injection", re.compile(r"`[^`]*(wget|curl|sh|bash)", re.I), "url"),
    # SQL injection
    ("sqli", re.compile(r"(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+table)", re.I), "url"),
    ("sqli", re.compile(r"(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+table)", re.I), "data"),
    # XSS
    ("xss", re.compile(r"<script", re.I), "url"),
    ("xss", re.compile(r"<script", re.I), "data"),
    ("xss", re.compile(r"javascript:", re.I), "url"),
    # Cloud metadata / SSRF
    ("cloud_metadata", re.compile(r"169\.254\.169\.254"), "url"),
    ("cloud_metadata", re.compile(r"metadata\.google\.internal"), "url"),
    ("ssrf", re.compile(r"^https?://", re.I), "url"),  # absolute URL in path = proxy/SSRF attempt
    # Credential harvesting
    ("credential_access", re.compile(r"\.(env|git/config|git/HEAD|aws/credentials|ssh/id_rsa|npmrc|pgpass|netrc|my\.cnf|docker/config\.json|htpasswd|svn)"), "url"),
    ("credential_access", re.compile(r"(credentials\.json|gcloud-service-key|\.env\b|secrets\.(json|yml|yaml)|serviceAccountKey|id_rsa|id_ed25519)"), "url"),
    ("credential_access", re.compile(r"(appsettings(\.\w+)?\.json|application-\w+\.yml)"), "url"),
    # WordPress probes
    ("wordpress", re.compile(r"/(wp-login\.php|wp-admin|wp-content|wp-includes|xmlrpc\.php|wp-json)", re.I), "url"),
    # phpunit / eval-stdin
    ("phpunit_rce", re.compile(r"phpunit.*eval-stdin\.php", re.I), "url"),
    # CGI abuse
    ("cgi_abuse", re.compile(r"/cgi-bin/"), "url"),
    # Router/IoT exploits
    ("iot_exploit", re.compile(r"(GponForm|boaform|/goform/|/HNAP1|/cgibin/mainfunction)", re.I), "url"),
    # Config/debug exposure
    ("config_exposure", re.compile(r"/(config\.(json|yml|php|js)|configuration\.php|debug/vars|/actuator|\.well-known|druid/index|containers/json)", re.I), "url"),
    # Database dumps
    ("database_exposure", re.compile(r"/(database\.(sql|yml)|dump\.sql|db\.sql|backup\.sql)", re.I), "url"),
    # Docker
    ("docker_exposure", re.compile(r"(docker-compose\.(yml|yaml|dev|prod)|Dockerfile|containers/json)", re.I), "url"),
    # Known CVE paths
    ("known_cve", re.compile(r"(/cgi-bin/luci|/GponForm/|/HNAP1|/solr/|/geoserver/|XDEBUG_SESSION)", re.I), "url"),
    # Login brute force (POST to login-like endpoints)
    ("login_bruteforce", re.compile(r"/(login|signin|auth|admin)(\.(php|cgi|asp|jsp))?$", re.I), "url"),
    # Appliance login pages (FortiGate, PAN-OS, SonicWall, etc.)
    ("appliance_login", re.compile(r"/(remote/login|remote/logincheck|global-protect/login|dana-na/auth)", re.I), "url"),
    ("appliance_login", re.compile(r"/api/sonicos/(auth|tfa)", re.I), "url"),
    # Spring Boot / Java actuator
    ("actuator_exposure", re.compile(r"/actuator(/|$)", re.I), "url"),
    # Backup/archive scanning
    ("backup_scan", re.compile(r"/(backup|bak|old|copy|archive)(/|\.)", re.I), "url"),
]

# URL path clusters: group related paths under a label
URL_CLUSTERS: list[tuple[str, re.Pattern]] = [
    ("WordPress", re.compile(r"^/(wp-login|wp-admin|wp-content|wp-includes|xmlrpc|wp-json)", re.I)),
    ("phpunit RCE", re.compile(r"phpunit.*eval-stdin", re.I)),
    ("env/credential files", re.compile(r"/\.(env|git|aws|ssh|npm|pg|my\.cnf|docker|netrc|htpasswd|svn)", re.I)),
    ("env/credential files", re.compile(r"(credentials\.json|gcloud-service-key|secrets\.(json|yml)|serviceAccountKey|id_rsa|id_ed25519)", re.I)),
    ("env/credential files", re.compile(r"(appsettings(\.\w+)?\.json|application-\w+\.yml)", re.I)),
    ("path traversal", re.compile(r"(\.\./|%2e%2e)", re.I)),
    ("CGI scripts", re.compile(r"^/cgi-bin/", re.I)),
    ("IoT/router exploits", re.compile(r"(GponForm|boaform|goform|HNAP1|cgibin/mainfunction)", re.I)),
    ("config/debug endpoints", re.compile(r"/(config\.|configuration|debug/|actuator|druid)", re.I)),
    ("database files", re.compile(r"/(database\.|dump\.sql|db\.sql|backup\.sql)", re.I)),
    ("Docker files", re.compile(r"(docker-compose|Dockerfile|containers/json)", re.I)),
    ("appliance login probes", re.compile(r"/(remote/login|remote/logincheck|global-protect|dana-na)", re.I)),
    ("appliance login probes", re.compile(r"/api/sonicos/", re.I)),
    ("API probes", re.compile(r"^/api/", re.I)),
    ("login pages", re.compile(r"/(login|signin|auth)(\.(php|cgi|asp|jsp))?$", re.I)),
    ("backup/archive scans", re.compile(r"/(backup|bak|old|copy|archive)(/|\.)", re.I)),
    ("index/root scan", re.compile(r"^/$")),
    ("favicon", re.compile(r"favicon\.ico")),
    ("robots/sitemap", re.compile(r"(robots\.txt|sitemap\.xml)", re.I)),
    ("SharePoint/Office", re.compile(r"/_layouts/", re.I)),
    ("PHP probes", re.compile(r"(phpinfo\.php|info\.php|php-cgi|\.php\?)", re.I)),
    ("Hikvision/DVR", re.compile(r"/(SDK/webLanguage|ISAPI/)", re.I)),
    ("well-known", re.compile(r"^/\.well-known/", re.I)),
    ("version/health", re.compile(r"/(version|health|status|ping)$", re.I)),
    ("SVN metadata", re.compile(r"/\.svn/", re.I)),
    ("Next.js/SPA assets", re.compile(r"/(_next|static/js|static/css)/", re.I)),
    ("wp-config", re.compile(r"wp-config\.(php|txt|bak)", re.I)),
]


def _sanitize_string(s: str, max_len: int = 40) -> str:
    """Truncate and strip non-printable / non-ASCII for safe LLM consumption.

    Also strips HTML tags and common prompt-injection markers so that
    attacker-controlled strings cannot reach the LLM or browser intact.
    """
    if not isinstance(s, str):
        return ""
    # Remove non-printable chars
    cleaned = re.sub(r"[^\x20-\x7e]", "", s)
    # Strip HTML tags
    cleaned = re.sub(r"<[^>]*>", "", cleaned)
    # Defang common prompt injection openers
    cleaned = re.sub(r"(?i)(ignore\s+(all\s+)?previous\s+instructions?)", "[redacted]", cleaned)
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "..."
    return cleaned


def _classify_url(url: str) -> str:
    """Return a cluster label for a URL, or 'other'."""
    for label, pattern in URL_CLUSTERS:
        if pattern.search(url):
            return label
    return "other"


def _detect_attacks(entry: dict) -> set[str]:
    """Return set of attack tags that match this log entry."""
    tags = set()
    for tag, pattern, fld in ATTACK_PATTERNS:
        value = entry.get(fld, "")
        if not value:
            continue
        if isinstance(pattern, re.Pattern):
            if pattern.search(value):
                tags.add(tag)
        elif pattern in value:
            tags.add(tag)
    return tags


def _time_bucket(ts_str: str, bucket_minutes: int = 60) -> str:
    """Parse ISO timestamp and return bucket label like '2026-03-16T14:00'."""
    try:
        dt = datetime.fromisoformat(ts_str)
        minute = (dt.minute // bucket_minutes) * bucket_minutes
        return dt.replace(minute=minute, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M")
    except (ValueError, TypeError):
        return "unknown"


def _bucket_to_power_of_10(n: int) -> int:
    """Round to nearest power of 10 for structural hashing."""
    if n <= 0:
        return 0
    return 10 ** round(math.log10(max(n, 1)))


# ---------------------------------------------------------------------------
# SchemaSummary dataclass
# ---------------------------------------------------------------------------

@dataclass
class SchemaSummary:
    """Structured summary of a batch of honeypot logs.

    Contains only categories, counts, and pattern labels — never raw
    attacker-controlled strings. Safe to pass to an LLM.
    """
    date_range: list[str]  # [start, end] ISO date strings
    total_entries: int = 0

    # Cardinalities
    unique_ips: int = 0
    unique_urls: int = 0
    unique_useragents: int = 0

    # Attack pattern tag counts
    attack_tags: dict[str, int] = field(default_factory=dict)

    # URL cluster counts
    url_clusters: dict[str, int] = field(default_factory=dict)

    # Top-N values (sanitized)
    top_ips: list[tuple[str, int]] = field(default_factory=list)
    top_urls: list[tuple[str, int]] = field(default_factory=list)
    top_useragents: list[tuple[str, int]] = field(default_factory=list)
    top_methods: list[tuple[str, int]] = field(default_factory=list)

    # Time-bucketed request counts
    time_buckets: dict[str, int] = field(default_factory=dict)

    # HTTP methods breakdown
    methods: dict[str, int] = field(default_factory=dict)

    # Signature ID hit counts
    signature_hits: dict[str, int] = field(default_factory=dict)
    signature_comments: dict[str, str] = field(default_factory=dict)

    # Has POST data?
    entries_with_body: int = 0

    # Ports targeted (from Host header)
    target_ports: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def structural_hash(self) -> str:
        """Hash only structural fields for cache keying.

        Designed to be stable across days with similar attack profiles.
        Uses top-5 attack tags by volume (ignoring long-tail one-offs),
        top-5 cluster names as a set (order-insensitive), rough magnitude
        buckets, and method set. Does NOT hash exact counts.
        """
        # Top-5 tags by count — ignores rare one-off detections
        top_tags = sorted(
            sorted(self.attack_tags, key=lambda k: -self.attack_tags[k])[:5]
        )
        # Top-5 clusters as a set — order doesn't matter
        top_clusters = sorted(
            sorted(self.url_clusters, key=lambda k: -self.url_clusters[k])[:5]
        )
        structural = {
            "tags_top5": top_tags,
            "clusters_top5": top_clusters,
            "magnitude_entries": _bucket_to_power_of_10(self.total_entries),
            "magnitude_ips": _bucket_to_power_of_10(self.unique_ips),
            "top_methods": sorted(self.methods.keys()),
            "has_body": self.entries_with_body > 0,
        }
        raw = json.dumps(structural, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

TOP_N = 10


def analyze(entries: Iterator[dict], date_start: str = "", date_end: str = "") -> SchemaSummary:
    """Analyze a batch of log entries and produce a SchemaSummary.

    Args:
        entries: Iterator of parsed log dicts from the ingester.
        date_start: ISO date string for range start.
        date_end: ISO date string for range end.
    """
    ip_counter: Counter = Counter()
    url_counter: Counter = Counter()
    ua_counter: Counter = Counter()
    method_counter: Counter = Counter()
    attack_counter: Counter = Counter()
    cluster_counter: Counter = Counter()
    time_counter: Counter = Counter()
    sig_counter: Counter = Counter()
    sig_comments: dict[str, str] = {}
    port_counter: Counter = Counter()
    entries_with_body = 0
    total = 0

    for entry in entries:
        total += 1

        sip = entry.get("sip", "")
        url = entry.get("url", "")
        ua = entry.get("useragent", "")
        method = entry.get("method", "")
        data = entry.get("data", "")
        ts = entry.get("time", "")

        ip_counter[sip] += 1
        url_counter[url] += 1
        if ua:
            ua_counter[ua] += 1
        method_counter[method] += 1

        # Attack pattern detection
        tags = _detect_attacks(entry)
        for tag in tags:
            attack_counter[tag] += 1

        # URL clustering
        cluster = _classify_url(url)
        cluster_counter[cluster] += 1

        # Time bucketing
        bucket = _time_bucket(ts)
        time_counter[bucket] += 1

        # Signature ID
        sig = entry.get("signature_id")
        if isinstance(sig, dict):
            sid = str(sig.get("id", ""))
            if sid:
                sig_counter[sid] += 1
                comment = sig.get("comment", "")
                if comment and sid not in sig_comments:
                    sig_comments[sid] = comment

        # Body present?
        if data and data.strip():
            entries_with_body += 1

        # Target port (from Host header)
        headers = entry.get("headers", {})
        if isinstance(headers, dict):
            host = headers.get("Host", headers.get("host", ""))
            if ":" in host:
                port = host.rsplit(":", 1)[-1]
                if port.isdigit():
                    port_counter[port] += 1
                else:
                    port_counter["80"] += 1
            else:
                port_counter["80"] += 1

    summary = SchemaSummary(
        date_range=[date_start or "unknown", date_end or "unknown"],
        total_entries=total,
        unique_ips=len(ip_counter),
        unique_urls=len(url_counter),
        unique_useragents=len(ua_counter),
        attack_tags=dict(attack_counter.most_common()),
        url_clusters=dict(cluster_counter.most_common()),
        top_ips=[(ip, c) for ip, c in ip_counter.most_common(TOP_N)],
        top_urls=[(_sanitize_string(u, 60), c) for u, c in url_counter.most_common(TOP_N)],
        top_useragents=[(_sanitize_string(ua, 60), c) for ua, c in ua_counter.most_common(TOP_N)],
        top_methods=method_counter.most_common(),
        time_buckets=dict(sorted(time_counter.items())),
        methods=dict(method_counter.most_common()),
        signature_hits=dict(sig_counter.most_common()),
        signature_comments=sig_comments,
        entries_with_body=entries_with_body,
        target_ports=dict(port_counter.most_common(TOP_N)),
    )

    return summary
