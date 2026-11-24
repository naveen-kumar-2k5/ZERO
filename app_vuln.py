
import os
from datetime import datetime, timezone, timedelta

import requests
import urllib3
from flask import Blueprint, jsonify, request, render_template
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).resolve().parent / ".env")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────
# Config — read from env at import time. No defaults for secrets.
# ─────────────────────────────────────────────────────
IDX_HOST = os.getenv("WAZUH_INDEXER_HOST", "https://192.168.244.131:9200")
IDX_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
IDX_PASS = os.getenv("WAZUH_INDEXER_PASS", "")  # REQUIRED — no default
IDX_VERIFY = os.getenv("WAZUH_INDEXER_VERIFY", "false").lower() == "true"
IDX_INDEX_PATTERN = os.getenv(
    "WAZUH_VULN_INDEX", "wazuh-states-vulnerabilities-*"
)
IDX_TIMEOUT = int(os.getenv("WAZUH_INDEXER_TIMEOUT", "8"))

SEVERITIES = ("Critical", "High", "Medium", "Low")
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

vuln_bp = Blueprint("vuln", __name__)


# ─────────────────────────────────────────────────────
# Indexer helper
# ─────────────────────────────────────────────────────
class IndexerError(RuntimeError):
    pass


def _indexer_post(path, body, timeout=IDX_TIMEOUT):
    if not IDX_PASS:
        raise IndexerError(
            "WAZUH_INDEXER_PASS is not set. Add it to .env and restart."
        )
    url = f"{IDX_HOST.rstrip('/')}/{path.lstrip('/')}"
    try:
        r = requests.post(
            url,
            auth=(IDX_USER, IDX_PASS),
            json=body,
            verify=IDX_VERIFY,
            timeout=timeout,
        )
    except requests.RequestException as e:
        raise IndexerError(f"Indexer unreachable: {e}") from e

    if r.status_code == 401:
        raise IndexerError("Indexer rejected credentials (401). Check WAZUH_INDEXER_USER/PASS.")
    if r.status_code >= 500:
        raise IndexerError(f"Indexer error {r.status_code}: {r.text[:200]}")
    try:
        r.raise_for_status()
    except requests.HTTPError as e:
        raise IndexerError(f"Indexer HTTP {r.status_code}: {r.text[:200]}") from e
    return r.json()


# ─────────────────────────────────────────────────────
# Query builders (pure functions — unit-testable)
# ─────────────────────────────────────────────────────
def build_filters(severity=None, agent=None, q=None):
    """Return list of OpenSearch query clauses for a search request."""
    must = []
    if severity and severity in SEVERITIES:
        must.append({"term": {"vulnerability.severity": severity}})
    if agent:
        must.append({"term": {"agent.name": agent}})
    if q:
        must.append({
            "multi_match": {
                "query": q,
                "fields": [
                    "vulnerability.id^3",
                    "vulnerability.description",
                    "package.name^2",
                    "package.version",
                    "agent.name^2",
                ],
                "type": "best_fields",
            }
        })
    # Only include rows that have a CVE and a severity — the index also
    # contains "Pending"/"Untriaged" placeholder docs during a feed scan.
    must.append({"terms": {"vulnerability.severity": list(SEVERITIES)}})
    return must


def build_search_body(severity=None, agent=None, q=None, limit=100):
    limit = max(1, min(int(limit), 500))
    return {
        "size": limit,
        "track_total_hits": True,
        "sort": [
            {"vulnerability.severity": {"order": "asc"}},   # Critical first (alphabetical: C<H<L<M)
            {"vulnerability.score.base": {"order": "desc", "missing": "_last"}},
            {"vulnerability.detected_at": {"order": "desc", "missing": "_last"}},
        ],
        "query": {"bool": {"must": build_filters(severity, agent, q)}},
        "_source": [
            "vulnerability.id",
            "vulnerability.severity",
            "vulnerability.score.base",
            "vulnerability.description",
            "vulnerability.detected_at",
            "vulnerability.published_at",
            "vulnerability.scanner.reference",
            "agent.id",
            "agent.name",
            "package.name",
            "package.version",
            "package.architecture",
        ],
    }


def build_summary_body(agent=None):
    """Aggregation-only query — returns severity counts (and per-agent counts)."""
    filters = [{"terms": {"vulnerability.severity": list(SEVERITIES)}}]
    if agent:
        filters.append({"term": {"agent.name": agent}})
    return {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}},
            "by_agent": {"terms": {"field": "agent.name", "size": 50}},
            "by_cve": {"cardinality": {"field": "vulnerability.id"}},
            "by_package": {"cardinality": {"field": "package.name"}},
        },
    }


# ─────────────────────────────────────────────────────
# Response shaping
# ─────────────────────────────────────────────────────
def _snippet(text, n=280):
    if not text:
        return ""
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1].rsplit(" ", 1)[0] + "…"


def shape_hit(hit):
    src = hit.get("_source", {}) or {}
    v = src.get("vulnerability", {}) or {}
    p = src.get("package", {}) or {}
    a = src.get("agent", {}) or {}
    return {
        "cve":        v.get("id"),
        "severity":   v.get("severity") or "Low",
        "cvss":       (v.get("score") or {}).get("base"),
        "description": _snippet(v.get("description")),
        "detected_at": v.get("detected_at"),
        "published_at": v.get("published_at"),
        "reference":  (v.get("scanner") or {}).get("reference"),
        "agent":      a.get("name") or "unknown",
        "agent_id":   a.get("id"),
        "package":    p.get("name"),
        "version":    p.get("version"),
        "arch":       p.get("architecture"),
    }


def sort_hits(rows):
    return sorted(
        rows,
        key=lambda r: (
            SEV_ORDER.get(r["severity"], 9),
            -(r["cvss"] or 0),
        ),
    )


# ─────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────
@vuln_bp.route("/vulnerabilities")
def page():
    return render_template("vulnerabilities.html")


@vuln_bp.route("/api/v1/vulnerabilities", methods=["GET"])
def api_vulnerabilities():
    severity = (request.args.get("severity") or "").strip() or None
    agent    = (request.args.get("agent")    or "").strip() or None
    q        = (request.args.get("q")        or "").strip() or None
    summary  = request.args.get("summary", "false").lower() == "true"

    if severity and severity not in SEVERITIES:
        return jsonify({"status": "error",
                        "error": f"severity must be one of {list(SEVERITIES)}"}), 400

    try:
        if summary:
            body = build_summary_body(agent=agent)
            res  = _indexer_post(
                f"{IDX_INDEX_PATTERN}/_search", body
            )
            aggs = (res.get("aggregations") or {})
            sev_buckets = {b["key"]: int(b["doc_count"])
                           for b in (aggs.get("by_severity") or {}).get("buckets", [])}
            agent_buckets = [
                {"agent": b["key"], "count": int(b["doc_count"])}
                for b in (aggs.get("by_agent") or {}).get("buckets", [])
            ]
            return jsonify({
                "status": "success",
                "data": {
                    "totalHits":    res.get("hits", {}).get("total", {}).get("value", 0),
                    "uniqueCVEs":   (aggs.get("by_cve") or {}).get("value", 0),
                    "uniquePackages": (aggs.get("by_package") or {}).get("value", 0),
                    "bySeverity":   {k: sev_buckets.get(k, 0) for k in SEVERITIES},
                    "byAgent":      agent_buckets,
                    "indexPattern": IDX_INDEX_PATTERN,
                },
            })

        try:
            limit = min(max(int(request.args.get("limit", 100)), 1), 500)
        except ValueError:
            limit = 100

        body = build_search_body(severity=severity, agent=agent, q=q, limit=limit)
        res  = _indexer_post(f"{IDX_INDEX_PATTERN}/_search", body)
        hits = res.get("hits", {}).get("hits", []) or []
        total = res.get("hits", {}).get("total", {}).get("value", len(hits))
        data = sort_hits([shape_hit(h) for h in hits])

        return jsonify({
            "status": "success",
            "count":  len(data),
            "total":  total,
            "filters": {
                "severity": severity,
                "agent":    agent,
                "q":        q,
                "limit":    limit,
            },
            "data": data,
        })
    except IndexerError as e:
        return jsonify({
            "status": "error",
            "error":  str(e),
            "hint":   "See docs/vulnerabilities.md — check WAZUH_INDEXER_* env vars "
                      "and that the vulnerability-detection module has run at least once.",
        }), 502


@vuln_bp.route("/api/v1/vulnerabilities/agents", methods=["GET"])
def api_vuln_agents():
    """Distinct agent names that currently have findings — for the filter dropdown."""
    try:
        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"terms": {"vulnerability.severity": list(SEVERITIES)}}
            ]}},
            "aggs": {
                "agents": {"terms": {"field": "agent.name", "size": 100}},
            },
        }
        res = _indexer_post(f"{IDX_INDEX_PATTERN}/_search", body)
        buckets = (res.get("aggregations", {}).get("agents", {}) or {}).get("buckets", [])
        return jsonify({
            "status": "success",
            "data": [{"agent": b["key"], "count": int(b["doc_count"])} for b in buckets],
        })
    except IndexerError as e:
        return jsonify({"status": "error", "error": str(e)}), 502