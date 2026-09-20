# Enhanced app.py with Product-Version Insights, Patch Status, and Dependency Tree

from flask import Flask, render_template, request, send_from_directory, jsonify, make_response, session

import os
import sys
import re
import time
import json
import threading
import traceback
from datetime import datetime
from collections import Counter, defaultdict
from openpyxl import Workbook
from openpyxl.utils import get_column_letter
from openpyxl.styles import Font, Alignment, PatternFill
from dotenv import load_dotenv, set_key
import requests
import io
import csv
import networkx as nx
import secrets


def resource_path(relative_path):
    """Path to a bundled read-only asset (templates/static). Resolves inside
    PyInstaller's onefile temp extraction dir when frozen."""
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


def get_app_dir():
    """Writable directory for user files (cve_reports/, cache/, config.env) --
    always beside the exe when frozen, never inside the ephemeral MEIPASS temp dir."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


CONFIG_ENV_PATH = os.path.join(get_app_dir(), "config.env")
load_dotenv(CONFIG_ENV_PATH)

app = Flask(__name__,
            template_folder=resource_path("templates"),
            static_folder=resource_path("static"))

app.secret_key = secrets.token_hex(32)  # Generate secure secret key
app.config['SESSION_PERMANENT'] = True  # Keep session even after browser closes


# --- Tunables -------------------------------------------------------------
NVD_PAGE_SIZE = 2000        # NVD's maximum resultsPerPage
MAX_CVES = 5000             # safety cap on CVEs pulled per search (a warning is shown if hit)
EPSS_BATCH_SIZE = 100       # CVE ids per EPSS request
KEV_CACHE_TTL = 24 * 3600   # seconds before the CISA KEV catalog is re-downloaded
KEV_CACHE_PATH = os.path.join(get_app_dir(), "cache", "kev_catalog.json")
MAX_STORED_PRODUCTS = 60    # affected-product entries kept per CVE (matching uses the full list)
MAX_AFFECTED_SHOWN = 30     # CPE strings shown in the "Affected Products" text
MAX_REFERENCES = 100        # reference links kept per CVE
GRAPH_CVE_LIMIT = 100       # highest-risk CVEs that feed the Product -> Version map
MAX_JOBS = 10               # finished scans kept in memory for exports / detail lookups


def get_persisted_api_key():
    """API key saved to config.env (survives app restarts), if any."""
    key = os.getenv("NVD_API_KEY", "").strip()
    return key if key and key != "your_actual_api_key_here" else ""


# --- CVSS / CWE reference data --------------------------------------------
_IMPACT_3 = {'N': 'None', 'L': 'Low', 'H': 'High'}
_IMPACT_2 = {'N': 'None', 'P': 'Partial', 'C': 'Complete'}
_AV_3 = {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'}

# Vector-string abbreviations -> (key, label, value names), keyed by CVSS major version
CVSS_LABELS = {
    '3': [
        ('AV', 'Attack Vector', _AV_3),
        ('AC', 'Attack Complexity', {'L': 'Low', 'H': 'High'}),
        ('PR', 'Privileges Required', _IMPACT_3),
        ('UI', 'User Interaction', {'N': 'None', 'R': 'Required'}),
        ('S', 'Scope', {'U': 'Unchanged', 'C': 'Changed'}),
        ('C', 'Confidentiality', _IMPACT_3),
        ('I', 'Integrity', _IMPACT_3),
        ('A', 'Availability', _IMPACT_3),
    ],
    '2': [
        ('AV', 'Access Vector', {'L': 'Local', 'A': 'Adjacent Network', 'N': 'Network'}),
        ('AC', 'Access Complexity', {'H': 'High', 'M': 'Medium', 'L': 'Low'}),
        ('Au', 'Authentication', {'M': 'Multiple', 'S': 'Single', 'N': 'None'}),
        ('C', 'Confidentiality', _IMPACT_2),
        ('I', 'Integrity', _IMPACT_2),
        ('A', 'Availability', _IMPACT_2),
    ],
    '4': [
        ('AV', 'Attack Vector', _AV_3),
        ('AC', 'Attack Complexity', {'L': 'Low', 'H': 'High'}),
        ('AT', 'Attack Requirements', {'N': 'None', 'P': 'Present'}),
        ('PR', 'Privileges Required', _IMPACT_3),
        ('UI', 'User Interaction', {'N': 'None', 'P': 'Passive', 'A': 'Active'}),
        ('VC', 'System Confidentiality', _IMPACT_3),
        ('VI', 'System Integrity', _IMPACT_3),
        ('VA', 'System Availability', _IMPACT_3),
        ('SC', 'Subsequent Confidentiality', _IMPACT_3),
        ('SI', 'Subsequent Integrity', _IMPACT_3),
        ('SA', 'Subsequent Availability', _IMPACT_3),
    ],
}

CWE_NAMES = {
    'NVD-CWE-Other': 'Other (not covered by a specific CWE)',
    'NVD-CWE-noinfo': 'Insufficient information',
    'CWE-20': 'Improper Input Validation',
    'CWE-22': 'Path Traversal',
    'CWE-77': 'Command Injection',
    'CWE-78': 'OS Command Injection',
    'CWE-79': 'Cross-site Scripting (XSS)',
    'CWE-89': 'SQL Injection',
    'CWE-94': 'Code Injection',
    'CWE-119': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
    'CWE-125': 'Out-of-bounds Read',
    'CWE-190': 'Integer Overflow or Wraparound',
    'CWE-200': 'Exposure of Sensitive Information',
    'CWE-269': 'Improper Privilege Management',
    'CWE-276': 'Incorrect Default Permissions',
    'CWE-287': 'Improper Authentication',
    'CWE-306': 'Missing Authentication for Critical Function',
    'CWE-352': 'Cross-Site Request Forgery (CSRF)',
    'CWE-362': 'Race Condition',
    'CWE-400': 'Uncontrolled Resource Consumption',
    'CWE-401': 'Missing Release of Memory (Memory Leak)',
    'CWE-416': 'Use After Free',
    'CWE-434': 'Unrestricted Upload of File with Dangerous Type',
    'CWE-476': 'NULL Pointer Dereference',
    'CWE-502': 'Deserialization of Untrusted Data',
    'CWE-522': 'Insufficiently Protected Credentials',
    'CWE-601': 'Open Redirect',
    'CWE-611': 'XML External Entity (XXE) Reference',
    'CWE-732': 'Incorrect Permission Assignment for Critical Resource',
    'CWE-787': 'Out-of-bounds Write',
    'CWE-798': 'Use of Hard-coded Credentials',
    'CWE-862': 'Missing Authorization',
    'CWE-863': 'Incorrect Authorization',
    'CWE-918': 'Server-Side Request Forgery (SSRF)',
}

# NVD reference tags, most useful first. A reference is listed under the first of
# its tags that appears here; anything else lands under "Other".
REFERENCE_TAG_ORDER = [
    'Patch', 'Exploit', 'Vendor Advisory', 'Mitigation', 'Third Party Advisory',
    'US Government Resource', 'Technical Description', 'Issue Tracking', 'Release Notes',
    'VDB Entry', 'Product', 'Mailing List', 'Broken Link',
]


def parse_cvss_vector(vector):
    """Break a CVSS vector string into [{'label', 'value'}] with readable names.
    Handles v2, v3.x and v4.0; unknown metrics are skipped."""
    if not vector:
        return []
    parts = vector.split('/')
    major = '2'
    if parts[0].startswith('CVSS:'):
        major = parts[0].split(':', 1)[1].split('.')[0]
        parts = parts[1:]
    values = dict(p.split(':', 1) for p in parts if ':' in p)
    return [
        {'label': label, 'value': names.get(values[key], values[key])}
        for key, label, names in CVSS_LABELS.get(major, [])
        if key in values
    ]


def pick_cvss_metric(metrics):
    """Choose the CVSS metric to display: newest v3.x first, then v4.0, then v2;
    within a version, NVD's own (Primary) score beats a CNA's (Secondary)."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV3", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        if not isinstance(entries, list):
            entries = [entries]
        metric = next((m for m in entries if m.get("type") == "Primary"), entries[0])
        data = metric.get("cvssData", {})
        # v2 keeps baseSeverity on the metric itself; v3/v4 keep it in cvssData
        severity = data.get("baseSeverity") or metric.get("baseSeverity") or "N/A"
        return {
            'severity': str(severity).upper(),
            'score': data.get("baseScore", "N/A"),
            'vector': data.get("vectorString", ""),
            'version': data.get("version", ""),
            'source': metric.get("source", ""),
            'exploitability': metric.get("exploitabilityScore"),
            'impact': metric.get("impactScore"),
        }
    return {'severity': "N/A", 'score': "N/A", 'vector': "", 'version': "",
            'source': "", 'exploitability': None, 'impact': None}


def extract_cwes(cve):
    """CWE ids for a CVE, NVD's primary assessment first: [{'id', 'name'}]."""
    primary, other = [], []
    for weakness in cve.get("weaknesses", []):
        bucket = primary if weakness.get("type") == "Primary" else other
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value and value not in bucket:
                bucket.append(value)
    ids = primary + [c for c in other if c not in primary]
    return [{'id': c, 'name': CWE_NAMES.get(c, '')} for c in ids]


def group_references(references):
    """Group NVD reference links by their most useful tag."""
    groups = defaultdict(list)
    seen = set()
    for ref in references[:MAX_REFERENCES]:
        url = ref.get("url")
        if not url or url in seen:  # NVD repeats a URL once per reporting source
            continue
        seen.add(url)
        tags = ref.get("tags", [])
        primary = next((t for t in REFERENCE_TAG_ORDER if t in tags), None)
        groups[primary or 'Other'].append({
            'url': url,
            'tags': [t for t in tags if t != primary],
        })
    ordered = [t for t in REFERENCE_TAG_ORDER + ['Other'] if t in groups]
    return [{'tag': t, 'links': groups[t]} for t in ordered]


# --- Version comparison ---------------------------------------------------
# Pre-release markers sort *before* the bare version (2.0-rc1 < 2.0); any other
# letter suffix sorts *after* it (OpenSSL's 1.0.2k > 1.0.2).
_PRERELEASE_RANK = {'dev': 0, 'snapshot': 0, 'alpha': 1, 'milestone': 2, 'beta': 3,
                    'preview': 4, 'pre': 4, 'rc': 5}


def version_key(version):
    """Sortable key for a version string. Best-effort: real-world version schemes
    are inconsistent, so this handles the common dotted/lettered forms."""
    text = re.sub(r'^[vV](?=\d)', '', str(version).strip())
    key = []
    for token in re.findall(r'\d+|[A-Za-z]+', text):
        if token.isdigit():
            key.append((1, int(token), ''))
        elif token.lower() in _PRERELEASE_RANK:
            key.append((0, _PRERELEASE_RANK[token.lower()], ''))
        else:
            key.append((2, 0, token.lower()))
    return key


def compare_versions(a, b):
    """-1 / 0 / 1 like cmp(); missing trailing parts count as zero (2.4 == 2.4.0)."""
    ka, kb = version_key(a), version_key(b)
    pad = (1, 0, '')
    size = max(len(ka), len(kb))
    ka += [pad] * (size - len(ka))
    kb += [pad] * (size - len(kb))
    return (ka > kb) - (ka < kb)


def format_version_label(cpe_version, start_incl, start_excl, end_incl, end_excl):
    """Readable version text for a CPE match: a range if NVD gives bounds."""
    bounds = []
    if start_incl:
        bounds.append(f">= {start_incl}")
    if start_excl:
        bounds.append(f"> {start_excl}")
    if end_incl:
        bounds.append(f"<= {end_incl}")
    if end_excl:
        bounds.append(f"< {end_excl}")
    if bounds:
        return ", ".join(bounds)
    if cpe_version == "*":
        return "All Versions"
    if cpe_version == "-":
        return "N/A (no version)"
    return cpe_version


def entry_covers_version(entry, version):
    """Does one affected-product entry cover `version`?
    True / False, or None when the entry has no version information to judge by."""
    start_incl, start_excl = entry['start_incl'], entry['start_excl']
    end_incl, end_excl = entry['end_incl'], entry['end_excl']
    if start_incl or start_excl or end_incl or end_excl:
        if start_incl and compare_versions(version, start_incl) < 0:
            return False
        if start_excl and compare_versions(version, start_excl) <= 0:
            return False
        if end_incl and compare_versions(version, end_incl) > 0:
            return False
        if end_excl and compare_versions(version, end_excl) >= 0:
            return False
        return True
    cpe_version = entry['cpe_version']
    if cpe_version == '*':
        return True
    if cpe_version == '-':
        return None
    return compare_versions(version, cpe_version) == 0


def product_tokens(product):
    return [t for t in re.split(r'[\s_\-]+', (product or '').lower()) if t]


def entry_matches_product(entry, tokens):
    """Every word of the searched product appears in the entry's vendor/product."""
    if not tokens:
        return False
    haystack = f"{entry['vendor_id']} {entry['product_id']}".replace('_', ' ').replace('-', ' ')
    return all(t in haystack for t in tokens)


class ScanError(Exception):
    """A scan failed in a way worth showing the user verbatim."""


# --- Scan jobs (run in a background thread so the UI can show progress) ----
JOBS = {}
JOBS_LOCK = threading.Lock()


def new_job(product, version):
    job = {
        "id": secrets.token_urlsafe(9),
        "status": "running",        # running | done | error
        "stage": "nvd",             # nvd | kev | epss | analytics | done
        "message": "Starting...",
        "progress": 0.0,
        "product": product,
        "version": version,
        # CVEs in arrival order. Append-only (never re-sorted) so the page can fetch
        # "everything after row N" while the scan is still running.
        "rows": [],
        "enrich_version": 0,        # bumped whenever KEV / EPSS data lands on `rows`
        "results": None,            # risk-sorted copy of `rows`, set when the scan finishes
        "analytics": None,
        "warnings": [],
        "version_summary": None,
        "error": None,
        "index": {},                # cve id -> row, filled as rows arrive (detail lookups)
    }
    with JOBS_LOCK:
        JOBS[job["id"]] = job
        while len(JOBS) > MAX_JOBS:
            JOBS.pop(next(iter(JOBS)))  # dicts keep insertion order: oldest first
    return job


def get_job(job_id):
    with JOBS_LOCK:
        return JOBS.get(job_id or "")


def run_scan(job, api_key):
    """Execute a scan for `job`, publishing results as each stage produces them:
    CVE rows appear as every NVD page arrives, then KEV and EPSS data are layered on,
    then the analytics are built. The page polls and renders whatever is ready."""
    def progress(message, fraction):
        job["message"] = message
        job["progress"] = fraction

    scanner = EnhancedCVEScanner(api_key=api_key, progress=progress)
    job["warnings"] = scanner.warnings  # live list: warnings show up as they are raised
    product, version = job["product"], job["version"]
    version_counts = Counter()

    def publish_nvd_batch(batch):
        unified = [scanner.unify_nvd(item, product, version) for item in batch]
        if version:
            version_counts.update(u["Version_Match"] for u in unified)
            job["version_summary"] = {
                "affected": version_counts["Affected"],
                "unverified": version_counts["Unverified"],
                "excluded": version_counts["Not Affected"],
                "other_product": version_counts["Other Product"],
            }
            # Drop CVEs whose ranges rule this version out, and keyword hits that are
            # really about a different product
            unified = [u for u in unified if u["Version_Match"] in ("Affected", "Unverified")]
        for u in unified:
            job["index"][u["CVE"]] = u
        job["rows"].extend(unified)  # after the rows are fully built: pollers read len(rows)

    def enrichment_landed():
        job["enrich_version"] += 1

    try:
        scanner.search_nvd(product, on_batch=publish_nvd_batch)
        rows = job["rows"]

        job["stage"] = "kev"
        scanner.apply_kev(rows)
        enrichment_landed()

        job["stage"] = "epss"
        scanner.apply_epss(rows, on_progress=enrichment_landed)

        job["stage"] = "analytics"
        progress("Building charts...", 0.95)
        # Sort by multiple criteria (KEV first, then EPSS, then year)
        results = sorted(
            rows,
            key=lambda x: (
                x['KEV_Status'] == 'Known Exploited',
                x['EPSS_Score'],
                extract_cve_year(x['CVE'])
            ),
            reverse=True
        )
        job["analytics"] = scanner.generate_analytics_data(results)
        job["results"] = results
        job["progress"] = 1.0
        job["message"] = "Done"
        job["stage"] = "done"
        job["status"] = "done"  # last: pollers treat "done" as "everything above is set"
    except ScanError as e:
        job["error"] = str(e)
        job["status"] = "error"
    except Exception as e:
        traceback.print_exc()
        job["error"] = f"Unexpected error: {e}"
        job["status"] = "error"


ROWS_PAGE_SIZE = 2000       # rows returned per /api/job/<id>/rows request
ROW_DESC_CHARS = 500        # description text sent to the table (hover text + column search)
ROW_AFFECTED_CHARS = 400


def slim_row(item):
    """The fields the CVE table needs -- the full record stays server-side and is
    fetched on demand by the row expander (/api/job/<id>/cve/<cve>)."""
    detailed = item.get("Affected_Products_Detailed") or []
    return {
        "cve": item["CVE"],
        "severity": item["Severity"],
        "score": item["Score"],
        "epss": item["EPSS_Score"],
        "epss_pct": item["EPSS_Percentile"],
        "kev": item["KEV_Status"] == "Known Exploited",
        "patch": bool(item["Patch_Reference_Found"]),
        "cwe": item["CWE"],
        "vm": item["Version_Match"],
        "desc": (item["Description"] or "")[:ROW_DESC_CHARS],
        "affected": item["Affected_Products"][:ROW_AFFECTED_CHARS],
        "versions": ", ".join(f"{d['vendor']} {d['version']}" for d in detailed[:3]),
        "more_versions": len(detailed) > 3,
    }


@app.route("/")
def index():
    # API key comes from the Settings tab, not the search form -- prefer
    # the current session, falling back to whatever's persisted on disk.
    api_key = session.get('api_key') or get_persisted_api_key() or ""
    # The page is a shell; results are loaded by its JS. ?job=<id> re-attaches to a
    # scan (running or finished) after a reload.
    return render_template(
        "index.html",
        job_id=request.args.get("job", ""),
        graph_limit=GRAPH_CVE_LIMIT,
        api_key=api_key,
        api_key_persisted=bool(get_persisted_api_key())
    )


def parse_search_form(source):
    product = (source.get("product_name") or "").strip()
    version = (source.get("version") or "").strip() or None
    return product, version


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a scan in the background; poll /api/scan/<job_id> for progress."""
    product, version = parse_search_form(request.form if request.form else (request.get_json(silent=True) or {}))
    if not product:
        return jsonify({'status': 'error', 'message': 'Product name is required'}), 400

    api_key = session.get('api_key') or get_persisted_api_key() or None
    job = new_job(product, version)
    threading.Thread(target=run_scan, args=(job, api_key), daemon=True).start()
    return jsonify({'status': 'started', 'job_id': job["id"]})


@app.route('/api/scan/<job_id>')
def scan_status(job_id):
    job = get_job(job_id)
    if not job:
        return jsonify({'status': 'error', 'message': 'Unknown scan'}), 404
    return jsonify({
        'status': job["status"],
        'stage': job["stage"],
        'message': job["message"],
        'progress': job["progress"],
        'error': job["error"],
        'product': job["product"],
        'version': job["version"] or "",
        'rows': len(job["rows"]),                # how many CVEs are ready to fetch
        'enrich_version': job["enrich_version"],  # changes when new KEV/EPSS data is available
        'version_summary': job["version_summary"],
        'warnings': list(job["warnings"]),
    })


@app.route('/api/job/<job_id>/rows')
def job_rows(job_id):
    """CVE rows from `offset` on, in arrival order (up to ROWS_PAGE_SIZE per call)."""
    job = get_job(job_id)
    if not job:
        return jsonify({'status': 'error', 'message': 'Unknown scan'}), 404
    offset = max(0, request.args.get("offset", 0, type=int))
    chunk = job["rows"][offset:offset + ROWS_PAGE_SIZE]
    return jsonify({'rows': [slim_row(r) for r in chunk], 'next': offset + len(chunk)})


@app.route('/api/job/<job_id>/enrichment')
def job_enrichment(job_id):
    """EPSS scores and KEV membership gathered so far, keyed by CVE id. Small on
    purpose: the page merges it into rows it already has instead of refetching them."""
    job = get_job(job_id)
    if not job:
        return jsonify({'status': 'error', 'message': 'Unknown scan'}), 404
    version = job["enrich_version"]  # read first: the data below is at least this fresh
    epss, kev = {}, []
    for r in list(job["rows"]):
        if r["EPSS_Score"] or r["EPSS_Percentile"]:
            epss[r["CVE"]] = [r["EPSS_Score"], r["EPSS_Percentile"]]
        if r["KEV_Status"] == "Known Exploited":
            kev.append(r["CVE"])
    return jsonify({'epss': epss, 'kev': kev, 'version': version})


@app.route('/api/job/<job_id>/analytics')
def job_analytics(job_id):
    """Chart data for a finished scan (built once EPSS/KEV are in)."""
    job = get_job(job_id)
    if not job:
        return jsonify({'status': 'error', 'message': 'Unknown scan'}), 404
    if job["status"] != "done":
        return jsonify({'status': 'error', 'message': 'The scan has not finished yet'}), 409
    return jsonify(job["analytics"])


@app.route('/api/job/<job_id>/cve/<cve_id>')
def cve_details(job_id, cve_id):
    """Full detail for one CVE (loaded on demand by the row expander)."""
    job = get_job(job_id)
    item = job["index"].get(cve_id) if job else None
    if item is None:
        return jsonify({'status': 'error', 'message': 'CVE not found in these results'}), 404
    return jsonify({
        'status': 'success',
        'cve': item["CVE"],
        'description': item["Description"],
        'link': item["Link"],
        'published': item["Published_Date"],
        'last_modified': item["Last_Modified"],
        'nvd_status': item["Vuln_Status"],
        **item["Details"],
    })


@app.route('/api/save-key', methods=['POST'])
def save_api_key():
    """Persist the NVD API key to config.env so it survives app restarts."""
    data = request.get_json(silent=True) or {}
    api_key = (data.get('api_key') or "").strip()
    if not api_key:
        return jsonify({'status': 'error', 'message': 'API key is required'}), 400

    set_key(CONFIG_ENV_PATH, "NVD_API_KEY", api_key)
    os.environ["NVD_API_KEY"] = api_key
    session['api_key'] = api_key
    return jsonify({'status': 'success', 'message': 'API key saved'})

@app.route('/clear-api-key', methods=['POST'])
def clear_api_key():
    """Clear the API key from the session and from disk"""
    session.pop('api_key', None)
    set_key(CONFIG_ENV_PATH, "NVD_API_KEY", "")
    os.environ["NVD_API_KEY"] = ""
    return jsonify({'status': 'success', 'message': 'API key cleared'})


class EnhancedCVEScanner:
    def __init__(self, api_key=None, progress=None):
        self.api_key = api_key
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.epss_url = "https://api.first.org/data/v1/epss"
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.headers = {"apiKey": api_key} if api_key else {}
        self.delay = 0.6 if api_key else 6
        self.session = requests.Session()
        self.warnings = []
        self._progress = progress or (lambda message, fraction: None)
        self._last_fraction = 0.0  # progress-bar position to keep while retrying

    # -- NVD ---------------------------------------------------------------
    def _nvd_request(self, params):
        """One NVD request, retrying on rate limiting / transient failures."""
        last_error = "unknown error"
        for attempt in range(1, 4):
            try:
                r = self.session.get(self.nvd_url, params=params, headers=self.headers, timeout=30)
                if r.status_code in (403, 429, 503):
                    # NVD signals rate limiting with 403/429; back off and retry
                    last_error = f"HTTP {r.status_code} (rate limited or busy)"
                    self._progress(f"NVD is rate limiting requests -- retrying ({attempt}/3)...",
                                   self._last_fraction)
                    time.sleep(6 * attempt)
                    continue
                r.raise_for_status()
                return r.json()
            except requests.exceptions.SSLError as e:
                raise ScanError(
                    "TLS certificate verification failed while contacting NVD. If you are on a "
                    "network that inspects HTTPS traffic (corporate proxy/VPN), its certificate "
                    f"must be trusted by this machine. Details: {e}")
            except requests.RequestException as e:
                last_error = str(e)
                time.sleep(2 * attempt)
        raise ScanError(f"Could not reach NVD after 3 attempts: {last_error}")

    def search_nvd(self, product, on_batch=None):
        """Keyword search across every page of NVD results (up to MAX_CVES).
        `on_batch(items)` is called with each page as it arrives, so callers can
        show results before the last page is fetched.
        The version is deliberately not part of the query: NVD often describes
        affected versions as ranges ('before 2.4.51'), which a text search on the
        exact version would miss -- run_scan filters by version afterwards."""
        print(f"[NVD] Searching: {product}")
        params = {"resultsPerPage": NVD_PAGE_SIZE, "startIndex": 0, "keywordSearch": product}
        collected = []
        total = 0
        while True:
            data = self._nvd_request(params)
            total = data.get("totalResults", 0)
            batch = data.get("vulnerabilities", [])[:MAX_CVES - len(collected)]
            collected.extend(batch)
            if on_batch and batch:
                on_batch(batch)

            target = max(1, min(total, MAX_CVES))
            self._last_fraction = 0.05 + 0.45 * min(1.0, len(collected) / target)
            self._progress(f"Fetched {min(len(collected), target):,} of {target:,} CVEs from NVD...",
                           self._last_fraction)

            if not batch or len(collected) >= min(total, MAX_CVES):
                break
            params["startIndex"] = len(collected)
            time.sleep(self.delay)  # NVD rate limit applies between pages

        if total > MAX_CVES:
            self.warnings.append(
                f"NVD has {total:,} CVEs matching \"{product}\" -- only the first {MAX_CVES:,} were "
                "loaded. Use a more specific product name to narrow the search.")
        return collected

    # -- EPSS --------------------------------------------------------------
    def get_epss_scores(self, cve_list, on_batch=None):
        """EPSS scores for every CVE id, fetched in batches. `on_batch(scores)` is
        called with each batch's scores as they arrive."""
        epss_data = {}
        batches = [cve_list[i:i + EPSS_BATCH_SIZE] for i in range(0, len(cve_list), EPSS_BATCH_SIZE)]
        failed = 0
        for n, batch in enumerate(batches, 1):
            self._progress(f"Getting EPSS scores ({n}/{len(batches)})...", 0.55 + 0.37 * n / len(batches))
            try:
                response = self.session.get(f"{self.epss_url}?cve={','.join(batch)}", timeout=30)
                response.raise_for_status()
                batch_scores = {}
                for item in response.json().get('data', []):
                    batch_scores[item.get('cve')] = {
                        'epss_score': float(item.get('epss', 0)),
                        'epss_percentile': float(item.get('percentile', 0))
                    }
                epss_data.update(batch_scores)
                if on_batch:
                    on_batch(batch_scores)
            except (requests.RequestException, ValueError) as e:
                print(f"[EPSS] Error: {e}")
                failed += 1

        if failed:
            self.warnings.append(
                f"EPSS scores could not be loaded for {failed} of {len(batches)} batches -- "
                "those CVEs show an EPSS of 0.000.")
        print(f"[EPSS] Retrieved scores for {len(epss_data)} CVEs")
        return epss_data

    # -- CISA KEV ----------------------------------------------------------
    @staticmethod
    def _read_kev_cache():
        try:
            with open(KEV_CACHE_PATH, "r", encoding="utf-8") as f:
                cached = json.load(f)
            if isinstance(cached.get("entries"), dict) and isinstance(cached.get("fetched_at"), (int, float)):
                return cached
        except (OSError, ValueError, AttributeError):
            pass
        return None

    @staticmethod
    def _write_kev_cache(entries):
        try:
            os.makedirs(os.path.dirname(KEV_CACHE_PATH), exist_ok=True)
            tmp_path = KEV_CACHE_PATH + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump({"fetched_at": time.time(), "entries": entries}, f)
            os.replace(tmp_path, KEV_CACHE_PATH)  # atomic: never leaves a half-written cache
        except OSError as e:
            print(f"[KEV] Could not write cache: {e}")

    def get_kev_data(self):
        """CISA Known Exploited Vulnerabilities catalog as {cve_id: details}.
        Cached on disk for KEV_CACHE_TTL; a stale cache is used if CISA is unreachable."""
        cached = self._read_kev_cache()
        if cached and time.time() - cached["fetched_at"] < KEV_CACHE_TTL:
            print(f"[KEV] Using cached catalog ({len(cached['entries'])} entries)")
            return cached["entries"]

        self._progress("Downloading CISA KEV catalog...", 0.5)
        try:
            response = self.session.get(self.kev_url, timeout=30)
            response.raise_for_status()
            entries = {}
            for vuln in response.json().get('vulnerabilities', []):
                cve_id = vuln.get('cveID')
                if cve_id:
                    entries[cve_id] = {
                        'date_added': vuln.get('dateAdded', ''),
                        'due_date': vuln.get('dueDate', ''),
                        'ransomware': vuln.get('knownRansomwareCampaignUse', 'Unknown'),
                        'required_action': vuln.get('requiredAction', ''),
                        'name': vuln.get('vulnerabilityName', ''),
                    }
            print(f"[KEV] Loaded {len(entries)} known exploited vulnerabilities")
            self._write_kev_cache(entries)
            return entries
        except (requests.RequestException, ValueError) as e:
            print(f"[KEV] Error: {e}")
            if cached:
                when = datetime.fromtimestamp(cached["fetched_at"]).strftime("%Y-%m-%d %H:%M")
                self.warnings.append(
                    f"Could not reach CISA -- using the KEV catalog cached on {when}.")
                return cached["entries"]
            self.warnings.append(
                "Could not download the CISA KEV catalog -- KEV status only reflects what NVD reports.")
            return {}

    def check_patch_reference(self, cve):
        """Whether NVD tagged any reference as 'Patch'. Reflects NVD's own
        reference metadata only -- not a verified vendor fix."""
        return any("Patch" in ref.get("tags", []) for ref in cve.get("references", []))

    # -- Affected products / version matching ------------------------------
    def extract_affected_entries(self, cve):
        """Every vulnerable CPE match across all of a CVE's configurations, deduplicated."""
        entries, seen = [], set()
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable"):
                        continue
                    criteria = match.get("criteria", "")
                    # cpe:2.3:part:vendor:product:version:... -- split on unescaped colons
                    parts = [re.sub(r'\\(.)', r'\1', p) for p in re.split(r'(?<!\\):', criteria)]
                    if len(parts) < 6:
                        continue

                    vendor_id, product_id, cpe_version = parts[3].lower(), parts[4].lower(), parts[5].lower()
                    bounds = tuple(match.get(k) for k in (
                        "versionStartIncluding", "versionStartExcluding",
                        "versionEndIncluding", "versionEndExcluding"))
                    key = (vendor_id, product_id, cpe_version, bounds)
                    if key in seen:
                        continue
                    seen.add(key)

                    entries.append({
                        'vendor': vendor_id.replace("_", " ").title(),
                        'product': product_id.replace("_", " ").title(),
                        'version': format_version_label(cpe_version, *bounds),
                        'cpe': criteria,
                        'vendor_id': vendor_id,
                        'product_id': product_id,
                        'cpe_version': cpe_version,
                        'start_incl': bounds[0],
                        'start_excl': bounds[1],
                        'end_incl': bounds[2],
                        'end_excl': bounds[3],
                    })
        return entries

    def evaluate_version_match(self, entries, tokens, version):
        """Check `version` against the searched product's affected ranges.
        Returns (status, detail), where status is one of:
          'Affected'      -- a listed range/version for the product includes `version`
          'Not Affected'  -- the product is listed, but no range includes `version`
          'Other Product' -- NVD lists affected products, none of them the one searched
                             (a keyword hit, e.g. the description merely mentions it)
          'Unverified'    -- NVD gives nothing to check `version` against"""
        if not entries:
            return "Unverified", "NVD has not published affected-product data for this CVE yet."
        relevant = [e for e in entries if entry_matches_product(e, tokens)]
        if not relevant:
            listed = ", ".join(sorted({f"{e['vendor']} {e['product']}" for e in entries})[:3])
            return "Other Product", f"NVD lists this CVE under other products (e.g. {listed})."
        undecided = False
        for entry in relevant:
            covers = entry_covers_version(entry, version)
            if covers:
                return "Affected", f"{entry['vendor']} {entry['product']}: {entry['version']}"
            if covers is None:
                undecided = True
        if undecided:
            return "Unverified", "NVD gives no version information for this product."
        return "Not Affected", ""

    def unify_nvd(self, item, product="", version=None):
        cve = item.get("cve", {})
        desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        cve_id = cve.get("id")

        cvss = pick_cvss_metric(cve.get("metrics", {}))
        cwes = extract_cwes(cve)

        # Affected products: the full list drives version matching; only the
        # entries for the searched product (or all, if none match) are kept for display.
        entries = self.extract_affected_entries(cve)
        tokens = product_tokens(product)
        relevant = [e for e in entries if entry_matches_product(e, tokens)]
        ordered = relevant + [e for e in entries if e not in relevant]
        stored = (relevant or entries)[:MAX_STORED_PRODUCTS]

        version_match, version_detail = "", ""
        if version:
            version_match, version_detail = self.evaluate_version_match(entries, tokens, version)

        affected_text = ", ".join(e['cpe'] for e in ordered[:MAX_AFFECTED_SHOWN]) or "N/A"
        if len(ordered) > MAX_AFFECTED_SHOWN:
            affected_text += f" ... (+{len(ordered) - MAX_AFFECTED_SHOWN} more)"

        # NVD mirrors CISA's KEV fields on the record; used if the catalog can't be fetched
        nvd_kev = None
        if cve.get("cisaExploitAdd"):
            nvd_kev = {
                'date_added': cve.get("cisaExploitAdd", ""),
                'due_date': cve.get("cisaActionDue", ""),
                'ransomware': "Unknown",
                'required_action': cve.get("cisaRequiredAction", ""),
                'name': cve.get("cisaVulnerabilityName", ""),
            }

        return {
            "CVE": cve_id,
            "Severity": cvss['severity'],
            "Score": cvss['score'],
            "CVSS_Vector": cvss['vector'],
            "Description": desc,
            "Affected_Products": affected_text,
            "Affected_Products_Detailed": stored,
            "Published_Date": cve.get("published", ""),
            "Last_Modified": cve.get("lastModified", ""),
            "Vuln_Status": cve.get("vulnStatus", ""),
            "Link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "EPSS_Score": 0.0,
            "EPSS_Percentile": 0.0,
            "KEV_Status": "Known Exploited" if nvd_kev else "Not Known Exploited",
            "KEV_Date_Added": nvd_kev['date_added'] if nvd_kev else "",
            "KEV_Due_Date": nvd_kev['due_date'] if nvd_kev else "",
            "KEV_Ransomware": nvd_kev['ransomware'] if nvd_kev else "",
            "Patch_Reference_Found": self.check_patch_reference(cve),
            "CWE": ", ".join(c['id'] for c in cwes),
            "Version_Match": version_match,
            # Everything the row expander shows -- served on demand by /api/job/<id>/cve/<cve>
            "Details": {
                'cvss': {
                    'version': cvss['version'],
                    'vector': cvss['vector'],
                    'source': cvss['source'],
                    'exploitability': cvss['exploitability'],
                    'impact': cvss['impact'],
                    'breakdown': parse_cvss_vector(cvss['vector']),
                },
                'cwes': cwes,
                'kev': dict(nvd_kev) if nvd_kev else None,
                'version_match': {'status': version_match, 'detail': version_detail} if version else None,
                'affected_count': len(entries),
                'references': group_references(cve.get("references", [])),
            },
        }

    def build_dependency_graph(self, results):
        """Build a product -> version graph from real NVD CPE data. Only the first
        GRAPH_CVE_LIMIT results (already sorted by risk) are used, so the graph
        stays readable and responsive on large result sets."""
        G = nx.DiGraph()

        for item in results[:GRAPH_CVE_LIMIT]:
            cve_id = item['CVE']
            for vendor_info in item.get('Affected_Products_Detailed', []):
                vendor = vendor_info.get('vendor', 'Unknown')
                product = vendor_info.get('product', 'Unknown')
                version = vendor_info.get('version', 'Unknown')

                # Create unique node IDs
                product_node = f"{vendor}:{product}"
                version_node = f"{vendor}:{product}:{version}"

                if product_node not in G:
                    G.add_node(product_node,
                               type='product',
                               vendor=vendor,
                               product=product,
                               cve_count=0,
                               severity=item['Severity'],
                               cves=[])
                if cve_id not in G.nodes[product_node]['cves']:
                    G.nodes[product_node]['cves'].append(cve_id)
                    G.nodes[product_node]['cve_count'] += 1

                # Version nodes describe the highest-risk CVE that touches them
                if version_node not in G:
                    G.add_node(version_node,
                               type='version',
                               vendor=vendor,
                               product=product,
                               version=version,
                               cve_id=cve_id,
                               severity=item['Severity'],
                               epss_score=item['EPSS_Score'],
                               kev_status=item['KEV_Status'],
                               patch_reference_found=item['Patch_Reference_Found'])

                G.add_edge(product_node, version_node)

        return G

    def apply_kev(self, rows):
        """Mark CVEs that are in CISA's KEV catalog (which also carries the ransomware
        flag). Cheap -- the catalog is cached on disk -- so it runs before EPSS."""
        self._progress("Checking the CISA KEV catalog...", 0.5)
        kev_data = self.get_kev_data()
        for item in rows:
            kev = kev_data.get(item['CVE'])
            if kev:
                item['KEV_Status'] = 'Known Exploited'
                item['KEV_Date_Added'] = kev['date_added']
                item['KEV_Due_Date'] = kev['due_date']
                item['KEV_Ransomware'] = kev['ransomware']
                item['Details']['kev'] = dict(kev)

    def apply_epss(self, rows, on_progress=None):
        """Fill in EPSS scores batch by batch; `on_progress()` fires after each batch
        has been applied to `rows`."""
        by_cve = {item['CVE']: item for item in rows if item['CVE']}

        def apply_batch(scores):
            for cve_id, score in scores.items():
                item = by_cve.get(cve_id)
                if item:
                    item['EPSS_Score'] = score['epss_score']
                    item['EPSS_Percentile'] = score['epss_percentile']
            if on_progress:
                on_progress()

        self.get_epss_scores(list(by_cve), on_batch=apply_batch)

    def generate_analytics_data(self, results):
        """Generate enhanced analytics data for charts"""
        analytics = {
            'risk_distribution': {
                'kev_count': 0,
                'high_epss': 0,
                'medium_epss': 0,
                'low_epss': 0
            },
            'severity_distribution': Counter(),
            'year_trends': Counter(),
            'vendor_analysis': Counter(),
            'epss_cvss_data': [],
            # Product-Version analysis
            'vendor_version_matrix': defaultdict(lambda: defaultdict(int)),
            'top_vulnerable_versions': Counter(),
            # Patch availability
            'patch_status': {'patched': 0, 'unpatched': 0},
            'patch_by_vendor': defaultdict(lambda: {'patched': 0, 'unpatched': 0}),
            # Dependency graph data
            'dependency_graph': {}
        }
        cwe_counts = Counter()
        attack_vectors = Counter()

        for item in results:
            # Weakness types (CWE) and how remotely reachable the CVE is (CVSS attack vector)
            cwe_counts.update(c.strip() for c in (item.get('CWE') or '').split(',') if c.strip())
            av = re.search(r'(?:^|/)AV:([NALP])(?:/|$)', item.get('CVSS_Vector') or '')
            attack_vectors[_AV_3[av.group(1)] if av else 'Unknown'] += 1

            # Risk distribution
            if item['KEV_Status'] == 'Known Exploited':
                analytics['risk_distribution']['kev_count'] += 1
            elif item['EPSS_Score'] >= 0.7:
                analytics['risk_distribution']['high_epss'] += 1
            elif item['EPSS_Score'] >= 0.3:
                analytics['risk_distribution']['medium_epss'] += 1
            else:
                analytics['risk_distribution']['low_epss'] += 1

            # Severity distribution
            analytics['severity_distribution'][item['Severity']] += 1

            # Year trends
            year = extract_cve_year(item['CVE'])
            if year > 0:
                analytics['year_trends'][year] += 1

            # Vendor/version analysis -- each vendor and vendor+version counts once per CVE
            vendors = set()
            vendor_versions = set()
            for vendor_info in item.get('Affected_Products_Detailed', []):
                vendor = vendor_info.get('vendor', 'Unknown')
                vendors.add(vendor)
                vendor_versions.add((vendor, vendor_info.get('version', 'Unknown')))

            has_patch = item.get('Patch_Reference_Found', False)
            for vendor in vendors:
                analytics['vendor_analysis'][vendor] += 1
                analytics['patch_by_vendor'][vendor]['patched' if has_patch else 'unpatched'] += 1
            for vendor, version in vendor_versions:
                analytics['vendor_version_matrix'][vendor][version] += 1
                analytics['top_vulnerable_versions'][f"{vendor} {version}"] += 1

            # Patch reference analysis
            analytics['patch_status']['patched' if has_patch else 'unpatched'] += 1

            # EPSS vs CVSS correlation data
            cvss_score = item['Score']
            if cvss_score != 'N/A':
                analytics['epss_cvss_data'].append({
                    'x': float(cvss_score),
                    'y': float(item['EPSS_Score']),
                    'kev': item['KEV_Status'] == 'Known Exploited',
                    'cve': item['CVE'],
                    'patch_ref': has_patch
                })

        # Build dependency graph
        dep_graph = self.build_dependency_graph(results)
        analytics['dependency_graph'] = nx.readwrite.json_graph.node_link_data(dep_graph)

        # Convert defaultdicts to regular dicts for JSON serialization
        analytics['vendor_version_matrix'] = {k: dict(v) for k, v in analytics['vendor_version_matrix'].items()}
        analytics['patch_by_vendor'] = {k: dict(v) for k, v in analytics['patch_by_vendor'].items()}

        analytics['cwe_distribution'] = [
            {'id': cwe, 'name': CWE_NAMES.get(cwe, ''), 'count': count}
            for cwe, count in cwe_counts.most_common(8)
        ]
        analytics['attack_vector'] = [
            {'label': label, 'count': attack_vectors[label]}
            for label in (*_AV_3.values(), 'Unknown') if attack_vectors[label]
        ]

        # Known-exploited spotlight: how many, how many tied to ransomware, what's newest
        kev_items = [i for i in results if i['KEV_Status'] == 'Known Exploited']
        newest_kev = sorted((i for i in kev_items if i.get('KEV_Date_Added')),
                            key=lambda i: i['KEV_Date_Added'], reverse=True)[:3]
        analytics['kev_summary'] = {
            'total': len(kev_items),
            'ransomware': sum(1 for i in kev_items if i.get('KEV_Ransomware') == 'Known'),
            'recent': [{'cve': i['CVE'],
                        'date_added': i['KEV_Date_Added'],
                        'name': (i['Details'].get('kev') or {}).get('name', '')} for i in newest_kev],
        }

        # "Fix these first": known-exploited, then most likely to be exploited, then worst CVSS
        def priority(i):
            score = i['Score'] if isinstance(i['Score'], (int, float)) else 0
            return (i['KEV_Status'] == 'Known Exploited', i['EPSS_Score'], score)

        analytics['top_priority'] = [
            {'cve': i['CVE'], 'severity': i['Severity'], 'score': i['Score'],
             'epss': i['EPSS_Score'], 'epss_pct': i['EPSS_Percentile'],
             'kev': i['KEV_Status'] == 'Known Exploited', 'patch': bool(i['Patch_Reference_Found'])}
            for i in sorted(results, key=priority, reverse=True)[:10]
        ]

        return analytics


# --- Exports ----------------------------------------------------------------
# One column spec shared by CSV and Excel: (header, value getter)
EXPORT_COLUMNS = [
    ("CVE", lambda i: i.get("CVE", "")),
    ("Severity", lambda i: i.get("Severity", "")),
    ("CVSS Score", lambda i: i.get("Score", "")),
    ("CVSS Vector", lambda i: i.get("CVSS_Vector", "")),
    ("EPSS Score", lambda i: round(i.get("EPSS_Score", 0), 3)),
    ("EPSS Percentile", lambda i: round(i.get("EPSS_Percentile", 0), 3)),
    ("KEV Status", lambda i: i.get("KEV_Status", "")),
    ("KEV Date Added", lambda i: i.get("KEV_Date_Added", "")),
    ("KEV Due Date", lambda i: i.get("KEV_Due_Date", "")),
    ("Known Ransomware Use", lambda i: i.get("KEV_Ransomware", "")),
    ("CWE", lambda i: i.get("CWE", "")),
    ("Version Match", lambda i: i.get("Version_Match", "")),
    ("Patch Reference (NVD)", lambda i: "Yes" if i.get("Patch_Reference_Found", False) else "No"),
    ("Published", lambda i: i.get("Published_Date", "")),
    ("Description", lambda i: i.get("Description", "")),
    ("Affected Products", lambda i: i.get("Affected_Products", "")),
    ("Link", lambda i: i.get("Link", "")),
]
EXPORT_HEADERS = [h for h, _ in EXPORT_COLUMNS]


def export_filename(product_name, extension):
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", product_name)
    return f"{safe_name}_{datetime.now():%Y-%m-%d_%H-%M-%S}_enhanced_cve_report.{extension}"


def export_to_excel(data, product_name):
    """Manual Excel export - only when requested"""
    reports_dir = os.path.join(get_app_dir(), "cve_reports")
    os.makedirs(reports_dir, exist_ok=True)

    filename = export_filename(product_name, "xlsx")
    filepath = os.path.join(reports_dir, filename)

    wb = Workbook()
    ws = wb.active
    ws.title = "Enhanced CVE Report"
    ws.append(EXPORT_HEADERS)

    # Header formatting
    for cell in ws[1]:
        cell.font = Font(bold=True)
        cell.alignment = Alignment(wrap_text=True)

    # Severity fills -- same fixed status palette used in the UI/charts
    SEVERITY_FILLS = {
        "CRITICAL": PatternFill("solid", fgColor="F8D7DA"),
        "HIGH": PatternFill("solid", fgColor="FDE9D9"),
        "MEDIUM": PatternFill("solid", fgColor="FFF3CD"),
        "LOW": PatternFill("solid", fgColor="D4EDDA"),
    }

    CVE_COL = EXPORT_HEADERS.index("CVE") + 1
    SEVERITY_COL = EXPORT_HEADERS.index("Severity") + 1
    WRAPPED_COLS = (EXPORT_HEADERS.index("Description") + 1, EXPORT_HEADERS.index("Affected Products") + 1)

    for row, item in enumerate(data, start=2):  # row 1 is the header (ws.max_row is O(cells) -- avoid it in loops)
        ws.append([getter(item) for _, getter in EXPORT_COLUMNS])

        # Hyperlink the CVE id
        cell = ws.cell(row=row, column=CVE_COL)
        cell.hyperlink = item.get("Link", "")
        cell.style = "Hyperlink"

        fill = SEVERITY_FILLS.get(item.get("Severity", ""))
        if fill:
            ws.cell(row=row, column=SEVERITY_COL).fill = fill

        for col in WRAPPED_COLS:
            ws.cell(row=row, column=col).alignment = Alignment(wrap_text=True, vertical="top")

    # Column widths -- fixed + wrapped for the long text columns, auto for the rest
    for col in ws.columns:
        col_idx = col[0].column
        if col_idx in WRAPPED_COLS:
            ws.column_dimensions[get_column_letter(col_idx)].width = 60
            continue
        max_length = max((len(str(cell.value or "")) for cell in col), default=10)
        max_length = min(max_length, 40)
        ws.column_dimensions[get_column_letter(col_idx)].width = max_length + 2

    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions

    wb.save(filepath)
    return filename


def export_to_csv(data, product_name):
    """Manual CSV export"""
    filename = export_filename(product_name, "csv")

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(EXPORT_HEADERS)
    for item in data:
        writer.writerow([getter(item) for _, getter in EXPORT_COLUMNS])

    return output.getvalue(), filename


def extract_cve_year(cve_str):
    if cve_str is None:
        return 0
    match = re.match(r'CVE-(\d{4})-\d+', cve_str)
    if match:
        return int(match.group(1))
    return 0


def finished_job_or_404(job_id):
    job = get_job(job_id)
    if job and job["status"] == "done":
        return job
    return None


@app.route('/download/excel')
def download_excel():
    """Manual Excel download of a finished scan"""
    job = finished_job_or_404(request.args.get('job'))
    if not job:
        return "These results are no longer available. Run the search again.", 404
    try:
        filename = export_to_excel(job["results"], job["product"])
        reports_dir = os.path.join(get_app_dir(), "cve_reports")
        return send_from_directory(reports_dir, filename, as_attachment=True)
    except Exception as e:
        return f"Error generating Excel: {e}", 500

@app.route('/download/csv')
def download_csv():
    """Manual CSV download of a finished scan"""
    job = finished_job_or_404(request.args.get('job'))
    if not job:
        return "These results are no longer available. Run the search again.", 404
    try:
        csv_data, filename = export_to_csv(job["results"], job["product"])
        response = make_response(csv_data)
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Content-Type"] = "text/csv"
        return response
    except Exception as e:
        return f"Error generating CSV: {e}", 500

@app.route('/api/theme', methods=['POST'])
def save_theme_preference():
    """Save user theme preference (server-side storage optional)"""
    theme = request.json.get('theme', 'light')
    return jsonify({'status': 'success', 'theme': theme})

if __name__ == "__main__":
    app.run(debug=True)
