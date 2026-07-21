# Enhanced app.py with Product-Version Insights, Patch Status, and Dependency Tree

from flask import Flask, render_template, request, send_from_directory, jsonify, make_response, session

import os
import sys
import re
import time
import json
from datetime import datetime
from collections import Counter, defaultdict
from openpyxl import Workbook
from openpyxl.utils import get_column_letter
from openpyxl.styles import Font, Alignment, PatternFill
from dotenv import load_dotenv, set_key
import requests
import urllib3
import io
import csv
import networkx as nx
from urllib.parse import urlparse
from flask import request
import secrets


def resource_path(relative_path):
    """Path to a bundled read-only asset (templates/static). Resolves inside
    PyInstaller's onefile temp extraction dir when frozen."""
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


def get_app_dir():
    """Writable directory for user files (cve_reports/, config.env) -- always
    beside the exe when frozen, never inside the ephemeral MEIPASS temp dir."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_ENV_PATH = os.path.join(get_app_dir(), "config.env")
load_dotenv(CONFIG_ENV_PATH)

app = Flask(__name__,
            template_folder=resource_path("templates"),
            static_folder=resource_path("static"))

app.secret_key = secrets.token_hex(32)  # Generate secure secret key
app.config['SESSION_PERMANENT'] = True  # Keep session even after browser closes


def get_persisted_api_key():
    """API key saved to config.env (survives app restarts), if any."""
    key = os.getenv("NVD_API_KEY", "").strip()
    return key if key and key != "your_actual_api_key_here" else ""


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        product = request.form.get("product_name", "").strip()
        version = request.form.get("version", "").strip()
        version = version if version else None

        # API key comes from the Settings tab, not the search form -- prefer
        # the current session, falling back to whatever's persisted on disk.
        api_key = session.get('api_key') or get_persisted_api_key() or None

        # Initialize scanner with the API key
        scanner = EnhancedCVEScanner(api_key=api_key)
        
        # Get base CVE data
        results = scanner.search_nvd(product, version)
        unified_results = [scanner.unify_nvd(v) for v in results]

        # Enhance with EPSS and KEV data
        enhanced_results = scanner.enhance_cve_data(unified_results)

        # Sort by multiple criteria (KEV first, then EPSS, then year)
        enhanced_results.sort(
            key=lambda x: (
                x['KEV_Status'] == 'Known Exploited',
                x['EPSS_Score'],
                extract_cve_year(x['CVE'])
            ),
            reverse=True
        )

        # Generate enhanced analytics data
        analytics = scanner.generate_analytics_data(enhanced_results)

        return render_template(
            "index.html",
            results=enhanced_results,
            analytics=analytics,
            product=product,
            version=version or "",
            api_key=api_key or "",
            api_key_persisted=bool(get_persisted_api_key())
        )

    # For GET request, prefer the session key, falling back to the one saved on disk
    saved_api_key = session.get('api_key') or get_persisted_api_key()
    return render_template(
        "index.html",
        results=None,
        api_key=saved_api_key,
        api_key_persisted=bool(get_persisted_api_key())
    )

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
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.epss_url = "https://api.first.org/data/v1/epss"
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.headers = {"apiKey": api_key} if api_key else {}
        self.delay = 0.6 if api_key else 6

    def search_nvd(self, product, version=None):
        query = product
        if version:
            query += f" {version}"
        print(f"[NVD] Searching exact: {query}")
        
        params = {
            "resultsPerPage": 100,
            "startIndex": 0,
            "keywordSearch": query
        }
        
        try:
            r = requests.get(self.nvd_url, params=params, headers=self.headers, timeout=15, verify=False)
            r.raise_for_status()
            time.sleep(self.delay)
            data = r.json()
            return data.get("vulnerabilities", [])
        except Exception as e:
            print(f"[NVD] Error: {e}")
            return []

    def get_epss_scores(self, cve_list):
        """Get EPSS scores for list of CVEs"""
        if not cve_list:
            return {}
        
        cve_batch = cve_list[:100]
        cve_str = ",".join(cve_batch)
        print(f"[EPSS] Getting scores for {len(cve_batch)} CVEs...")
        
        try:
            response = requests.get(f"{self.epss_url}?cve={cve_str}", timeout=30, verify=False)
            response.raise_for_status()
            data = response.json()
            
            epss_data = {}
            for item in data.get('data', []):
                cve_id = item.get('cve')
                epss_data[cve_id] = {
                    'epss_score': float(item.get('epss', 0)),
                    'epss_percentile': float(item.get('percentile', 0))
                }
            
            print(f"[EPSS] Retrieved scores for {len(epss_data)} CVEs")
            return epss_data
        except Exception as e:
            print(f"[EPSS] Error: {e}")
            return {}

    def get_kev_data(self):
        """Get CISA Known Exploited Vulnerabilities catalog"""
        print("[KEV] Fetching CISA KEV catalog...")
        try:
            response = requests.get(self.kev_url, timeout=30, verify=False)
            response.raise_for_status()
            data = response.json()
            
            kev_lookup = set()
            for vuln in data.get('vulnerabilities', []):
                cve_id = vuln.get('cveID')
                if cve_id:
                    kev_lookup.add(cve_id)
            
            print(f"[KEV] Loaded {len(kev_lookup)} known exploited vulnerabilities")
            return kev_lookup
        except Exception as e:
            print(f"[KEV] Error: {e}")
            return set()

    def check_patch_reference(self, cve):
        """Whether NVD tagged any reference as 'Patch'. Reflects NVD's own
        reference metadata only -- not a verified vendor fix."""
        return any("Patch" in ref.get("tags", []) for ref in cve.get("references", []))

    def unify_nvd(self, item):
        cve = item.get("cve", {})
        desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        
        severity = "N/A"
        score = "N/A"
        metrics = cve.get("metrics", {})
        
        for key in ["cvssMetricV3", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics:
                metric = metrics[key][0] if isinstance(metrics[key], list) else metrics[key]
                sev = metric.get("cvssData", {})
                severity = sev.get("baseSeverity", "N/A")
                score = sev.get("baseScore", "N/A")
                break
        
        # Extract publication date
        pub_date = cve.get("published", "")
        
        # Enhanced affected products extraction with versions
        affected_detailed = self.extract_affected_products_detailed(cve)
        affected_simple = self.extract_affected(cve)
        
        # Check for a patch reference in NVD's own data
        cve_id = cve.get("id")
        patch_reference_found = self.check_patch_reference(cve)

        return {
            "CVE": cve_id,
            "Severity": severity,
            "Score": score,
            "Description": desc,
            "Affected_Products": affected_simple,
            "Affected_Products_Detailed": affected_detailed,
            "Published_Date": pub_date,
            "Link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "EPSS_Score": 0.0,
            "EPSS_Percentile": 0.0,
            "KEV_Status": "Not Known Exploited",
            "Patch_Reference_Found": patch_reference_found
        }

    def extract_affected(self, cve):
        """Simple affected products extraction for backward compatibility"""
        affected = []
        try:
            nodes = cve.get("configurations", [{}])[0].get("nodes", [])
            for node in nodes:
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        affected.append(match.get("criteria", ""))
        except Exception:
            pass
        return ", ".join(affected) if affected else "N/A"

    def extract_affected_products_detailed(self, cve):
        """Enhanced affected products extraction with version parsing"""
        vendors = []
        try:
            nodes = cve.get("configurations", [{}])[0].get("nodes", [])
            for node in nodes:
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        cpe = match.get("criteria", "")
                        # Parse CPE format: cpe:2.3:a:vendor:product:version
                        parts = cpe.split(":")
                        if len(parts) >= 6:
                            vendor = parts[3].replace("_", " ").title()
                            product = parts[4].replace("_", " ").title()
                            version = parts[5].replace("_", " ") if len(parts) > 5 else "Unknown"
                            
                            # Clean up version field
                            if version == "*" or version == "-":
                                version = "All Versions"
                                
                            vendors.append({
                                'vendor': vendor,
                                'product': product,
                                'version': version,
                                'cpe': cpe,
                                'version_start': match.get('versionStartIncluding'),
                                'version_end': match.get('versionEndExcluding')
                            })
        except Exception:
            pass
        return vendors

    def build_dependency_graph(self, results):
        """Build a product -> version graph from real NVD CPE data"""
        G = nx.DiGraph()
        
        # Build graph from affected products
        for item in results:
            cve_id = item['CVE']
            for vendor_info in item.get('Affected_Products_Detailed', []):
                vendor = vendor_info.get('vendor', 'Unknown')
                product = vendor_info.get('product', 'Unknown')
                version = vendor_info.get('version', 'Unknown')
                
                # Create unique node IDs
                product_node = f"{vendor}:{product}"
                version_node = f"{vendor}:{product}:{version}"
                
                # Add nodes with attributes
                G.add_node(product_node, 
                          type='product',
                          vendor=vendor,
                          product=product,
                          cve_count=G.nodes.get(product_node, {}).get('cve_count', 0) + 1,
                          severity=item['Severity'],
                          cves=G.nodes.get(product_node, {}).get('cves', []) + [cve_id])
                
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

                # Add dependency edge
                G.add_edge(product_node, version_node)

        return G

    def _get_cve_year(self, cve_id):
        if not cve_id:
            return 0
        m = re.match(r'CVE-(\d{4})-', cve_id)
        if m:
            return int(m.group(1))
        return 0

    def enhance_cve_data(self, unified_results):
        """Add EPSS and KEV data to CVE results"""
        cve_ids = [item['CVE'] for item in unified_results if item['CVE']]
        
        # Get enrichment data
        epss_data = self.get_epss_scores(cve_ids)
        kev_data = self.get_kev_data()
        
        # Enhance each CVE
        for item in unified_results:
            cve_id = item['CVE']
            
            # Add EPSS score
            if cve_id in epss_data:
                item['EPSS_Score'] = epss_data[cve_id]['epss_score']
                item['EPSS_Percentile'] = epss_data[cve_id]['epss_percentile']
            
            # Add KEV status
            if cve_id in kev_data:
                item['KEV_Status'] = 'Known Exploited'
        
        return unified_results

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
            # NEW: Product-Version analysis
            'vendor_version_matrix': defaultdict(lambda: defaultdict(int)),
            'top_vulnerable_versions': Counter(),
            # NEW: Patch availability
            'patch_status': {'patched': 0, 'unpatched': 0},
            'patch_by_vendor': defaultdict(lambda: {'patched': 0, 'unpatched': 0}),
            # NEW: Dependency graph data
            'dependency_graph': {}
        }
        
        for item in results:
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
            year = self._get_cve_year(item['CVE'])
            if year > 0:
                analytics['year_trends'][year] += 1
            
            # Enhanced vendor-version analysis
            for vendor_info in item.get('Affected_Products_Detailed', []):
                vendor = vendor_info.get('vendor', 'Unknown')
                version = vendor_info.get('version', 'Unknown')
                
                # Traditional vendor analysis
                analytics['vendor_analysis'][vendor] += 1
                
                # NEW: Vendor-Version matrix for heatmap
                analytics['vendor_version_matrix'][vendor][version] += 1
                
                # NEW: Top vulnerable versions across all vendors
                version_key = f"{vendor} {version}"
                analytics['top_vulnerable_versions'][version_key] += 1
            
            # NEW: Patch reference analysis
            if item.get('Patch_Reference_Found', False):
                analytics['patch_status']['patched'] += 1
            else:
                analytics['patch_status']['unpatched'] += 1

            # Patch reference status by vendor
            for vendor_info in item.get('Affected_Products_Detailed', []):
                vendor = vendor_info.get('vendor', 'Unknown')
                if item.get('Patch_Reference_Found', False):
                    analytics['patch_by_vendor'][vendor]['patched'] += 1
                else:
                    analytics['patch_by_vendor'][vendor]['unpatched'] += 1

            # EPSS vs CVSS correlation data
            cvss_score = item['Score']
            if cvss_score != 'N/A':
                analytics['epss_cvss_data'].append({
                    'x': float(cvss_score),
                    'y': float(item['EPSS_Score']),
                    'kev': item['KEV_Status'] == 'Known Exploited',
                    'cve': item['CVE'],
                    'patch_ref': item.get('Patch_Reference_Found', False)
                })
        
        # Build dependency graph
        dep_graph = self.build_dependency_graph(results)
        analytics['dependency_graph'] = nx.readwrite.json_graph.node_link_data(dep_graph)
        
        # Convert defaultdicts to regular dicts for JSON serialization
        analytics['vendor_version_matrix'] = {k: dict(v) for k, v in analytics['vendor_version_matrix'].items()}
        analytics['patch_by_vendor'] = {k: dict(v) for k, v in analytics['patch_by_vendor'].items()}
        
        return analytics

    def export_to_excel_manual(self, data, product_name):
        """Manual Excel export - only when requested"""
        reports_dir = os.path.join(get_app_dir(), "cve_reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", product_name)
        filename = f"{safe_name}_{datetime.now():%Y-%m-%d_%H-%M-%S}_enhanced_cve_report.xlsx"
        filepath = os.path.join(reports_dir, filename)
        
        wb = Workbook()
        ws = wb.active
        ws.title = "Enhanced CVE Report"
        
        # Enhanced headers with new fields
        headers = ["CVE", "Severity", "CVSS Score", "EPSS Score", "EPSS Percentile", "KEV Status",
                  "Patch Reference (NVD)", "Description", "Affected Products", "Link"]
        ws.append(headers)

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

        DESCRIPTION_COL = 8
        AFFECTED_COL = 9

        # Add data rows
        for item in data:
            ws.append([
                item.get("CVE", ""),
                item.get("Severity", ""),
                item.get("Score", ""),
                round(item.get("EPSS_Score", 0), 3),
                round(item.get("EPSS_Percentile", 0), 3),
                item.get("KEV_Status", ""),
                "Yes" if item.get("Patch_Reference_Found", False) else "No",
                item.get("Description", ""),
                item.get("Affected_Products", ""),
                ""
            ])
            row = ws.max_row

            # Add hyperlink
            cell = ws.cell(row=row, column=1)
            cell.hyperlink = item.get("Link", "")
            cell.style = "Hyperlink"

            fill = SEVERITY_FILLS.get(item.get("Severity", ""))
            if fill:
                ws.cell(row=row, column=2).fill = fill

            for col in (DESCRIPTION_COL, AFFECTED_COL):
                ws.cell(row=row, column=col).alignment = Alignment(wrap_text=True, vertical="top")

        # Column widths -- fixed + wrapped for the long text columns, auto for the rest
        for col in ws.columns:
            col_idx = col[0].column
            if col_idx in (DESCRIPTION_COL, AFFECTED_COL):
                ws.column_dimensions[get_column_letter(col_idx)].width = 60
                continue
            max_length = max((len(str(cell.value) or "") for cell in col), default=10)
            max_length = min(max_length, 40)
            ws.column_dimensions[get_column_letter(col_idx)].width = max_length + 2

        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions

        wb.save(filepath)
        return filename

    def export_to_csv_manual(self, data, product_name):
        """Manual CSV export"""
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", product_name)
        filename = f"{safe_name}_{datetime.now():%Y-%m-%d_%H-%M-%S}_enhanced_cve_report.csv"
        
        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow(["CVE", "Severity", "CVSS Score", "EPSS Score", "EPSS Percentile",
                        "KEV Status", "Patch Reference (NVD)", "Description", "Affected Products", "Link"])

        # Write data
        for item in data:
            writer.writerow([
                item.get("CVE", ""),
                item.get("Severity", ""),
                item.get("Score", ""),
                round(item.get("EPSS_Score", 0), 3),
                round(item.get("EPSS_Percentile", 0), 3),
                item.get("KEV_Status", ""),
                "Yes" if item.get("Patch_Reference_Found", False) else "No",
                item.get("Description", ""),
                item.get("Affected_Products", ""),
                item.get("Link", "")
            ])
        
        return output.getvalue(), filename

scanner = EnhancedCVEScanner(api_key=os.getenv("NVD_API_KEY"))

def extract_cve_year(cve_str):
    if cve_str is None:
        return 0
    match = re.match(r'CVE-(\d{4})-\d+', cve_str)
    if match:
        return int(match.group(1))
    return 0

@app.route('/download/excel')
def download_excel():
    """Manual Excel download"""
    product = request.args.get('product', 'results')
    results_json = request.args.get('data', '[]')
    try:
        results = json.loads(results_json)
        filename = scanner.export_to_excel_manual(results, product)
        reports_dir = os.path.join(get_app_dir(), "cve_reports")
        return send_from_directory(reports_dir, filename, as_attachment=True)
    except Exception as e:
        return f"Error generating Excel: {e}", 500

@app.route('/download/csv')
def download_csv():
    """Manual CSV download"""
    product = request.args.get('product', 'results')
    results_json = request.args.get('data', '[]')
    try:
        results = json.loads(results_json)
        csv_data, filename = scanner.export_to_csv_manual(results, product)
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