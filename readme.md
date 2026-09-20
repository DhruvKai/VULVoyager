# VULVoyager

A desktop app that looks up CVEs for a product/version against NVD, enriches them
with EPSS and CISA KEV data, and shows the results with charts and CSV/Excel export.

## Searching

- **Product** is matched against NVD by keyword; every page of results is loaded (up to
  5,000 CVEs -- narrow the name if a warning says the cap was hit). Results appear as they
  load: CVEs show up as each NVD page arrives, then KEV status and EPSS scores fill in while a
  progress bar tracks the scan, and the charts and exports become available when it finishes.
- **Version (optional)** checks the version against NVD's affected-version ranges instead of
  just searching for the text, so `apache http server` + `2.4.49` only shows CVEs whose ranges
  include 2.4.49. Each CVE is tagged **Affects <version>** or **Version unverified** (NVD has
  no version data for it yet), and CVEs that NVD lists under a different product, or whose
  ranges exclude the version, are hidden -- a notice above the table says how many. Version
  comparison is best-effort for unusual versioning schemes.
- **Details** under each CVE expands its CWE weakness type, CVSS vector breakdown, CISA KEV
  dates and ransomware flag, and reference links grouped by tag (Patch, Exploit, Vendor
  Advisory, ...).
- **CVE list**: type in the box under any column header to filter by that column. **Full page**
  (top-left of the table) expands the list edge to edge; press Esc to leave it.
- **Analytics** tab: a "Fix these first" top-10 (KEV first, then EPSS, then CVSS), risk
  distribution, severity breakdown, EPSS vs CVSS, attack vector, trends by year, top vendors,
  most vulnerable versions, top weakness types (CWE), patch-reference coverage and a CISA KEV
  spotlight.
- The CISA KEV catalog is cached in a `cache/` folder next to the app for 24 hours (and used
  as a fallback if CISA is unreachable). Delete the folder to force a refresh.

## Setup

Install dependencies:

```
pip install -r requirements.txt
```

## Running

- **Desktop app** (native window, no browser/console): `python desktop.py`
- **Browser-based dev mode** (Flask dev server, auto-reload): `python app.py`, then open `http://127.0.0.1:5000`

## Building the standalone .exe

```
pyinstaller VULVoyager.spec
```

The built app is written to `dist/VULVoyager.exe`.

## How to Get an NVD API Key

An API key is optional but strongly recommended -- without one, NVD rate-limits
requests to one every 6 seconds.

1. Go to the official NVD API key request page:
   https://nvd.nist.gov/developers/request-an-api-key

2. Fill out the request form (name, email, optional organization) and submit.

3. Check your email (including Spam/Junk) for your key.

## Using the API key

1. Open `config.env` in the project root (same folder as `app.py`) and set:

   ```
   NVD_API_KEY=your_actual_api_key_here
   ```

   `config.env` is gitignored -- your key stays local. You can also paste the key
   directly into the app's search form; it's remembered for the session.

2. The app loads it automatically via `python-dotenv` and sends it as the `apiKey`
   header on NVD requests.
