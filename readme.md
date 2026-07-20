# VULVoyager

A desktop app that looks up CVEs for a product/version against NVD, enriches them
with EPSS and CISA KEV data, and shows the results with charts and CSV/Excel export.

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
