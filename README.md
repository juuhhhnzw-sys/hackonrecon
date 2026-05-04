# HackOn Recon — Automated Recon & Pentest Insight Platform

**HackOn Recon** is a portfolio-grade, production-style recon and insight tool built for **authorized security testing** and education. It runs multiple recon modules in parallel, normalizes results into a unified schema, scores risk using deterministic rules, and generates:

- JSON output
- Markdown report
- CLI visualization

## Quick start

### 1) Install

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### 2) Run

```bash
python -m hackon.backend.cli example.com --max-workers 6 --timeout 12
```

Outputs are written to:

- `scans/` (JSON)
- `reports/` (Markdown)

### 3) API bridge (FastAPI) + dashboard

Install API dependencies (included in `requirements.txt`):

```bash
pip install -r requirements.txt
```

Start the API (from the project root, with venv activated):

```bash
python -m uvicorn hackon.backend.api.main:app --host 127.0.0.1 --port 8000
```

Endpoints:

- `POST /api/scans` — body: `{ "target": "example.com", "max_workers": 6, "timeout": 12 }`
- `GET /api/scans` — list scans
- `GET /api/scans/{id}` — status (`queued` | `running` | `done` | `failed`)
- `GET /api/scans/{id}/result` — full normalized JSON (+ `id` for the UI)
- `GET /api/scans/{id}/report.md` — Markdown report file

### 4) Frontend dashboard

Requires [Node.js LTS](https://nodejs.org/) (includes `npm`). The UI talks **only** to the real API (no mock).

1. Start the API (step 3).
2. Then:

```bash
cd frontend
cp .env.example .env
npm install
npm run dev
```

`frontend/.env` must point at your API, for example:

```bash
VITE_API_BASE_URL=http://127.0.0.1:8000
```

On Windows PowerShell, if `cp` is unavailable:

```powershell
Copy-Item .env.example .env
```

## Environment variables

| Where | Variable | Required | Description |
|--------|-----------|----------|-------------|
| `frontend/.env` | `VITE_API_BASE_URL` | Yes (for UI) | Base URL of the FastAPI server (no trailing slash). |
| Server env | `HACKON_CORS_ORIGINS` | No | Comma-separated extra CORS origins (e.g. your deployed frontend). Local dev is covered by defaults. |

Templates: root `.env.example` (backend notes) and `frontend/.env.example` (Vite).

**Do not commit** `frontend/.env`, `.venv/`, `node_modules/`, or `scans/` — they are listed in `.gitignore`.

## Publish to GitHub (portfolio)

From the project root (after `.gitignore` is in place):

```bash
git init
git add .
git status   # confirm .venv, node_modules, scans, frontend/.env are NOT listed
git commit -m "Initial commit: HackOn Recon platform"
```

Create an empty repository on GitHub, then:

```bash
git remote add origin https://github.com/SEU_USUARIO/hackon-recon.git
git branch -M main
git push -u origin main
```

Replace `SEU_USUARIO/hackon-recon` with your repo path.

## Safety

This project performs **recon only** (port checks, HTTP GET, directory discovery, subdomain enumeration) and does not include destructive exploitation or payload delivery.

## Project layout

Matches the required architecture:

```
hackon/
  backend/
    api/main.py
    core/orchestrator.py
    modules/
    analyzer/risk_engine.py
    report/generator.py
    utils/
    cli.py
scans/
reports/
```

