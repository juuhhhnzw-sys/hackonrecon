# 👾 HackOn Recon

### Modular reconnaissance platform with multithreaded scanning, plugin architecture and deterministic risk analysis

## 📊 Dashboard Preview

<p align="center">
  <img src="./docs/dashboard.png" width="800"/>
</p>

---

## 💡 Why This Project

This project demonstrates how real-world reconnaissance pipelines can be structured
using modular architecture, parallel execution and deterministic analysis.

It focuses on building systems, not just scripts.

---

## 🧠 Overview

HackOn Recon is a **modular reconnaissance and analysis platform** designed for authorized security testing and education.

It orchestrates multiple scanning modules in parallel, normalizes results into a unified schema, applies deterministic risk scoring, and produces structured outputs for analysis.

---

## ⚙️ Key Features

* ⚡ **Parallel scanning engine** (multithreaded execution)
* 🧩 **Plugin-based architecture (addons)**
* 📊 **Unified data normalization layer**
* 🧠 **Deterministic risk scoring (0–100)**
* 📄 **Automated report generation (JSON + Markdown)**
* 🌐 **REST API (FastAPI)**
* 💻 **Interactive dashboard (frontend)**

---

## 🧩 Plugin System

HackOn uses a modular addon-based architecture where each scanning component
operates independently and integrates into a unified pipeline.

---
## 🧩 Architecture

```bash
Input (target)
 → Orchestrator
   → Modules (addons)
     - Port Scanner
     - HTTP Probe
     - Dir Fuzzer
     - Subdomain Enum
   → Normalization Layer
   → Risk Engine (0–100 scoring)
   → Report Generator
 → Output (JSON + Markdown + API)
```

---

## 📊 Example Output

```json
{
  "target": "example.com",
  "open_ports": [80, 443],
  "endpoints": [
    { "path": "/admin", "status": 403, "risk": "medium" },
    { "path": "/api", "status": 200, "risk": "low" }
  ],
  "subdomains": ["api.example.com"],
  "risk_score": 45,
  "severity": "medium"
}
```

---

## 🚀 Quick Start

### 1) Install

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

---

### 2) Run CLI

```bash
python -m hackon.backend.cli example.com --max-workers 6 --timeout 12
```

Outputs:

* `scans/` → JSON
* `reports/` → Markdown

---

### 3) API (FastAPI)

```bash
python -m uvicorn hackon.backend.api.main:app --host 127.0.0.1 --port 8000
```

Endpoints:

* `POST /api/scans`
* `GET /api/scans`
* `GET /api/scans/{id}`
* `GET /api/scans/{id}/result`
* `GET /api/scans/{id}/report.md`

---

### 4) Dashboard

```bash
cd frontend
cp .env.example .env
npm install
npm run dev
```

---

## ⚙️ Environment

| Variable            | Description          |
| ------------------- | -------------------- |
| VITE_API_BASE_URL   | API base URL         |
| HACKON_CORS_ORIGINS | Optional CORS config |

---

## 📁 Project Structure

```bash
hackon/
  backend/
    api/
    core/
    modules/
    analyzer/
    report/
    utils/
    cli.py

scans/
reports/
```

---

## 🔐 Safety

This project is intended for **authorized testing and educational use only**.

It performs **reconnaissance only** (no exploitation or payload delivery).

---

## 🎯 Purpose
Designed to simulate real-world reconnaissance pipelines using modular and scalable architecture.

---
