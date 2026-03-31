[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![MongoDB](https://img.shields.io/badge/storage-MongoDB-green)](https://www.mongodb.com/)

# DarkPulse

**DarkPulse** is a modular OSINT / threat intelligence platform that collects, normalizes, and displays security data from multiple sources — news, exploits, leaks, defacements, social feeds, and PakDB SIM lookups.

---

## Quick Start (For Collaborators)

### Prerequisites

| Dependency | Required | Install |
|---|---|---|
| **Python 3.11+** | ✅ | [python.org](https://www.python.org/) or `conda create -n fyp_env python=3.11` |
| **MongoDB 6+** | ✅ | `brew install mongodb-community` (macOS) or [mongodb.com](https://www.mongodb.com/try/download/community) |
| **Tor Browser** | Optional | Needed for PakDB lookups — [torproject.org](https://www.torproject.org/) |

### Setup Steps

```bash
# 1. Clone the repo
git clone https://github.com/<your-username>/darkpulse.git
cd darkpulse

# 2. Create & activate Python environment
conda create -n fyp_env python=3.11 -y
conda activate fyp_env

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install Playwright browsers (needed for PakDB)
playwright install chromium

# 5. Create your .env file
cp .env.example .env
# Edit .env — at minimum set MONGO_URI (default localhost is fine)

# 6. Start MongoDB (if not already running)
brew services start mongodb-community   # macOS
# OR: mongod --dbpath /path/to/data      # manual

# 7. Start the backend server
python -m uvicorn ui_server:app --host 0.0.0.0 --port 8000

# 8. Open http://localhost:8000 in your browser
```

### Data Population

The dashboard needs data in MongoDB. To populate it:

```bash
# Run the orchestrator to collect from all sources
conda activate fyp_env
python orchestrator.py
```

This will scrape news, exploits, leaks, defacements, and social feeds into MongoDB.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Browser → http://localhost:8000                │
│  (index.html + app.js + style.css)              │
└────────────┬────────────────────────────────────┘
             │ REST API
┌────────────▼────────────────────────────────────┐
│  ui_server.py (FastAPI + Uvicorn)               │
│  - /news, /threats, /stats                      │
│  - /pakdb/lookup, /pakdb/history, /pakdb/search │
└────────────┬────────────────────────────────────┘
             │
┌────────────▼────────────────────────────────────┐
│  MongoDB (darkpulse database)                   │
│  - articles (news)                              │
│  - redis_kv_store (threats/exploits/leaks)      │
│  - pakdb_lookups (PakDB history)                │
└─────────────────────────────────────────────────┘
```

## Dashboard Tabs

| Tab | Source | Description |
|---|---|---|
| **News** | 8 news scrapers | Cybersecurity news articles |
| **Exploits** | ExploitDB | CVEs and vulnerability exploits |
| **Social** | Forums/channels | Social media threat intel |
| **Leaks** | CERT feeds | Data leak advisories |
| **Defacement** | Defacer.net, Zone-Xsec | Website defacement records |
| **API** | GitHub, APK scanners | API collector results |
| **PakDB** | pakistandatabase.com | SIM database lookups (requires Tor) |

## Tech Stack

- **Backend:** Python, FastAPI, Motor (async MongoDB), Playwright
- **Frontend:** Vanilla HTML/CSS/JS (no framework)
- **Database:** MongoDB
- **Scraping:** BeautifulSoup, Requests, Playwright
- **Proxy:** Tor (SOCKS5) for .onion and PakDB access

## Project Structure

```
darkpulse/
├── ui_server.py          # FastAPI backend (REST API)
├── orchestrator.py       # Scheduled data collection
├── config.py             # Centralized config (reads .env)
├── index.html            # Dashboard UI
├── app.js                # Frontend logic
├── style.css             # Dashboard styling
├── requirements.txt      # Python dependencies
├── .env.example          # Environment variable template
├── news_collector/       # News source scrapers
├── leak_collector/       # Leak/CERT feed scrapers
├── social_collector/     # Social platform scrapers
├── api_collector/        # API-based collectors (GitHub, APK, PakDB)
└── crawler/              # Generic web crawler
```

## Troubleshooting

| Problem | Solution |
|---|---|
| **"Cannot reach backend"** | Make sure `python -m uvicorn ui_server:app --port 8000` is running |
| **"Connection refused"** | Check MongoDB is running: `mongosh` or `brew services list` |
| **Empty dashboard** | Run `python orchestrator.py` to populate data |
| **PakDB "proxy connection failed"** | Open Tor Browser first (it runs on port 9150) |
| **Import errors** | Activate conda env: `conda activate fyp_env` |
