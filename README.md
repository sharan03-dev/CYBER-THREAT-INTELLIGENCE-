# Kavach CTI Platform

Kavach is a Cyber Threat Intelligence (CTI) platform for collecting, exploring, and assessing security reports and indicators. It provides a web dashboard, a FastAPI backend, and a MongoDB data store, with interactive demonstrations of MongoDB schema design, working-set analysis, and common data-modeling use cases.

> Developed for Exercise 7, 23CSE528 — NoSQL Database using MongoDB.

## Screenshots

### Overview dashboard

![Kavach CTI overview dashboard](docs/screenshots/overview.png)

### IP intelligence dossier

![Kavach CTI IP intelligence dossier](docs/screenshots/ip-dossier.png)

### Schema lab

![Kavach CTI schema lab](docs/screenshots/schema-lab.png)

## Features

- **Threat intelligence feed:** Search and filter reports, inspect classification details, and browse associated indicators.
- **Overview dashboard:** Review threat categories, severity trends, CVEs, threat actors, and source health.
- **IP intelligence:** Investigate IP addresses using local feed evidence, CIDR ranges, and optional external reputation services.
- **Explainable risk assessment:** View a 0–100 score, contributing evidence, and a risk verdict for an IP address.
- **Text classifier:** Analyze text for threat category, severity, verdict, Admiralty code, and extracted indicators of compromise (IOCs).
- **Feed and source management:** View source status and trigger feed refreshes.
- **MongoDB labs:** Explore production-style schema design, embedded-document redesign, working-set behavior, and cache monitoring.
- **Six MongoDB use-case patterns:** See examples covering content management, product catalogs, analyst profiles, time-series ingestion, analytics, and live synchronization.

## Technology

| Area | Technology |
|---|---|
| Backend | Python, FastAPI, Uvicorn, PyMongo |
| Frontend | HTML, CSS, JavaScript |
| Database | MongoDB 8.0 |
| Data ingestion | RSS and IOC feeds, CISA KEV, and security reports |

## Requirements

- Python 3.12 (recommended)
- MongoDB 8.0
- Internet access to fetch live threat-intelligence data

The project includes bundled sample reports and an offline setup option. Optional API keys enable additional IP reputation lookups; the application can start without them.

## Installation and setup

Run these commands from the repository root.

### 1. Create a virtual environment and install dependencies

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure the application

```bash
cp .env.example .env
```

The defaults connect to MongoDB at `mongodb://localhost:27017`. Edit `.env` to change the connection or add optional provider keys.

### 3. Start MongoDB

On macOS with Homebrew:

```bash
brew services start mongodb-community@8.0
```

On other platforms, start your MongoDB 8.0 service using the appropriate service manager.

### 4. Initialize the database

```bash
python backend/scripts/setup_database.py
```

This command fetches available source data and prepares the platform collections. Initial setup may take a few minutes. For sample data without live feed downloads, run:

```bash
python backend/scripts/setup_database.py --offline
```

### 5. Run the web application

```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Visit [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser. On macOS, the included `./run.sh` script starts MongoDB if needed and launches the application.

## Configuration

Copy `.env.example` to `.env`. Available settings include:

| Variable | Description | Default |
|---|---|---|
| `MONGO_URI` | MongoDB connection string | `mongodb://localhost:27017` |
| `MONGO_DB` | Main application database | `cti_platform` |
| `LAB72_DB` | Lab 7.2 database | `cti_lab72` |
| `PORT` | Web server port used by `run.sh` | `8000` |
| `IPSUM_MIN_HITS` | Minimum IPsum list matches for imported IPs | `2` |
| `NEWS_ITEMS_PER_FEED` | Maximum news items collected per feed | `40` |
| `LOOKUP_CACHE_HOURS` | IP lookup cache lifetime in hours | `6` |
| `GREYNOISE_API_KEY` | Optional GreyNoise API key | — |
| `ABUSEIPDB_API_KEY` | Optional AbuseIPDB API key | — |
| `VIRUSTOTAL_API_KEY` | Optional VirusTotal API key | — |
| `OTX_API_KEY` | Optional AlienVault OTX API key | — |

Keep credentials in `.env`; do not commit secrets to the repository.

## Labs and demonstrations

Run commands from the repository root.

| Lab or activity | Command |
|---|---|
| Lab 7.1: production schema analysis and dump | `python labs/lab7_1/lab_01_production_schema.py --dump` |
| Lab 7.1: analyze from a dump | `python labs/lab7_1/lab_01_production_schema.py --from-dump` |
| Activity 7.1: embedded redesign | `python labs/lab7_1/activity_7_1_embedded_redesign.py` |
| Lab 7.2: working-set analysis | `python labs/lab7_2/lab_02_working_set_analysis.py --small-cache 128` |
| Activity 7.2: cache monitor with workload | `python labs/lab7_2/activity_7_2_monitor.py --workload` |
| MongoDB use-case patterns | `python labs/use_cases/use_case_patterns.py` |
| Use case 6: live sync demonstration | `python labs/use_cases/watch_reports.py --demo` |

Written answers and explanations:

- `labs/lab7_1/ANSWERS.md`
- `labs/lab7_2/ANSWERS.md`
- `labs/use_cases/USE_CASES.md`

MongoDB change streams require a replica set. When the database runs as a standalone server, the live-sync feature falls back to polling. See `labs/use_cases/USE_CASES.md` for replica-set setup instructions.

## Data sources and external services

The ingestion pipeline uses public security news feeds, IOC feeds, CISA KEV, and security-report sources. IP investigations can query external reputation services; optional providers require their own API keys. The `--offline` database setup mode loads bundled sample data without fetching live feeds. Review third-party provider terms before using their services.

## Project structure

```text
backend/
  app/                 FastAPI routes, database access, ingestion, classification, labs
  scripts/             Database setup scripts
  data/                Bundled sample reports
frontend/              Web interface and static assets
labs/                  Lab scripts, activities, and written explanations
docs/screenshots/       Application screenshots
dump/                  Database dump documentation and generated dumps
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
