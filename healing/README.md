# Healing Monitor

This module powers the DARKPULSE `Healing Monitor` page. It discovers collector scripts, checks whether they still return data, records live-site reachability, stores HTML snapshots, compares DOM drift, measures selector health, and generates safe repair previews.

## Open-source tools used

Everything is local and self-hosted:

- Python standard library: `ast`, `pathlib`, `hashlib`, `json`, `difflib`, `datetime`, `threading`
- `requests` for free HTTP reachability checks
- `beautifulsoup4` for local DOM parsing and selector evaluation
- `playwright` only where the project already uses browser-driven collectors
- `pymongo` / MongoDB for local status, snapshot, event, and repair storage

No paid API, hosted monitor, or premium healing service is used.

## Architecture

- [discovery.py](./discovery.py)
  Scans collector folders, ignores helper/config files, extracts target URLs and selector hints.
- [live_check.py](./live_check.py)
  Runs free local live checks and captures response code, final URL, response time, and HTML.
- [html_snapshot.py](./html_snapshot.py)
  Stores baseline/latest snapshots under `data/healing/snapshots`.
- [selector_health.py](./selector_health.py)
  Tests selector hints against the latest DOM and calculates selector health.
- [drift_detector.py](./drift_detector.py)
  Compares baseline vs latest structure and labels change as `no_change`, `minor_change`, or `major_change`.
- [repair_engine.py](./repair_engine.py)
  Generates conservative selector replacement suggestions from DOM similarity.
- [health_runner.py](./health_runner.py)
  Executes single-script checks, updates runtime status, snapshots, events, and repair previews.
- [status_service.py](./status_service.py)
  Main application service used by API routes and the CLI.
- [routes.py](./routes.py)
  FastAPI endpoints for the frontend.
- [storage.py](./storage.py)
  Mongo-backed storage plus local patch/backup files.

## Workflow

1. Discovery scans all collector roots and registers monitorable scripts.
2. Each script is checked in safe test mode.
3. If the site is reachable, the current HTML is stored and compared with the baseline snapshot.
4. Selector health is calculated from the script's known selectors.
5. If data stops coming and the DOM changed, a repair preview is generated.
6. Repair application is guarded:
   - a backup is created first
   - the candidate patch is applied
   - the script is re-tested immediately
   - if data does not recover, the original file is restored automatically

## Stored data

Mongo collections:

- `healing_targets`
- `healing_snapshots`
- `healing_events`
- `healing_repairs`
- `healing_runtime`

Local files:

- snapshots: `data/healing/snapshots/`
- repair previews: `data/healing/repairs/`
- rollback backups: `data/healing/backups/`

## Manual run commands

From the project root:

```bash
./myenv/bin/python -m healing.cli discover
./myenv/bin/python -m healing.cli summary
./myenv/bin/python -m healing.cli run --limit 12
./myenv/bin/python -m healing.cli run --collector leak --mode collector --limit 25
./myenv/bin/python -m healing.cli check api_collector__scripts___pakdb_py
./myenv/bin/python -m healing.cli repair api_collector__scripts___pakdb_py
./myenv/bin/python -m healing.cli apply-repair api_collector__scripts___pakdb_py
```

## Adding a new collector script into monitoring

To be discovered automatically, the script should:

1. Live under one of the collector roots:
   - `news_collector/scripts`
   - `leak_collector/scripts`
   - `defacement_collector/scripts`
   - `exploit_collector/scripts`
   - `social_collector/scripts`
   - `api_collector/scripts`
2. Contain a real target URL or domain in the source file.
3. Define a collector class matching the filename stem.
4. Avoid being only a helper/config/query-only utility file.

If the script contains selectors such as `select`, `select_one`, `query_selector`, `query_selector_all`, or `find/find_all`, the monitor will extract selector hints automatically.

## Selector mappings

Selector repair previews are stored in:

- Mongo `healing_repairs`
- local JSON files under `data/healing/repairs/<script_id>/`

Each preview keeps:

- failed selectors
- suggested replacements
- old selector -> new selector mappings
- candidate patch path
- repair confidence

## Rollback behavior

When `apply-repair` runs:

1. A full backup of the original script is written to `data/healing/backups/<script_id>/`
2. The candidate patch is applied
3. The script is re-tested
4. If data recovery fails, the original file is restored automatically

This keeps repairs reversible and prevents blind destructive changes.
