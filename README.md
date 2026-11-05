# ScanTrack

Vulnerability findings management API. Ingests scanner output, deduplicates findings, tracks each from `open` to `fixed`.

## Run locally
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env        # then set SECRET_KEY (command inside the file)
python -m scripts.create_admin
uvicorn app.main:app --reload     # docs at http://localhost:8000/docs
pytest -q
```

## Run with Docker
```bash
docker compose up --build -d
docker compose exec api python -m scripts.create_admin
```

## Where to change things
| I want to...                    | Edit                          |
|---------------------------------|-------------------------------|
| Add / change an endpoint        | `app/api/v1/<name>.py`        |
| Change business rules           | `app/services/`               |
| Add a DB column / table         | `app/models/` (+ migration)   |
| Change request/response shape   | `app/schemas/`                |
| Change auth / hashing / JWT     | `app/core/security.py`        |
| Change roles / permissions      | `app/api/deps.py`             |
| Add a setting                   | `app/core/config.py`          |

## Endpoints (`/api/v1`)
| Method | Path                    | Role            |
|--------|-------------------------|-----------------|
| POST   | /auth/login             | public          |
| GET    | /auth/me                | any             |
| POST   | /users                  | admin           |
| POST   | /ingest                 | analyst, admin  |
| GET    | /findings               | any             |
| GET    | /findings/{id}          | any             |
| PATCH  | /findings/{id}/status   | analyst, admin  |
| GET    | /health (no prefix)     | public          |

Lifecycle: `open -> in_progress -> fixed`, `fixed -> open` (also automatic when a scanner reports it again).
