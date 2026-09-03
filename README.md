# NULLSEC KIT Backend

NULLSEC KIT is a professional web-based passive defensive security toolkit and authorized-assessment API. Built using Python 3.12, FastAPI, and Pydantic, the backend delivers high-performance, modular, secure, and production-ready security tools.

This repository covers **Phase 1 (Foundation)** and **Phase 2 (DNS Lookup)**.

---

## 🛡️ Architecture & Flow

The backend enforces a strict separation of concerns to maintain clean code quality:

```
ROUTE
  ↓
SCHEMA VALIDATION
  ↓
SERVICE (Decoupled, SSRF Protected)
  ↓
LIBRARY / EXTERNAL PROVIDER (e.g. dnspython)
  ↓
NORMALIZED RESULT
  ↓
API RESPONSE
```

### Modular Structure

- **`app/main.py`**: Lightweight bootstrapper. Configures middlewares, registers global error handlers, and mounts the API routers.
- **`app/config/settings.py`**: Reads configuration and defines fallback defaults.
- **`app/api/router.py`**: Houses the modular sub-routes namespaces (`/api/v1`).
- **`app/middleware/`**: Implements custom IP-based rate limiting (with automatic Redis fallback) and standard HTTP security hardening headers.
- **`app/utils/validation.py`**: Contains strict format validators (IP, domain, URL, CVE, port) and protects against SSRF (Server-Side Request Forgery) by ensuring targets resolve to public/external hosts.
- **`app/database/`**: Fully decoupled interfaces for MongoDB and Redis that fail open/fall back to safe in-memory mock stores if servers are down.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.11+
- Virtualenv (recommended)

### Local Setup

1. **Clone and navigate to the directory**:
   ```bash
   cd backend
   ```

2. **Set up a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Create a local `.env` configuration**:
   ```bash
   cp .env.example .env
   ```

5. **Start the Uvicorn Dev Server**:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```

6. **Interactive Documentation**:
   Once started, visit:
   - Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
   - ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## 🧪 Running Automated Tests

All core functionality (routing, health checks, domain validation, SSRF blocklists, rate-limiting mock, and DNS resolution) is fully covered under Python `pytest`.

To run tests:
```bash
pytest -v
```

---

## 📦 Containerization & Deployment

### Run with Docker

1. **Build image**:
   ```bash
   docker build -t nullsec-kit-backend .
   ```

2. **Run container**:
   ```bash
   docker run -p 8000:8000 -e PORT=8000 nullsec-kit-backend
   ```

### Deploying to Render
NULLSEC KIT is configured for instant deployment on Render. It includes:
- `Dockerfile` for containerized runtimes.
- `render.yaml` for one-click setup.
- Automatic Port binding configuration.
