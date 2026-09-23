# 15-Day Engineering & Development Log

## Project: Zero Trust Policy Verification Engine (ZTPVE)
**Developer**: Harshad (B.Tech IT)  
**Timeline**: 15-Day Structured Capstone Sprint  

---

### DAY 1: Project Initialization & Architectural Foundation
**Date**: September 9, 2026  
**Objective**: Set up repository, establish technology constraints (AWS Free Tier, Python, FastAPI), create architecture notes, and construct the foundational project skeleton.

#### 1. Tasks Executed
- [x] Initialized Git repository with appropriate `.gitignore` (ignoring `.env`, `.db`, virtual environments, caches).
- [x] Created `requirements.txt` pinning core dependencies: `fastapi`, `uvicorn`, `pydantic`, `boto3`, `pytest`, `httpx`.
- [x] Defined `.env.example` template with storage switches (`STORAGE_BACKEND=sqlite` vs `dynamodb`).
- [x] Added `LICENSE` (MIT).
- [x] Drafted initial architecture documentation ([docs/architecture.md](architecture.md)) detailing the three-tier design (Presentation, FastAPI API, TOC FSM Engine, Storage Abstraction).
- [x] Created baseline directory layout:
  ```text
  zero-trust-policy-verification/
  ├── backend/
  │   ├── api/
  │   ├── core/
  │   ├── models/
  │   └── storage/
  ├── frontend/
  ├── policies/
  ├── docs/
  └── scripts/
  ```

#### 2. Key Architectural Decisions (Student Design Notes)
- **Decision 1: Why Python and FastAPI?**  
  *Rationale*: Python is optimal for formal graph algorithms and Theory of Computation representations. FastAPI was chosen over Flask because FastAPI provides native Pydantic v2 validation, automatic OpenAPI `/docs`, and async request handling out-of-the-box.
- **Decision 2: Dual Storage Strategy (SQLite + DynamoDB)**  
  *Rationale*: For local testing and viva demos, SQLite requires zero setup and runs offline. For cloud deployment, DynamoDB provisioned at 5 RCU/5 WCU fits within the permanent AWS Free Tier ($0/month). The repository pattern abstracts both behind `PolicyRepository`.
- **Decision 3: Zero-Bloat Frontend**  
  *Rationale*: Avoid heavy React/Node toolchains that can break during offline viva evaluations. Use clean HTML5/CSS/JavaScript with Cytoscape.js loaded via CDN or static asset.

#### 3. Git Commits for Day 1
- `2651d34` - `chore: initialize repository and development environment`
- `a8198e5` - `docs: add initial project architecture and setup specification`

#### 4. Reflections & Next Steps for Day 2
- *Reflection*: Setting up the `.gitignore` early prevents accidental commits of secrets and local database files.
- *Tomorrow's Goal (Day 2)*: Formally specify the Zero Trust Policy JSON schema and build Pydantic v2 data models (`ZeroTrustPolicy`, `PolicyRule`, `PolicyMetadata`).

---

*(Days 2 through 15 are documented in subsequent log entries.)*
