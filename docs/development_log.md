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

### DAY 2: Zero Trust Policy Data Model & Schema Validation
**Date**: September 10, 2026  
**Objective**: Formally define the access policy data format, state and transition schemas, validation rules, and automated model unit tests.

#### 1. Tasks Executed
- [x] Defined `PolicyRule` Pydantic model (`source`, `target`, `action`, `condition`, `description`, auto-generated `rule_id`).
- [x] Defined `PolicyMetadata` model (author, target_resource, allowed_roles, max_session_seconds, risk_threshold).
- [x] Implemented `ZeroTrustPolicy` model with configurable `initial_state` (default `START`), `terminal_states` list, and `get_all_states()` method.
- [x] Enforced schema constraints: minimum 1 rule per policy, required source and target states, automated UUID prefixes (`pol_`, `rule_`).
- [x] Implemented comprehensive unit tests in `backend/tests/test_policy_model.py` covering model creation, validation errors, and state aggregation.

#### 2. Key Architectural Decisions (Student Design Notes)
- **Decision 1: Why JSON-based Declarative Policy Format?**  
  *Rationale*: JSON is universally serializable across REST APIs, easily ingested by AWS DynamoDB, human-editable, and maps directly to the formal transition relation $\delta \subseteq Q \times \Sigma \times \mathcal{C} \times Q$.
- **Decision 2: Automated Unique State Aggregation (`get_all_states`)**  
  *Rationale*: Instead of forcing the administrator to redundantly list every state name in a separate `states` array, `get_all_states()` calculates $Q = \{q_0\} \cup F \cup \{s \mid (s, t) \in \delta\} \cup \{t \mid (s, t) \in \delta\}$. This prevents human typo desynchronization between state declarations and rule definitions.
- **Decision 3: Pydantic v2 Field Validation**  
  *Rationale*: Catches malformed policy submissions at the API boundary before running graph verification algorithms.

#### 3. Git Commits for Day 2
- `b738e9e` - `feat: define Zero Trust policy and rule data models with Pydantic v2`
- `test: add unit test suite for policy model and schema validation`

#### 4. Reflections & Next Steps for Day 3
- *Reflection*: Pydantic v2 is noticeably faster than v1 and generates complete JSON schemas out-of-the-box.
- *Tomorrow's Goal (Day 3)*: Construct the formal Finite State Machine (FSM) class representing the 5-tuple $M = (Q, \Sigma, \delta, q_0, F)$ and build directed graph adjacency representations.

---

*(Days 3 through 15 are documented in subsequent log entries.)*
