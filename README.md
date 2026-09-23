# Zero Trust Policy Verification Engine (ZTPVE)

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Theory of Computation](https://img.shields.io/badge/Theory%20of%20Computation-FSM%20Formal%20Verification-6366f1.svg)](docs/formal_model.md)
[![AWS Free Tier](https://img.shields.io/badge/AWS-100%25%20Free%20Tier%20Compliant-FF9900.svg?logo=amazon-aws&logoColor=white)](infrastructure/)
[![Tests](https://img.shields.io/badge/pytest-21%20passed%20(100%25)-success.svg)](backend/tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An academic and practical **Zero Trust Policy Verification Engine** that bridges **Theory of Computation (Automata & Formal Methods)**, **Cybersecurity (NIST SP 800-207 Zero Trust Architecture)**, and **Cloud Computing (AWS Free Tier)**. 

The engine models access-control policies as Deterministic Finite Automata (DFAs) augmented with transition guard predicates, formally verifying safety invariants, detecting unreachable/dead-end states, exposing authorization bypasses, and producing human-explainable counterexample witness traces.

---

## Table of Contents
- [1. Core Problem & Academic Motivation](#1-core-problem--academic-motivation)
- [2. Theory of Computation Formal Model](#2-theory-of-computation-formal-model)
- [3. Architecture Overview](#3-architecture-overview)
- [4. Project Structure](#4-project-structure)
- [5. Quick Start (Local Setup)](#5-quick-start-local-setup)
- [6. Running Automated Tests](#6-running-automated-tests)
- [7. Empirical Evaluation & Benchmarks](#7-empirical-evaluation--benchmarks)
- [8. AWS Free Tier Cloud Deployment](#8-aws-free-tier-cloud-deployment)
- [9. Flaw Detection Showcase](#9-flaw-detection-showcase)
- [10. 15-Day Development Plan & Git Commit Log](#10-15-day-development-plan--git-commit-log)
- [11. Viva Defense Preparation](#11-viva-defense-preparation)
- [12. License](#12-license)

---

## 1. Core Problem & Academic Motivation

Traditional perimeter-based access control models rely on implicit trust once a user enters a corporate network. In contrast, **Zero Trust Architecture (NIST SP 800-207)** asserts: **"Never Trust, Always Verify"**.

However, complex enterprise policies frequently suffer from:
- **Authentication Bypasses**: Paths reaching `ACCESS_GRANTED` without verifying user credentials.
- **Missing Device Health Checks**: Granting access without verifying endpoint compliance.
- **Privilege Escalation**: Moving from unverified states directly to high-privilege authorization.
- **Orphan/Unreachable States**: Policy rules that can never be reached during legitimate access attempts.
- **Dead-End (Trap) States**: Workflows that trap a user session without granting, denying, or revoking access.
- **Perpetual Zombie Sessions**: Access grants lacking timeout or revocation paths.
- **Rule Conflicts & Non-Determinism**: Ambiguous rules leading to divergent outcomes from the same trigger.

ZTPVE eliminates these flaws **pre-deployment** through formal verification algorithms running with linear time complexity $\mathcal{O}(|V| + |E|)$.

---

## 2. Theory of Computation Formal Model

An access-control security policy is formalized as a Deterministic Finite Automaton (DFA) augmented with predicate guard conditions:

$$M = (Q, \Sigma, \delta, q_0, F)$$

```
  +---------+   connect   +-----------------+   valid creds   +---------------+
  |  START  | ----------> | UNAUTHENTICATED | --------------> | AUTHENTICATED |
  +---------+             +-----------------+                 +---------------+
                                   |                                  |
                           invalid | credentials                      | mfa_verify
                                   v                                  v
                          +-----------------+               +-------------------+
                          |  ACCESS_DENIED  |               | IDENTITY_VERIFIED |
                          +-----------------+               +-------------------+
                                                                      |
                                                          device_posture | check
                                                                      v
  +-----------------+    grant      +------------+   evaluate role  +-----------------+
  |  ACCESS_GRANTED | <------------ | AUTHORIZED | <--------------- | DEVICE_VERIFIED |
  +-----------------+               +------------+                  +-----------------+
        |     |
ttl_exp |     | anomaly_detected
        v     v
  +-----------------+
  | SESSION_EXPIRED | / REVOKED
  +-----------------+
```

### Formal Invariants Verified
1. **Authentication Precedence Invariant**:
   $$\forall \text{ path } P = (q_0, \dots, q_k = \text{ACCESS\_GRANTED}) : \exists i < k \text{ s.t. } q_i \in \{\text{AUTHENTICATED}, \text{IDENTITY\_VERIFIED}\}$$
2. **Device Trust Invariant**:
   $$\forall \text{ path } P \text{ to } \text{ACCESS\_GRANTED} : \exists j < k \text{ s.t. } q_j = \text{DEVICE\_VERIFIED} \lor C_{j-1, j} \models \text{DeviceCheck}$$
3. **Authorization Check Invariant**: Access grant transitions must originate from `AUTHORIZED` or evaluate explicit permission predicates.
4. **Session Revocability Invariant**:
   $$\text{Reachable}(\text{ACCESS\_GRANTED}) \cap \{\text{SESSION\_EXPIRED}, \text{REVOKED}\} \neq \emptyset$$
5. **Absence of Dead/Trap States**:
   $$\forall q \in Q \setminus F, \quad \exists f \in F \text{ s.t. } \text{Reachable}(q, f)$$
6. **Reachability of Defined States**:
   $$\forall q \in Q, \quad q \in \text{Reachable}(q_0)$$
7. **Transition Determinism**:
   $$\forall q \in Q, \forall \sigma \in \Sigma, \quad |\delta(q, \sigma, C)| \le 1$$

Full mathematical details and formal proofs: [docs/formal_model.md](docs/formal_model.md).

---

## 3. Architecture Overview

```
+-----------------------------------------------------------------------------------+
|                                  WEB FRONTEND                                     |
|  - Cytoscape.js Directed Automaton Visualizer with real-time violation highlights |
|  - Policy JSON Editor with syntax checker, template loader & report export        |
|  - Verification History & Live State Degree Inspector                             |
+-----------------------------------------+-----------------------------------------+
                                          | REST API (JSON / HTTP)
+-----------------------------------------v-----------------------------------------+
|                               FASTAPI BACKEND                                     |
|                                                                                   |
|  +--------------------+   +-----------------------+   +------------------------+  |
|  |   API Endpoints    |   |  Storage Abstraction  |   |   Audit & Telemetry    |  |
|  | (/verify, /reports)|   |  (SQLite / DynamoDB)  |   |    (CloudWatch Logs)   |  |
|  +---------+----------+   +-----------+-----------+   +-----------+------------+  |
|            |                          |                           |               |
|  +---------v--------------------------v---------------------------v------------+  |
|  |             FORMAL VERIFICATION & FSM ENGINE (TOC Core)                     |  |
|  |  * Automaton 5-tuple M = (Q, Sigma, delta, q0, F)                           |  |
|  |  * BFS/DFS Reachability, Cycle Detection & Dead State Analysis              |  |
|  |  * Zero Trust Invariant Rules & Minimal Witness Counterexample Traces       |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 4. Project Structure

```
zero-trust-policy-verification/
│
├── backend/
│   ├── api/                      # FastAPI endpoint routers (policies, experiments)
│   ├── core/                     # Theory of Computation core
│   │   ├── fsm.py                # Automaton 5-tuple M = (Q, Sigma, delta, q0, F)
│   │   ├── graph_algorithms.py   # BFS reachability, shortest witness path, dead states
│   │   ├── verifier.py           # Verification orchestrator
│   │   └── rules/                # Formal invariant rules (Auth, Device, Trap, Conflict)
│   ├── models/                   # Pydantic schemas (Policy, Rule, Report, Violation)
│   ├── storage/                  # Pluggable repository (SQLite local / DynamoDB AWS)
│   ├── tests/                    # 21 automated pytest unit and integration tests
│   └── main.py                   # FastAPI application entrypoint
│
├── frontend/
│   ├── index.html                # Responsive web dashboard
│   ├── css/style.css             # Professional engineering theme
│   └── js/
│       ├── app.js                # Frontend controller & API integration
│       └── visualizer.js         # Cytoscape.js directed graph renderer
│
├── policies/
│   ├── valid/                    # Compliant NIST SP 800-207 Zero Trust policies
│   └── invalid/                  # Flawed policies showcasing 7 distinct flaw types
│
├── experiments/
│   ├── run_experiments.py        # Empirical evaluation runner script
│   ├── benchmark_report.md       # Empirical accuracy & scalability analysis
│   └── results/                  # Generated CSV & JSON benchmark runs
│
├── infrastructure/
│   ├── terraform/                # AWS Free Tier Terraform configuration
│   ├── cloudformation/           # AWS Free Tier CloudFormation template
│   └── deploy_aws.sh             # AWS deployment automation script
│
├── docs/
│   ├── architecture.md           # System & Cloud Architecture specification
│   ├── formal_model.md           # Theory of Computation formal proofs & invariants
│   ├── research_paper_draft.md   # Academic literature review & research hypothesis
│   └── viva_defense_guide.md     # 25+ B.Tech Viva Q&As for final examination
│
├── scripts/
│   ├── run_local.bat             # One-click Windows runner
│   ├── run_local.sh              # One-click Linux/macOS runner
│   └── seed_policies.py          # Database seeder utility
│
├── requirements.txt              # Python package dependencies
├── .env.example                  # Environment variable configuration template
├── LICENSE                       # MIT License
└── README.md
```

---

## 5. Quick Start (Local Setup)

### Prerequisites
- Python 3.10+ (Tested up to Python 3.14)
- Modern web browser (Chrome, Firefox, Edge)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Seed Database & Start Server
**Windows**:
```cmd
scripts\run_local.bat
```

**Linux / macOS**:
```bash
chmod +x scripts/run_local.sh
./scripts/run_local.sh
```

**Manual Startup**:
```bash
python scripts/seed_policies.py
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### 3. Access Dashboard
- **Web Interface**: [http://localhost:8000](http://localhost:8000)
- **Interactive OpenAPI Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 6. Running Automated Tests

Run the comprehensive pytest suite covering automata operations, invariant rules, and HTTP routes:

```bash
python -m pytest backend/tests -v
```

### Test Results Summary:
```text
backend/tests/test_api.py::test_health_endpoint PASSED                   [  4%]
backend/tests/test_api.py::test_frontend_root_served PASSED              [  9%]
backend/tests/test_api.py::test_get_sample_templates PASSED              [ 14%]
backend/tests/test_api.py::test_verify_endpoint_direct PASSED            [ 19%]
backend/tests/test_api.py::test_experiments_benchmark_endpoint PASSED    [ 23%]
backend/tests/test_fsm.py::test_fsm_initialization PASSED                [ 28%]
backend/tests/test_fsm.py::test_fsm_add_transitions PASSED               [ 33%]
backend/tests/test_fsm.py::test_reachability_bfs PASSED                  [ 38%]
backend/tests/test_fsm.py::test_shortest_witness_path PASSED             [ 42%]
backend/tests/test_fsm.py::test_dead_state_detection PASSED              [ 47%]
backend/tests/test_fsm.py::test_rule_conflict_detection PASSED           [ 52%]
backend/tests/test_verifier.py::test_valid_employee_policy_passes PASSED [ 57%]
backend/tests/test_verifier.py::test_valid_admin_policy_passes PASSED    [ 61%]
backend/tests/test_verifier.py::test_valid_contractor_policy_passes PASSED [ 66%]
backend/tests/test_verifier.py::test_missing_authentication_detected PASSED [ 71%]
backend/tests/test_verifier.py::test_missing_device_verification_detected PASSED [ 76%]
backend/tests/test_verifier.py::test_unreachable_state_detected PASSED   [ 80%]
backend/tests/test_verifier.py::test_dead_state_detected PASSED          [ 85%]
backend/tests/test_verifier.py::test_conflicting_rules_detected PASSED   [ 90%]
backend/tests/test_verifier.py::test_no_revocation_path_detected PASSED  [ 95%]
backend/tests/test_verifier.py::test_critical_privilege_bypass_detected PASSED [100%]

======================== 21 passed in 0.34s ========================
```

---

## 7. Empirical Evaluation & Benchmarks

Run the empirical benchmark to measure classification metrics and algorithmic scalability across synthetic workflows:

```bash
python experiments/run_experiments.py
```

### Empirical Results (Measured on Execution Machine)
- **Classification Accuracy**: `100.0%`
- **Detection Rate (Recall)**: `100.0%` (All 7 flaw types detected)
- **False Positive Rate**: `0.0%` (Compliant policies generate 0 false alarms)
- **F1 Score**: `1.000`

### Scalability vs Policy Dimension
| Policy Scale $N$ | States $|Q|$ | Transitions $|\delta|$ | Verification Latency (ms) | Throughput (trans/sec) |
| :---: | :---: | :---: | :---: | :---: |
| **$N = 10$** | 11 | 12 | **0.144 ms** | 83,171 trans/sec |
| **$N = 50$** | 24 | 51 | **0.408 ms** | 125,049 trans/sec |
| **$N = 100$** | 41 | 101 | **0.811 ms** | 124,537 trans/sec |
| **$N = 500$** | 174 | 501 | **3.792 ms** | 132,109 trans/sec |
| **$N = 1000$** | 341 | 1,001 | **13.260 ms** | 75,492 trans/sec |

For complete analysis and LaTeX formulas, see [experiments/benchmark_report.md](experiments/benchmark_report.md).

---

## 8. AWS Free Tier Cloud Deployment

The architecture is designed to cost **$0.00 / month** using AWS Free Tier services:

| AWS Component | Configuration | Free Tier Allowance | Cost Impact |
| :--- | :--- | :--- | :--- |
| **Amazon DynamoDB** | Provisioned 5 RCU / 5 WCU | 25 RCU / 25 WCU + 25 GB storage | **$0.00 / mo** |
| **Amazon S3** | Static Website Hosting | 5 GB storage + 20,000 GETs | **$0.00 / mo** |
| **AWS Lambda / EC2** | Python 3.14 Container / t2.micro | 1M requests/mo (Lambda) or 750 hrs/mo (EC2) | **$0.00 / mo** |
| **Amazon CloudWatch** | Audit Logs (14-day retention) | 5 GB log data ingestion | **$0.00 / mo** |

### Deploy via Terraform
```bash
cd infrastructure/terraform
terraform init
terraform plan
terraform apply
```

### Deploy via AWS CloudFormation
```bash
aws cloudformation deploy \
  --template-file infrastructure/cloudformation/template.yaml \
  --stack-name ztpve-free-tier-stack \
  --capabilities CAPABILITY_NAMED_IAM
```

Once deployed, set `STORAGE_BACKEND=dynamodb` in `.env` to enable cloud persistence.

---

## 9. Flaw Detection Showcase

The engine explains **WHY** a policy fails rather than simply returning `invalid`:

| Vulnerability Type | Severity | Counterexample Witness Path | Explainable Remediation |
| :--- | :---: | :--- | :--- |
| `MISSING_AUTHENTICATION` | **CRITICAL** | `START -> UNAUTHENTICATED -> ACCESS_GRANTED` | Insert an `AUTHENTICATED` / `IDENTITY_VERIFIED` check before granting access. |
| `MISSING_DEVICE_VERIFICATION` | **HIGH** | `IDENTITY_VERIFIED -> AUTHORIZED -> ACCESS_GRANTED` | Enforce endpoint health checks (`DEVICE_VERIFIED`) prior to issuing tokens. |
| `DEAD_STATE` | **HIGH** | `AUTHENTICATED -> PENDING_MANUAL_REVIEW (Trap)` | Add resolution transitions leading to `ACCESS_DENIED` or `REVOKED`. |
| `UNREACHABLE_STATE` | **MEDIUM** | `[START] ... (No path to ELEVATED_AUDIT_LOG)` | Connect inbound transitions or prune orphan state from policy. |
| `RULE_CONFLICT` | **HIGH** | `DEVICE_VERIFIED -(tier_std)-> {AUTHORIZED, ACCESS_DENIED}` | Disambiguate overlapping rules with mutually exclusive conditions. |
| `NO_REVOCATION_PATH` | **HIGH** | `ACCESS_GRANTED -> (No exit path)` | Add timeout (`SESSION_EXPIRED`) and revocation (`REVOKED`) edges. |

---

## 10. 15-Day Development Plan & Git Commit Log

The system was developed following a disciplined 15-day incremental timeline:

- **Day 1**: Repository initialization, architecture specifications, initial FastAPI skeleton.
- **Day 2**: Policy data model schemas, Pydantic v2 validation models, initial model tests.
- **Day 3**: FSM core construction, formal 5-tuple $M = (Q, \Sigma, \delta, q_0, F)$ implementation.
- **Day 4**: Graph reachability, cycle detection, unreachable states, and dead state analysis.
- **Day 5**: Zero Trust safety invariants (identity, device posture, least privilege, session revocability).
- **Day 6**: Structured verification report synthesis, severity calculation, counterexample pathfinder.
- **Day 7**: FastAPI REST endpoints (`/verify`, `/policies`, `/reports`, `/health`).
- **Day 8**: Web dashboard UI, responsive layout, metrics ribbon, JSON policy editor.
- **Day 9**: Cytoscape.js directed automaton visualization and violation highlighting.
- **Day 10**: AWS Free Tier infrastructure (Terraform and CloudFormation templates).
- **Day 11**: Pluggable storage abstraction (SQLite local + DynamoDB AWS Free Tier adapter).
- **Day 12**: Security hardening, least-privilege IAM policies, timing & audit middleware.
- **Day 13**: Synthetic policy generator, automated test suite (21 passing tests), empirical benchmark runner.
- **Day 14**: Theory of Computation formal proofs, literature review draft, viva defense guide.
- **Day 15**: End-to-end integration, database seeding utility, one-click runners, project finalization.

---

## 11. Viva Defense Preparation

A dedicated 25+ question defense guide is provided in [docs/viva_defense_guide.md](docs/viva_defense_guide.md), addressing:
- Theory of Computation (DFAs, reachability, formal invariants, algorithmic complexity).
- Zero Trust Architecture (NIST SP 800-207, continuous verification, AuthN vs AuthZ).
- Cloud Infrastructure (DynamoDB capacity calculation, IAM least privilege, CloudWatch).
- Verification Engine Mechanics (witness paths, counterexamples, performance benchmarks).

---

## 12. License

This project is open-source under the [MIT License](LICENSE).
