# System & Cloud Architecture Specification

## 1. Overall System Architecture

The Zero Trust Policy Verification Engine (ZTPVE) is designed around a decoupled, three-tier modular pattern:

```
+---------------------------------------------------------------------------------+
|                                 PRESENTATION TIER                               |
|                                                                                 |
|   HTML5 / CSS / Vanilla JavaScript SPA  +  Cytoscape.js Directed Graph Visualizer|
|   * Policy JSON Editor with Schema Validator & Template Dropdowns               |
|   * Live State Inspector (in-degree, out-degree, classification)                 |
|   * Counterexample Violation Visualizer & Downloadable Audit Reports            |
+----------------------------------------+----------------------------------------+
                                         | REST / JSON (HTTP)
+----------------------------------------v----------------------------------------+
|                                APPLICATION API TIER                             |
|                                                                                 |
|   FastAPI REST Microservice (Python 3.14)                                       |
|   * Audit & Timing Middleware (X-Process-Time Header)                            |
|   * Pydantic v2 Schema Enforcers (ZeroTrustPolicy, PolicyRule, VerificationReport)|
|   * Endpoints: /api/policies/verify, /api/policies, /health, /api/experiments   |
+-------------------+------------------------------------+------------------------+
                    |                                    |
+-------------------v-------------------+   +------------v------------------------+
|       THEORY OF COMPUTATION ENGINE    |   |           STORAGE LAYER             |
|                                       |   |                                     |
| * Automaton Model M = (Q, Sigma,      |   | Abstract PolicyRepository Interface |
|   delta, q0, F)                       |   | + SQLite Store (Local Dev)          |
| * BFS/DFS Reachability Analyzer       |   | + DynamoDB Store (AWS Free Tier)    |
| * Formal Zero Trust Invariant Rules   |   |                                     |
| * Counterexample Witness Pathfinder   |   |                                     |
+---------------------------------------+   +-------------------------------------+
```

---

## 2. AWS Free Tier Cloud Deployment Architecture

The system can be deployed entirely within the **AWS Perpetual Free Tier**:

```
+-----------------------------------------------------------------------------------+
|                                  AWS US-EAST-1                                    |
|                                                                                   |
|   [Client Browser]                                                                |
|          |                                                                        |
|          | HTTPS (Static Web Assets)                                              |
|          v                                                                        |
|   [Amazon S3 Bucket] (Free Tier: 5GB storage, Static Website Configuration)       |
|                                                                                   |
|          | REST API JSON Calls                                                    |
|          v                                                                        |
|   [AWS Lambda / API Gateway] OR [Amazon EC2 t2.micro]                            |
|   - Lambda Free Tier: 1,000,000 requests/month + 400,000 GB-seconds               |
|   - EC2 Free Tier: 750 hours/month of Linux t2.micro                              |
|          |                                                                        |
|          +------------+-----------------------------------+                       |
|          |            |                                   |                       |
|          v            v                                   v                       |
|   [Amazon DynamoDB]  [Amazon CloudWatch Logs]      [AWS IAM Least Privilege]      |
|   - Policies Table   - Log Group: /aws/ztpve/audit - Managed execution role       |
|   - Reports Table    - 14-day retention (5GB free) - Strict scoped actions        |
|   - 25 RCU / 25 WCU                                                               |
+-----------------------------------------------------------------------------------+
```

---

## 3. Storage Layer Abstraction

The repository pattern (`backend/storage/base.py`) enables zero-friction switching between environments:
- **Local Development**: Set `STORAGE_BACKEND=sqlite` in `.env`. Uses a local SQLite file (`policies.db`), requiring zero cloud setup.
- **AWS Free Tier Production**: Set `STORAGE_BACKEND=dynamodb` in `.env`. Communicates via `boto3` to DynamoDB tables `zero_trust_policies` and `zero_trust_audit_reports`.

---

## 4. Security Architecture

1. **Least Privilege IAM**: The backend execution role permits only four DynamoDB actions (`GetItem`, `PutItem`, `Scan`, `DeleteItem`) restricted strictly to the project's table ARNs.
2. **Credential Sanitization**: No AWS access keys or secrets are embedded in code. In AWS, IAM Roles (Instance Profile or Lambda Execution Role) provide temporary STS tokens automatically.
3. **Formal Verification Explainability**: Every detected violation includes:
   - Severity (`CRITICAL`, `HIGH`, `MEDIUM`)
   - Exact rule/state ID
   - Root-cause explanation
   - Minimal counterexample trace path (witness)
   - Concrete remediation recommendation
