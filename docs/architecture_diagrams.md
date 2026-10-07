# Zero Trust Policy Verification Engine (ZTPVE)
## Comprehensive System Architecture Diagrams

This document contains architectural diagrams in standard Mermaid and ASCII formats, illustrating system components, automaton state transitions, data persistence models, and invariant verification sequences.

---

## 1. End-to-End System Architecture

```mermaid
graph TD
    Client["User / Security Auditor / Web Client"]
    
    subgraph Edge & Ingestion Layer
        FastAPI["FastAPI REST Application (Port 8000)"]
        RateLimiter["Sliding-Window Rate Limiter (120 req/min)"]
        Sanitizer["Payload Sanitizer (Depth <= 8, Script Filter)"]
    end
    
    subgraph Core Verification Engine
        Engine["Zero Trust Verification Engine"]
        FSMBuilder["FSM Builder M = (Q, Sigma, delta, q0, F)"]
        GraphAlgos["Graph Algorithms (BFS / DFS / Cycle Detection)"]
        Invariants["NIST SP 800-207 Safety Invariants"]
        WitnessTracer["Shortest Witness Path Extractor"]
        Scorer["Risk & Compliance Scorer (0 - 100)"]
    end
    
    subgraph Storage & Cloud Telemetry
        RepoRouter{"Storage Repository Router"}
        SQLiteStore["SQLite Store (5 B-Tree Indexes)"]
        DynamoStore["Amazon DynamoDB (Single-Table Design)"]
        CloudWatch["CloudWatch Custom Metrics Publisher"]
        S3Archiver["S3 Policy Backup Archiver"]
    end
    
    subgraph Frontend User Interface
        WebUI["Cytoscape.js Interactive Dashboard"]
    end

    Client -->|HTTP POST / GET| FastAPI
    FastAPI --> RateLimiter
    RateLimiter --> Sanitizer
    Sanitizer --> Engine
    
    Engine --> FSMBuilder
    FSMBuilder --> GraphAlgos
    GraphAlgos --> Invariants
    Invariants --> WitnessTracer
    WitnessTracer --> Scorer
    
    Scorer --> RepoRouter
    RepoRouter -->|STORAGE_BACKEND=sqlite| SQLiteStore
    RepoRouter -->|STORAGE_BACKEND=dynamodb| DynamoStore
    
    Scorer --> CloudWatch
    Scorer --> S3Archiver
    Scorer -->|JSON Verification Report| WebUI
```

---

## 2. Finite State Automaton State-Transition Lifecycle

The diagram below contrasts a fully compliant Zero Trust authentication-authorization trajectory with prohibited backdoor trajectories:

```mermaid
stateDiagram-v2
    [*] --> START
    
    START --> UNAUTHENTICATED: Submit credentials
    UNAUTHENTICATED --> AUTHENTICATED: Password verified
    AUTHENTICATED --> MFA_CHALLENGE: Request MFA
    MFA_CHALLENGE --> IDENTITY_VERIFIED: TOTP / WebAuthn token valid
    
    IDENTITY_VERIFIED --> DEVICE_VERIFIED: Device posture & EDR valid
    DEVICE_VERIFIED --> AUTHORIZED: RBAC/ABAC policy evaluated
    AUTHORIZED --> ACCESS_GRANTED: Token issued
    
    ACCESS_GRANTED --> SESSION_EXPIRED: Inactivity timeout (e.g. 15 min)
    ACCESS_GRANTED --> REVOKED: Admin revocation / Risk trigger
    
    SESSION_EXPIRED --> [*]
    REVOKED --> [*]
    
    %% Deliberate Flaws / Backdoors Detected by Engine
    START --> ACCESS_GRANTED: Bypasses Auth & Device Trust (FLAW)
    UNAUTHENTICATED --> ACCESS_GRANTED: Missing MFA & AuthZ (FLAW)
    IDENTITY_VERIFIED --> ACCESS_GRANTED: Skipped Device Trust (FLAW)
    AUTHENTICATED --> ACCESS_GRANTED: Skipped Authorization (FLAW)
```

---

## 3. Dual-Backend Persistence Architecture

```mermaid
flowchart LR
    subgraph Application Layer
        App["FastAPI Route Handlers"]
        Repo["PolicyRepository (Base Interface)"]
    end

    subgraph SQLite Relational Store
        SQLiteDB[("policies.db")]
        T_Policies["policies Table"]
        T_Reports["verification_reports Table"]
        
        Idx1["idx_policies_created_at"]
        Idx2["idx_policies_name"]
        Idx3["idx_reports_policy_id"]
        Idx4["idx_reports_timestamp"]
        Idx5["idx_reports_valid"]
        
        SQLiteDB --- T_Policies
        SQLiteDB --- T_Reports
        T_Policies --- Idx1
        T_Policies --- Idx2
        T_Reports --- Idx3
        T_Reports --- Idx4
        T_Reports --- Idx5
    end

    subgraph Amazon DynamoDB Single-Table Store
        DynamoTable[("ZeroTrustPolicies Table")]
        
        subgraph Key Partitioning
            PK["PK = POLICY#<policy_id>"]
            SK_Meta["SK = METADATA"]
            SK_Rep["SK = REPORT#<timestamp>"]
        end
        
        subgraph Global Secondary Index GSI1
            GSI_PK["GSI1PK = TYPE#POLICY / TYPE#REPORT"]
            GSI_SK["GSI1SK = <created_at> / <timestamp>"]
        end
        
        DynamoTable --- PK
        PK --- SK_Meta
        PK --- SK_Rep
        DynamoTable --- GSI_PK
        GSI_PK --- GSI_SK
    end

    App --> Repo
    Repo -->|sqlite| SQLiteDB
    Repo -->|dynamodb| DynamoTable
```

---

## 4. Verification Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Security Admin / CI Pipeline
    participant API as FastAPI REST Gateway
    participant San as PolicySanitizer & RateLimiter
    participant Core as ZeroTrustVerificationEngine
    participant Store as PolicyRepository (SQLite / DynamoDB)
    participant Cloud as AWS Telemetry (CloudWatch / S3)

    Admin->>API: POST /api/policies/verify {policy JSON}
    API->>San: Inspect payload depth, length, script patterns
    San-->>API: Validated & Sanitized Policy
    API->>Core: verify(policy)
    
    activate Core
    Core->>Core: Build FSM M = (Q, Sigma, delta, q0, F)
    Core->>Core: Evaluate BFS Reachability & Dead States
    Core->>Core: Check Auth, Device, AuthZ, Revocability Invariants
    Core->>Core: Trace Shortest Counterexample Witness Path
    Core->>Core: Calculate Risk Score (0-100) & Remediation Plan
    Core-->>API: VerificationReport synthesized
    deactivate Core

    opt Cloud Telemetry Enabled
        API->>Cloud: Publish CloudWatch Metric (ViolationsCount, Latency)
        API->>Cloud: Archive policy JSON to Amazon S3
    end

    API->>Store: save_report(report)
    Store-->>API: Saved Confirmation
    API-->>Admin: HTTP 200 OK {VerificationReport JSON}
```

---

## 5. Security Guard Pipeline & Threat Mitigation

```
[ Incoming HTTP Request ]
           │
           ▼
┌────────────────────────────────────────────────────────┐
│ 1. Sliding-Window Rate Limiter (backend/security/)     │
│    - Checks Client IP in 60s sliding window            │
│    - Allows max 120 requests/minute                    │
│    - Emits X-RateLimit-Limit & X-RateLimit-Remaining   │
│    - Rejects burst flooding with HTTP 429              │
└──────────────────────────┬─────────────────────────────┘
                           │ Passed
                           ▼
┌────────────────────────────────────────────────────────┐
│ 2. Policy Input Sanitizer (backend/security/)          │
│    - Rejects JSON Nesting Depth > 8 (JSON Bombs)       │
│    - Filters <script>, javascript:, onerror= (XSS)     │
│    - Rejects Null Byte (\x00) Poisoning                │
│    - Enforces Rule Limit <= 5000                       │
│    - Rejects malformed payload with HTTP 400           │
└──────────────────────────┬─────────────────────────────┘
                           │ Sanitized
                           ▼
┌────────────────────────────────────────────────────────┐
│ 3. Zero Trust Verification Engine (backend/core/)      │
│    - Evaluates Automaton Invariants in O(|Q| + |delta|)│
│    - Computes Risk Score and Posture Category          │
└────────────────────────────────────────────────────────┘
```
