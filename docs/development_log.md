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
- `545b8a6` - `test: add unit test suite for policy model and schema validation`

#### 4. Reflections & Next Steps for Day 3
- *Reflection*: Pydantic v2 is noticeably faster than v1 and generates complete JSON schemas out-of-the-box.
- *Tomorrow's Goal (Day 3)*: Construct the formal Finite State Machine (FSM) class representing the 5-tuple $M = (Q, \Sigma, \delta, q_0, F)$ and build directed graph adjacency representations.

---

### DAY 3: Finite State Machine (FSM) Core Construction
**Date**: September 11, 2026  
**Objective**: Build the Theory of Computation Automaton class $M = (Q, \Sigma, \delta, q_0, F)$, establish forward and reverse adjacency representations, and test transition handling.

#### 1. Tasks Executed
- [x] Implemented `Transition` named tuple in `backend/core/fsm.py` with `rule_id`, `source`, `target`, `action`, `condition`, and `description`.
- [x] Implemented `FiniteStateMachine` class capturing the formal 5-tuple:
  - $Q$: States set (initialized with $q_0 \cup F$).
  - $\Sigma$: Operational action alphabet.
  - $\delta$: Dual adjacency mappings: forward `_adj: Dict[str, List[Transition]]` and reverse `_rev_adj: Dict[str, List[Transition]]`.
  - $q_0$: Initial start state (`START`).
  - $F$: Designated terminal set (`ACCESS_GRANTED`, `ACCESS_DENIED`, `REVOKED`, `SESSION_EXPIRED`).
- [x] Implemented factory constructor `FiniteStateMachine.from_policy(policy)`.
- [x] Added neighbor lookup and degree inspection helpers (`get_outgoing()`, `get_incoming()`, `get_neighbors()`).
- [x] Built `to_cytoscape_elements()` to export Cytoscape.js compatible graph structures with class tagging for start, terminal, and access states.
- [x] Wrote automated unit tests in `backend/tests/test_fsm.py` validating initialization, transition addition, and degree properties.

#### 2. Key Architectural Decisions (Student Design Notes)
- **Decision 1: Dual Forward & Reverse Adjacency Representation**  
  *Rationale*: Forward traversal (`_adj`) is needed for standard BFS reachability from $q_0$, while reverse traversal (`_rev_adj`) is crucial for dead-end / sink-state detection (finding whether terminal states $F$ can be reached backwards from every non-terminal state in $Q \setminus F$). Storing both yields $\mathcal{O}(1)$ edge lookup in both directions.
- **Decision 2: Immutable NamedTuple for Transitions**  
  *Rationale*: In automata theory, transitions are mathematical relations. Making `Transition` a `NamedTuple` ensures hashability, immutability, and zero performance overhead compared to heavy ORM models.
- **Decision 3: Separation of Graph Representation from Verification Rules**  
  *Rationale*: By decoupling the mathematical FSM data structure from security verification rules, new Theory of Computation algorithms (cycle detection, equivalence testing, minimization) can be added independently without altering the core model.

#### 3. Git Commits for Day 3
- `2e42335` - `feat: implement formal Finite State Machine core and transition function`
- `f34b65e` - `test: add unit tests for FSM construction, reachability, and trap detection`

#### 4. Reflections & Next Steps for Day 4
- *Reflection*: The dual-adjacency approach makes reverse reachability run in linear time without rebuilding the graph.
- *Tomorrow's Goal (Day 4)*: Implement formal graph traversal algorithms in `backend/core/graph_algorithms.py` (BFS reachability, cycle detection, unreachable state detection, and dead-end state identification).

---

### DAY 4: Formal Verification & Graph Traversal Algorithms
**Date**: September 12, 2026  
**Objective**: Implement Theory of Computation algorithms for reachability analysis, dead-end trap detection, cycle-free pathfinding, and minimal counterexample witness extraction.

#### 1. Tasks Executed
- [x] Implemented `compute_reachable_states(fsm, start_state)` using Breadth-First Search (BFS) with strict $\mathcal{O}(|V| + |E|)$ time complexity.
- [x] Implemented `compute_unreachable_states(fsm)` to detect orphan security logic: $Q \setminus \text{Reachable}(q_0)$.
- [x] Implemented `find_shortest_path(fsm, source, target)` using BFS queue for minimal counterexample extraction (witness traces).
- [x] Implemented `find_all_simple_paths(fsm, source, target, max_depth)` using Depth-First Search (DFS) with visited sets to avoid infinite cycles.
- [x] Implemented `detect_dead_states(fsm)` using reverse BFS from the terminal set $F$ to locate non-terminal states that trap requests in unresolved limbo.
- [x] Implemented `detect_conflicts_and_nondeterminism(fsm)` detecting race conditions where the identical action and condition diverge to different states.
- [x] Added unit tests covering all traversal methods in `backend/tests/test_fsm.py`.

#### 2. Key Architectural Decisions (Student Design Notes)
- **Decision 1: Breadth-First Search for Minimal Witness Traces**  
  *Rationale*: In formal verification and security auditing, returning the shortest counterexample path (e.g., `START -> UNAUTHENTICATED -> ACCESS_GRANTED`) is far easier for a human administrator to understand and remediate than a long cyclic DFS trace. BFS naturally guarantees finding the shortest witness trajectory.
- **Decision 2: Reverse Multi-Source BFS for Dead-End Detection**  
  *Rationale*: Instead of running a separate search from every individual state to see if it can reach $F$ (which would take $\mathcal{O}(|V| \cdot (|V| + |E|))$), we initialize a single reverse BFS queue seeded with all terminal states $F$ simultaneously. This calculates terminal reachability in a single $\mathcal{O}(|V| + |E|)$ sweep!
- **Decision 3: Cycle-Free Depth-Limited DFS for Path Enumeration**  
  *Rationale*: Finite state machines in access control can contain legitimate retry loops (e.g., `SESSION_EXPIRED -> UNAUTHENTICATED`). Path exploration must prune cycles to prevent stack overflows while rigorously inspecting all distinct execution trajectories up to a bounded depth.

#### 3. Git Commits for Day 4
- `c022bc9` - `feat: add BFS reachability, cycle detection, and dead-state graph algorithms`
- `f34b65e` - `test: add unit tests for FSM construction, reachability, and trap detection`

#### 4. Reflections & Next Steps for Day 5
- *Reflection*: Reverse multi-source BFS reduced dead-state detection latency to a fraction of a millisecond.
- *Tomorrow's Goal (Day 5)*: Formally encode the Zero Trust domain invariants (Authentication Precedence, Device Trust, Least Privilege, Session Revocability) in `backend/core/rules/` on top of these graph algorithms.

---

### DAY 5: Zero Trust Safety Invariant Rules
**Date**: September 13, 2026  
**Objective**: Formally encode core NIST SP 800-207 Zero Trust domain safety invariants (Authentication Precedence, Device Posture Trust, Least Privilege Authorization, and Session Revocability) as modular verification checks with explainable remediation output.

#### 1. Tasks Executed
- [x] Implemented `AuthenticationInvariantRule`:
  - Enforces that EVERY trajectory leading into `ACCESS_GRANTED` must traverse identity authentication states (`AUTHENTICATED`, `IDENTITY_VERIFIED`, `MFA_VERIFIED`).
  - Severity: `CRITICAL`.
  - Automatically attaches minimal counterexample witness path on violation.
- [x] Implemented `DeviceTrustInvariantRule`:
  - Enforces NIST SP 800-207 Tenet 5 (asset posture verification) by checking for `DEVICE_VERIFIED` states or device health guard conditions.
  - Severity: `HIGH`.
- [x] Implemented `AuthorizationCheckRule`:
  - Blocks privilege bypasses (direct jumps from `START`/`UNAUTHENTICATED` to `ACCESS_GRANTED`).
  - Blocks authentication-to-grant transitions that omit explicit resource permission evaluation.
  - Severity: `CRITICAL` / `HIGH`.
- [x] Implemented `SessionRevocationInvariantRule`:
  - Prevents perpetual zombie grants by asserting that `ACCESS_GRANTED` has valid exit paths to `SESSION_EXPIRED` or `REVOKED`.
  - Severity: `HIGH`.
- [x] Created dedicated isolated unit tests in `backend/tests/test_zt_invariants.py` (9 tests covering each invariant in isolation).
- [x] Verified full test suite passing (35 tests in 0.49s).

#### 2. Key Architectural Decisions (Student Design Notes)
- **Decision 1: Universal Path Quantification ($\forall$ Trajectories)**  
  *Rationale*: In access control, checking if *one* path authenticates the user is insufficient. An attacker will exploit the least secure path. Therefore, safety invariants enforce universal quantification: $\forall \text{ path } P = (q_0, \dots, \text{ACCESS\_GRANTED})$, authentication and device posture must hold.
- **Decision 2: Severity Categorization Aligned with CVSS / NIST**  
  *Rationale*: Violations that permit unauthenticated external access are tagged `CRITICAL`, while missing device compliance or lack of session termination are tagged `HIGH`. This allows administrators to prioritize immediate mitigations.
- **Decision 3: Actionable Remediation Guidance**  
  *Rationale*: A formal verification tool is only useful if it explains how to fix the flaw. Every violation object provides a concrete, natural-language `remediation` field explaining exactly which state or transition to add or prune.

#### 3. Git Commits for Day 5
- `3c9b199` - `feat: refine Zero Trust safety invariant rules for identity, device posture, and authorization`
- `dcffb02` - `test: add isolated unit tests for individual Zero Trust safety invariants`
- `docs: add Day 5 Zero Trust invariant rules engineering log and security analysis`

#### 4. Reflections & Next Steps for Day 6
- *Reflection*: Universal path checking with depth-limited DFS proved remarkably fast (< 0.5 ms per policy).
- *Tomorrow's Goal (Day 6)*: Build the comprehensive verification orchestrator (`backend/core/verifier.py`), structured report synthesis (`backend/models/report.py`), and counterexample pathfinder.

---

### DAY 6: Verification Report Synthesis, Risk Scoring & Remediation Modeling
**Date**: September 14, 2026  
**Objective**: Build structured verification reporting models (`backend/models/report.py`), calculate quantitative risk scores (0–100), classify security postures, and generate step-by-step remediation plans.

#### 1. Tasks Executed
- [x] Defined `PolicyViolation` model encapsulating:
  - Violation type (`MISSING_AUTHENTICATION`, `MISSING_DEVICE_VERIFICATION`, `DEAD_STATE`, etc.).
  - Severity enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
  - Target states/rules, natural language message, root-cause explanation.
  - Counterexample witness path demonstrating the exploit trajectory.
  - Actionable remediation suggestion.
- [x] Implemented `VerificationReport` data model capturing:
  - Policy metadata, verification outcome (`valid: bool`), FSM state/transition dimensions.
  - Dynamic severity breakdown dictionary.
  - Quantitative risk score calculation (`calculate_risk_score()`).
  - Categorical security posture determination (`determine_posture()`): `COMPLIANT`, `LOW_RISK`, `ELEVATED_RISK`, `CRITICAL_RISK`.
  - Structured remediation plan synthesizer (`get_remediation_plan()`).
- [x] Updated `ZeroTrustVerificationEngine` in `backend/core/verifier.py` to populate risk score and security posture on every audit report.
- [x] Implemented unit test suite in `backend/tests/test_verification_report.py` (tested compliant metrics, risk score calculation, remediation plan extraction, and JSON serialization roundtrip).
- [x] Verified complete test suite passing (39 tests in 0.52s).

#### 2. Key Architectural Decisions (Student Design Notes)
- **Decision 1: Quantitative Risk Scoring (0–100 Scale)**  
  *Rationale*: While formal verification returns a binary truth value (valid or invalid), security executives and compliance auditors need a quantitative risk metric. We implemented a weighted scoring formula:
  $$\text{Score} = \min\left(100, \sum_{v \in \mathcal{V}} w(\text{severity}_v)\right)$$
  where $w(\text{CRITICAL}) = 40$, $w(\text{HIGH}) = 20$, $w(\text{MEDIUM}) = 10$, $w(\text{LOW}) = 5$.
- **Decision 2: Structured Remediation Step Generation**  
  *Rationale*: Raw violation lists can overwhelm developers. The `get_remediation_plan()` method automatically sequences remediation steps with targeted rule IDs and actions so that DevOps teams can apply fixes systematically.
- **Decision 3: Lossless JSON Serialization**  
  *Rationale*: Storing verification reports across SQLite or AWS DynamoDB requires reliable Pydantic v2 serialization. Roundtrip testing guarantees that witness paths, graph elements, and severity dictionaries survive database storage without schema degradation.

#### 3. Git Commits for Day 6
- `51ed18a` - `feat: implement weighted risk scoring, security posture categorization, and remediation planner in verification report`
- `75cfaf6` - `test: add unit tests for verification report synthesis, risk scoring, and remediation plan`
- `docs: add Day 6 verification report engineering log, risk scoring, and remediation analysis`

#### 4. Reflections & Next Steps for Day 7
- *Reflection*: The quantitative risk score maps intuitively to the red/yellow/green indicators on the UI.
- *Tomorrow's Goal (Day 7)*: Implement the FastAPI REST API layer (`backend/api/`) with endpoints for direct policy verification (`/api/policies/verify`), CRUD persistence, and audit report retrieval.

---

*(Days 7 through 15 are documented in subsequent log entries.)*

