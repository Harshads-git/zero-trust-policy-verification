# B.Tech IT Final Viva Defense & Technical Q&A Guide

This guide prepares the student for questions commonly asked by external examiners, faculty reviewers, and security architects during project defense.

---

## Category 1: Theory of Computation & Formal Methods

### Q1: What is the formal definition of the Finite State Machine used in this project?
**Answer**:
The access control system is modeled as a Deterministic Finite Automaton (DFA) augmented with predicate guard conditions:
$$M = (Q, \Sigma, \delta, q_0, F)$$
- $Q$: Finite set of states representing discrete security postures (e.g., `START`, `AUTHENTICATED`, `IDENTITY_VERIFIED`, `DEVICE_VERIFIED`, `AUTHORIZED`, `ACCESS_GRANTED`, etc.).
- $\Sigma$: Alphabet of input actions/events (e.g., `submit_credentials`, `verify_mfa`, `check_device`).
- $\delta$: Transition function $\delta: Q \times \Sigma \times \mathcal{C} \to Q$ mapping current state and guarded input to the next state.
- $q_0$: Initial entry state (`START`).
- $F$: Designated terminal states (`ACCESS_GRANTED`, `ACCESS_DENIED`, `REVOKED`, `SESSION_EXPIRED`).

### Q2: Why use a Finite State Automaton rather than a standard if-else rule engine or regular expressions?
**Answer**:
If-else chains evaluate static, instantaneous conditions but cannot easily verify multi-step trajectory properties (e.g., "was device health verified *before* authorization across all possible execution paths?"). Regular expressions operate over linear strings, not state transition graphs. A Finite State Automaton enables formal graph reachability, cycle detection, dead-state analysis, and counterexample path extraction.

### Q3: How do you identify unreachable states, and why are they considered a flaw?
**Answer**:
We run Breadth-First Search (BFS) starting from $q_0$. Any state $q \in Q$ that is not visited in the BFS tree belongs to $Q \setminus \text{Reachable}(q_0)$. Unreachable states indicate dead policy logic, orphan security controls, or misconfigured rule conditions that can never be triggered in production.

### Q4: What is a "dead state" or "trap state" in your engine?
**Answer**:
A dead state is a reachable non-terminal state ($q \in \text{Reachable}(q_0) \setminus F$) from which NO terminal state in $F$ can ever be reached. We detect this by computing reverse reachability from all $f \in F$. If an access workflow enters such a state, the session hangs indefinitely without granting, denying, or revoking access.

### Q5: What is the computational time and space complexity of your verification algorithms?
**Answer**:
The core graph operations (BFS reachability, cycle detection, reverse reachability) operate in $\mathcal{O}(|V| + |E|)$ time, where $|V| = |Q|$ is the number of states and $|E| = |\delta|$ is the number of transitions. Space complexity is $\mathcal{O}(|V| + |E|)$ for the adjacency lists and visited sets. In our benchmarks, policies with up to 1,000 transitions verify in ~13 milliseconds.

### Q6: What is a "witness path" or "counterexample trace"?
**Answer**:
When an invariant fails (e.g., missing authentication), rather than returning a binary "invalid", the engine uses BFS shortest-path search to extract the exact sequence of states demonstrating the flaw (e.g., `START -> UNAUTHENTICATED -> ACCESS_GRANTED`). This provides explainability for security auditors.

---

## Category 2: Zero Trust Architecture & Cybersecurity

### Q7: What is Zero Trust Architecture, and which standard does this project follow?
**Answer**:
Zero Trust is a security paradigm based on the principle of "Never Trust, Always Verify". It assumes threats exist both outside and inside traditional network perimeters. This project adheres to **NIST SP 800-207**, which defines core tenets including per-session dynamic authorization, explicit device posture verification, and continuous session monitoring.

### Q8: What is the difference between Authentication and Authorization?
**Answer**:
- **Authentication (AuthN)**: Proves the identity of the subject (e.g., passwords, MFA, FIDO2 tokens).
- **Authorization (AuthZ)**: Evaluates whether the identified subject is permitted to perform a specific action on a specific resource (e.g., RBAC/ABAC role checks).
Our engine specifically flags policies that jump from `AUTHENTICATED` directly to `ACCESS_GRANTED` without passing through an `AUTHORIZED` state.

### Q9: Why is device verification required in Zero Trust?
**Answer**:
Valid user credentials can be stolen via phishing or session hijacking. NIST SP 800-207 Tenet 5 mandates that the enterprise must continuously verify the health, encryption state, and compliance posture of the requesting asset (`DEVICE_VERIFIED`) before granting access to enterprise resources.

### Q10: How does the engine detect perpetual "zombie" access sessions?
**Answer**:
The Session Revocability Invariant checks whether `ACCESS_GRANTED` can reach `SESSION_EXPIRED` or `REVOKED`. If forward reachability from `ACCESS_GRANTED` does not contain any termination state, the policy is flagged for allowing indefinite unrevocable sessions.

### Q11: What is a privilege bypass vulnerability in this context?
**Answer**:
A backdoor transition that allows a subject to transition directly from `START` or `UNAUTHENTICATED` into `ACCESS_GRANTED` or `AUTHORIZED`, completely skipping identity and device checks.

---

## Category 3: Cloud Computing & AWS Free Tier

### Q12: How is this project architected to remain 100% within the AWS Free Tier?
**Answer**:
- **Amazon DynamoDB**: Configured with 5 RCU / 5 WCU provisioned capacity (well within the perpetual 25 RCU / 25 WCU Free Tier allowance, costing $0.00/month).
- **Amazon S3**: Hosts the static web dashboard (within the 5 GB standard storage and 20,000 GET requests limit).
- **AWS Lambda / EC2 t2.micro**: Runs the FastAPI backend (within 1M requests/mo or 750 free instance hours/mo).
- **Amazon CloudWatch Logs**: 14-day retention for audit logs (within 5 GB free ingestion).

### Q13: How does the backend support both local development and AWS cloud deployment?
**Answer**:
We use the **Repository Pattern** (`backend/storage/base.py`). The storage backend is controlled by the `STORAGE_BACKEND` environment variable. In local development, it defaults to `sqlite` (using a local `policies.db` file). In AWS cloud deployment, setting `STORAGE_BACKEND=dynamodb` activates the Boto3 DynamoDB provider without altering any business logic.

### Q14: How does the system implement IAM Least Privilege?
**Answer**:
The backend IAM role is not granted broad administrator access. The attached IAM policy grants only four scoped DynamoDB permissions (`GetItem`, `PutItem`, `Scan`, `DeleteItem`) strictly restricted to the resource ARNs of the two project tables, plus CloudWatch log write permissions.

### Q15: Why is Infrastructure as Code (IaC) included, and what tools did you use?
**Answer**:
IaC ensures reproducible, version-controlled cloud infrastructure. We provided both **Terraform** (`infrastructure/terraform/`) and native **AWS CloudFormation** (`infrastructure/cloudformation/template.yaml`) to define the DynamoDB tables, S3 bucket, CloudWatch log groups, and IAM policies.

---

## Category 4: Software Engineering & Implementation

### Q16: Why did you choose FastAPI over Flask or Django?
**Answer**:
FastAPI provides native asynchronous I/O, automatic OpenAPI / Swagger documentation generation (`/docs`), and tight integration with Pydantic v2 for strict type checking and validation. Django is unnecessarily heavyweight for a verification microservice, and Flask requires third-party plugins for schema validation.

### Q17: Why did you build the frontend using vanilla JavaScript and Cytoscape.js instead of a heavy React framework?
**Answer**:
Using vanilla JavaScript and Cytoscape.js eliminated heavy `node_modules` build toolchains (Webpack, Vite), keeping the project lightweight and portable. The frontend can be served directly from FastAPI static files or an AWS S3 bucket with zero build steps. Cytoscape.js provides high-performance graph layout engines (breadth-first, DAG) with rich styling for violation highlighting.

### Q18: How did you test the verification engine?
**Answer**:
We implemented an automated test suite using **pytest** comprising 21 unit and integration tests across three test modules:
1. `test_fsm.py`: FSM state addition, transition mapping, BFS reachability, shortest witness path, and dead-state detection.
2. `test_verifier.py`: 100% pass verification on valid policies and accurate violation detection across all 7 flaw categories.
3. `test_api.py`: HTTP endpoint testing for `/health`, `/api/policies/verify`, `/api/policies/samples/templates`, and benchmarks.

### Q19: What were your experimental evaluation results?
**Answer**:
We ran empirical experiments on 10 ground-truth labeled policies and synthetic policies scaling up to 1,000 transitions:
- **Detection Accuracy**: 100.0%
- **Detection Rate (Recall)**: 100.0%
- **False Positive Rate**: 0.0%
- **Verification Latency**: 0.14 ms for $N = 10$, 0.81 ms for $N = 100$, and 13.2 ms for $N = 1,000$.

### Q20: What are the limitations of the current implementation and scope for future work?
**Answer**:
- *Limitations*: The engine operates on discrete propositional states and explicit string predicates; it does not solve arbitrary first-order arithmetic constraints like an SMT solver (e.g., Z3).
- *Future Work*: Integrating SMT constraint solving for complex numerical attribute predicates (e.g., time-window intervals, IP subnet range matching), and building a CI/CD GitHub Action plugin to block pull requests containing flawed access policies.
