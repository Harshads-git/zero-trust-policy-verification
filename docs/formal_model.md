# Theory of Computation: Formal Automata Model & Verification Invariants

## 1. Abstract Automaton Definition

In this engine, an access-control security policy is formalized as a Deterministic Finite Automaton (DFA) augmented with transition guard predicates:

$$M = (Q, \Sigma, \delta, q_0, F)$$

Where:
1. **$Q$ (State Space)**: A finite, non-empty set of discrete security postures:
   $$Q = \{\text{START}, \text{UNAUTHENTICATED}, \text{AUTHENTICATED}, \text{IDENTITY\_VERIFIED}, \text{DEVICE\_VERIFIED}, \text{AUTHORIZED}, \text{ACCESS\_GRANTED}, \text{ACCESS\_DENIED}, \text{SESSION\_EXPIRED}, \text{REVOKED}\}$$
2. **$\Sigma$ (Input Alphabet)**: A finite alphabet of subject actions, authentication challenges, and contextual security triggers:
   $$\Sigma = \{\text{connect}, \text{submit\_credentials}, \text{verify\_mfa}, \text{inspect\_device}, \text{evaluate\_permissions}, \text{issue\_token}, \text{session\_timeout}, \text{revoke\_session}, \text{anomaly\_flag}\}$$
3. **$\delta$ (Transition Function)**: A state transition function mapping a state and an input event under an optional guard condition $C$ to a successor state:
   $$\delta : Q \times \Sigma \times \mathcal{C} \to Q$$
4. **$q_0 \in Q$ (Initial State)**: The initial entry state of any incoming connection request:
   $$q_0 = \text{START}$$
5. **$F \subseteq Q$ (Terminal / Sink States)**: The subset of designated terminal states where an access transaction concludes:
   $$F = \{\text{ACCESS\_GRANTED}, \text{ACCESS\_DENIED}, \text{REVOKED}, \text{SESSION\_EXPIRED}\}$$

---

## 2. Formal Zero Trust Safety Invariants

### Invariant 1: Authentication Precedence Invariant
**Principle**: *Never Trust, Always Verify Identity.*  
No trajectory in the automaton may enter the privileged `ACCESS_GRANTED` state without having successfully traversed an identity authentication state.

$$\forall \text{ path } P = (q_0, q_1, \dots, q_k) \text{ where } q_k = \text{ACCESS\_GRANTED}:$$
$$\exists i \in \{1, \dots, k-1\} \text{ such that } q_i \in \{\text{AUTHENTICATED}, \text{IDENTITY\_VERIFIED}\}$$

*Violation Category*: `MISSING_AUTHENTICATION` (Severity: `CRITICAL`).

---

### Invariant 2: Explicit Device Trust Invariant
**Principle**: *Continuous Endpoint Compliance (NIST SP 800-207).*  
Access to corporate workloads must not be granted solely on user credentials; the client hardware/device posture must be validated.

$$\forall \text{ path } P = (q_0, \dots, q_k = \text{ACCESS\_GRANTED}):$$
$$\exists j \in \{1, \dots, k-1\} \text{ s.t. } q_j = \text{DEVICE\_VERIFIED} \quad \lor \quad \text{Condition}(q_{j-1}, q_j) \models \text{DevicePostureCheck}$$

*Violation Category*: `MISSING_DEVICE_VERIFICATION` (Severity: `HIGH`).

---

### Invariant 3: Principle of Least Privilege & Strict Authorization
**Principle**: *Authentication $\neq$ Authorization.*  
Transition into `ACCESS_GRANTED` cannot originate directly from unprivileged states (`START`, `UNAUTHENTICATED`) or from authentication without evaluating explicit resource permissions.

$$\forall (q_s, \sigma, C, \text{ACCESS\_GRANTED}) \in \delta: \quad q_s = \text{AUTHORIZED} \quad \lor \quad C \models \text{PermissionGuard}$$

*Violation Category*: `PRIVILEGE_BYPASS` / `MISSING_AUTHORIZATION` (Severity: `CRITICAL` / `HIGH`).

---

### Invariant 4: Finite Session Lifetime & Continuous Revocability
**Principle**: *No Perpetual Grants (Zombie Sessions).*  
Every granted access session must possess forward reachability to an expiration or revocation state.

$$\text{Reachable}(\text{ACCESS\_GRANTED}) \cap \{\text{SESSION\_EXPIRED}, \text{REVOKED}\} \neq \emptyset$$

*Violation Category*: `NO_REVOCATION_PATH` (Severity: `HIGH`).

---

### Invariant 5: Absence of Dead/Trap States
**Principle**: *Completeness & Liveness.*  
Every non-terminal state must be capable of eventually progressing toward a designated terminal state $F$.

$$\forall q \in Q \setminus F, \quad \exists f \in F \text{ such that } \text{Reachable}(q, f)$$

*Violation Category*: `DEAD_STATE` (Severity: `HIGH`).

---

### Invariant 6: Reachability of Defined States
**Principle**: *Minimalism & Dead Policy Elimination.*  
Every defined state must be reachable from the start state $q_0$.

$$\forall q \in Q, \quad q \in \text{Reachable}(q_0)$$

*Violation Category*: `UNREACHABLE_STATE` (Severity: `MEDIUM`).

---

### Invariant 7: Transition Determinism & Rule Disambiguation
**Principle**: *Predictable Security Posture.*  
For any state $q$ and trigger $(\sigma, C)$, there must exist at most one destination state.

$$\forall q \in Q, \forall \sigma \in \Sigma, \forall C \in \mathcal{C}: \quad |\delta(q, \sigma, C)| \le 1$$

*Violation Category*: `RULE_CONFLICT` (Severity: `HIGH`).

---

## 3. Algorithmic Formulation & Complexity

Let $G = (V, E)$ be the directed graph induced by $M$, where $V = Q$ and $E = \delta$.

| Check | Algorithm | Worst-Case Time Complexity | Worst-Case Space Complexity |
| :--- | :--- | :--- | :--- |
| **Reachability Analysis** | Breadth-First Search (BFS) | $\mathcal{O}(\|V\| + \|E\|)$ | $\mathcal{O}(\|V\|)$ |
| **Unreachable State Detection** | $V \setminus \text{BFS}(q_0)$ | $\mathcal{O}(\|V\| + \|E\|)$ | $\mathcal{O}(\|V\|)$ |
| **Dead State Detection** | Reverse BFS from all $f \in F$ | $\mathcal{O}(\|V\| + \|E\|)$ | $\mathcal{O}(\|V\| + \|E\|)$ |
| **Invariant Trajectory Checking** | Depth-Limited DFS Path Extraction | $\mathcal{O}(\|V\| + \|E\|)$ | $\mathcal{O}(\text{depth})$ |
| **Counterexample Witness Path** | BFS Shortest Path | $\mathcal{O}(\|V\| + \|E\|)$ | $\mathcal{O}(\|V\|)$ |

Because access-control workflows typically contain $\|V\| < 100$ and $\|E\| < 500$, total formal verification completes in under **1 millisecond** on commodity hardware.
