"""
OASIS SARIF v2.1.0 Exporter
Static Analysis Results Interchange Format (SARIF) serializer for AxiomTrust.
Standard OASIS format for GitHub Code Scanning, GitLab SAST, and Microsoft Security DevOps.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import json
from pathlib import Path

from backend.models.report import VerificationReport, PolicyViolation, ViolationType, ViolationSeverity


# Standard Rule Definitions mapping AxiomTrust violations to CWE & NIST SP 800-207
SARIF_RULE_METADATA: Dict[str, Dict[str, Any]] = {
    ViolationType.MISSING_AUTHENTICATION.value: {
        "id": "AXIOM-ZT-001",
        "name": "MissingAuthenticationPrecedence",
        "shortDescription": {"text": "Access granted without preceding authentication (NIST Tenet 1 & 2)."},
        "fullDescription": {
            "text": "Execution trajectory reaches an ACCESS_GRANTED terminal state without traversing an explicitly designated authenticated state, violating NIST SP 800-207 mandatory authentication precedence."
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Ensure all paths to ACCESS_GRANTED require prior authentication (e.g., START -> UNAUTHENTICATED -> AUTHENTICATED).",
            "markdown": "**Remediation**: Route unauthenticated sessions through an authentication gate prior to evaluation.\n\n- **NIST Control**: SP 800-207 Tenets 1 & 2\n- **CWE**: [CWE-306](https://cwe.mitre.org/data/definitions/306.html)"
        },
        "properties": {
            "tags": ["security", "zero-trust", "NIST-SP-800-207", "CWE-306", "authentication"],
            "security-severity": "9.0",
            "precision": "very-high"
        }
    },
    ViolationType.MISSING_DEVICE_VERIFICATION.value: {
        "id": "AXIOM-ZT-002",
        "name": "MissingDevicePostureCheck",
        "shortDescription": {"text": "Access granted without explicit device compliance check (NIST Tenet 2)."},
        "fullDescription": {
            "text": "Execution path grants resource access without validating device health, corporate enrollment, or security posture."
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Add a device verification state (e.g., DEVICE_VERIFIED) or device posture condition guard on grant transitions.",
            "markdown": "**Remediation**: Mandate device health checks via EDR/MDM posture evaluation prior to authorizing resource access.\n\n- **NIST Control**: SP 800-207 Tenet 2\n- **CWE**: [CWE-284](https://cwe.mitre.org/data/definitions/284.html)"
        },
        "properties": {
            "tags": ["security", "zero-trust", "NIST-SP-800-207", "CWE-284", "device-trust"],
            "security-severity": "8.0",
            "precision": "very-high"
        }
    },
    ViolationType.MISSING_AUTHORIZATION.value: {
        "id": "AXIOM-ZT-003",
        "name": "MissingRoleAuthorization",
        "shortDescription": {"text": "Access granted without explicit role/attribute authorization (NIST Tenet 1)."},
        "fullDescription": {
            "text": "State transition grants resource access without checking authorization permissions, roles, or least-privilege scoping."
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Enforce role or attribute check prior to granting access.",
            "markdown": "**Remediation**: Require explicit role evaluation (`AUTHORIZATION_CHECK`) before reaching access grants.\n\n- **NIST Control**: SP 800-207 Tenet 1\n- **CWE**: [CWE-862](https://cwe.mitre.org/data/definitions/862.html)"
        },
        "properties": {
            "tags": ["security", "zero-trust", "NIST-SP-800-207", "CWE-862", "authorization"],
            "security-severity": "8.5",
            "precision": "very-high"
        }
    },
    ViolationType.UNAUTHORIZED_TRANSITION.value: {
        "id": "AXIOM-ZT-004",
        "name": "UnauthorizedStateTransition",
        "shortDescription": {"text": "Transition bypassed security boundary without required authorization step."},
        "fullDescription": {
            "text": "An incoming transition to an access state originates from an unauthorized state, violating least-privilege separation."
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Restrict access transition sources to authorized security checkpoints.",
            "markdown": "**Remediation**: Re-route transition from `AUTHORIZED` state only.\n\n- **CWE**: [CWE-285](https://cwe.mitre.org/data/definitions/285.html)"
        },
        "properties": {
            "tags": ["security", "zero-trust", "CWE-285", "access-control"],
            "security-severity": "7.5",
            "precision": "high"
        }
    },
    ViolationType.NO_REVOCATION_PATH.value: {
        "id": "AXIOM-ZT-005",
        "name": "MissingSessionRevocationPath",
        "shortDescription": {"text": "Granted access state lacks revocation or session expiration path (NIST Tenet 7)."},
        "fullDescription": {
            "text": "Access granted state forms an absorbing trap with no transitions leading to SESSION_EXPIRED or REVOKED, permitting perpetual zombie sessions."
        },
        "defaultConfiguration": {"level": "warning"},
        "help": {
            "text": "Add session timeout or administrative revocation transitions originating from ACCESS_GRANTED.",
            "markdown": "**Remediation**: Define explicit session expiration (`ttl_exp`) or revocation transitions.\n\n- **NIST Control**: SP 800-207 Tenet 7\n- **CWE**: [CWE-613](https://cwe.mitre.org/data/definitions/613.html)"
        },
        "properties": {
            "tags": ["security", "zero-trust", "NIST-SP-800-207", "CWE-613", "session-management"],
            "security-severity": "6.5",
            "precision": "very-high"
        }
    },
    ViolationType.PRIVILEGE_BYPASS.value: {
        "id": "AXIOM-ZT-006",
        "name": "PrivilegeBypassTrajectory",
        "shortDescription": {"text": "Short-circuit trajectory circumvents security checkpoints."},
        "fullDescription": {
            "text": "An adversary can reach an elevated authorization state by skipping mandatory multi-factor or device controls."
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Eliminate direct bypass edges and enforce linear checkpoint traversal.",
            "markdown": "**Remediation**: Sever bypass edges in policy transition table.\n\n- **CWE**: [CWE-269](https://cwe.mitre.org/data/definitions/269.html)"
        },
        "properties": {
            "tags": ["security", "privilege-escalation", "CWE-269"],
            "security-severity": "8.8",
            "precision": "very-high"
        }
    },
    ViolationType.UNMITIGATED_HIGH_RISK_PATH.value: {
        "id": "AXIOM-ZT-007",
        "name": "UnmitigatedHighRiskTrajectory",
        "shortDescription": {"text": "Cumulative session risk exceeds acceptable threshold without step-up auth (NIST Tenet 6)."},
        "fullDescription": {
            "text": "Continuous risk accumulation engine identified an execution path exceeding risk threshold without required step-up authentication."
        },
        "defaultConfiguration": {"level": "warning"},
        "help": {
            "text": "Require step-up authentication when cumulative risk exceeds policy ceiling.",
            "markdown": "**Remediation**: Instate dynamic step-up challenge before high-risk operations.\n\n- **NIST Control**: SP 800-207 Tenet 6\n- **CWE**: [CWE-358](https://cwe.mitre.org/data/definitions/358.html)"
        },
        "properties": {
            "tags": ["security", "continuous-adaptive-risk", "NIST-SP-800-207", "CWE-358"],
            "security-severity": "6.0",
            "precision": "high"
        }
    },
    ViolationType.UNREACHABLE_STATE.value: {
        "id": "AXIOM-TOC-001",
        "name": "UnreachableDeadLogicState",
        "shortDescription": {"text": "State cannot be reached from initial start state q0."},
        "fullDescription": {
            "text": "Graph reachability analysis proves state has in-degree 0 or is disconnected from initial state q0, representing redundant or orphaned policy logic."
        },
        "defaultConfiguration": {"level": "note"},
        "help": {
            "text": "Remove the unreachable state or add a valid transition from an existing reachable state.",
            "markdown": "**Remediation**: Remove orphaned state or wire legitimate inbound transitions.\n\n- **CWE**: [CWE-1164](https://cwe.mitre.org/data/definitions/1164.html)"
        },
        "properties": {
            "tags": ["quality", "theory-of-computation", "dead-code", "CWE-1164"],
            "security-severity": "3.0",
            "precision": "very-high"
        }
    },
    ViolationType.DEAD_STATE.value: {
        "id": "AXIOM-TOC-002",
        "name": "DeadEndTrapState",
        "shortDescription": {"text": "Non-terminal state from which no final terminal state is reachable."},
        "fullDescription": {
            "text": "Reachable state has no outbound paths leading to any final terminal state (grant, deny, expired), permanently trapping user workflows."
        },
        "defaultConfiguration": {"level": "warning"},
        "help": {
            "text": "Add error-handling, denial, or fallback transitions from dead-end states.",
            "markdown": "**Remediation**: Provide terminal escape transitions (e.g., timeout or deny) from trap states.\n\n- **CWE**: [CWE-835](https://cwe.mitre.org/data/definitions/835.html)"
        },
        "properties": {
            "tags": ["quality", "theory-of-computation", "trap-state", "CWE-835"],
            "security-severity": "5.5",
            "precision": "very-high"
        }
    },
    ViolationType.RULE_CONFLICT.value: {
        "id": "AXIOM-TOC-003",
        "name": "NonDeterministicRuleConflict",
        "shortDescription": {"text": "Identical state and action trigger ambiguous transitions with overlapping guards."},
        "fullDescription": {
            "text": "Automata determinism check found multiple transitions with identical source state and action without mutually exclusive guard predicates."
        },
        "defaultConfiguration": {"level": "warning"},
        "help": {
            "text": "Disambiguate actions or define mutually exclusive guard conditions.",
            "markdown": "**Remediation**: Ensure distinct actions or disjoint guard conditions for deterministic evaluation.\n\n- **CWE**: [CWE-436](https://cwe.mitre.org/data/definitions/436.html)"
        },
        "properties": {
            "tags": ["quality", "determinism", "rule-conflict", "CWE-436"],
            "security-severity": "5.0",
            "precision": "high"
        }
    },
    ViolationType.MALFORMED_POLICY.value: {
        "id": "AXIOM-SEC-001",
        "name": "MalformedPolicyStructure",
        "shortDescription": {"text": "Policy contains structural or syntax anomalies."},
        "fullDescription": {
            "text": "The provided policy violates structural schema constraints, missing essential initial states or transitions."
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Correct policy syntax according to AxiomTrust JSON schema.",
            "markdown": "**Remediation**: Fix schema violations and ensure valid initial state q0.\n\n- **CWE**: [CWE-20](https://cwe.mitre.org/data/definitions/20.html)"
        },
        "properties": {
            "tags": ["security", "schema-validation", "CWE-20"],
            "security-severity": "7.0",
            "precision": "very-high"
        }
    }
}


class SARIFExporter:
    """
    Serializes AxiomTrust Verification Reports into standard OASIS SARIF v2.1.0 format.
    Compatible with GitHub Advanced Security (Code Scanning), GitLab SAST, and Microsoft DevOps.
    """

    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    SARIF_VERSION = "2.1.0"
    TOOL_NAME = "AxiomTrust"
    TOOL_VERSION = "1.0.0"
    TOOL_URI = "https://github.com/Harshads-git/zero-trust-policy-verification"

    @classmethod
    def to_sarif_dict(
        cls,
        reports: List[VerificationReport],
        policy_file_paths: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Converts a list of VerificationReport instances into a complete SARIF v2.1.0 dictionary.
        
        Args:
            reports: List of formal verification reports from ZeroTrustVerificationEngine.
            policy_file_paths: Optional mapping of policy_id to actual repository relative file path.
        """
        policy_paths = policy_file_paths or {}
        
        # Build driver rules list
        rules_list: List[Dict[str, Any]] = []
        rule_id_to_index: Dict[str, int] = {}

        for rule_key, meta in SARIF_RULE_METADATA.items():
            rule_id_to_index[meta["id"]] = len(rules_list)
            rule_id_to_index[rule_key] = len(rules_list)
            rules_list.append(meta)

        results: List[Dict[str, Any]] = []

        for report in reports:
            artifact_uri = policy_paths.get(
                report.policy_id,
                f"policies/{report.policy_id}.json"
            )

            for violation in report.violations:
                rule_key = violation.type.value if hasattr(violation.type, "value") else str(violation.type)
                rule_meta = SARIF_RULE_METADATA.get(rule_key, {
                    "id": f"AXIOM-GEN-{rule_key}",
                    "name": rule_key,
                    "shortDescription": {"text": violation.message},
                    "fullDescription": {"text": violation.explanation},
                    "defaultConfiguration": {"level": "error"},
                    "help": {"text": violation.remediation or "Resolve policy violation."},
                    "properties": {"tags": ["security", "zero-trust"]}
                })

                rule_id = rule_meta["id"]
                rule_idx = rule_id_to_index.get(rule_id, 0)

                # Map AxiomTrust severity to SARIF level
                level = cls._map_severity_to_level(violation.severity)

                # Build physical and logical locations
                location_obj: Dict[str, Any] = {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": artifact_uri,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1
                        }
                    }
                }

                if violation.state:
                    location_obj["logicalLocations"] = [{
                        "name": violation.state,
                        "kind": "state",
                        "fullyQualifiedName": f"{report.policy_name}::{violation.state}"
                    }]

                # Format messages
                message_text = f"[{violation.severity.value}] {violation.message}"
                if violation.explanation:
                    message_text += f" - {violation.explanation}"

                markdown_msg = f"### ⚠️ Zero Trust Policy Violation: `{rule_meta['name']}`\n\n"
                markdown_msg += f"- **Policy**: `{report.policy_name}` (`{report.policy_id}`)\n"
                markdown_msg += f"- **Severity**: `{violation.severity.value}`\n"
                markdown_msg += f"- **Message**: {violation.message}\n\n"
                markdown_msg += f"> {violation.explanation}\n\n"
                if violation.remediation:
                    markdown_msg += f"**Remediation**: {violation.remediation}\n"

                result_entry: Dict[str, Any] = {
                    "ruleId": rule_id,
                    "ruleIndex": rule_idx,
                    "level": level,
                    "message": {
                        "text": message_text,
                        "markdown": markdown_msg
                    },
                    "locations": [location_obj],
                    "properties": {
                        "axiomtrust": {
                            "policy_id": report.policy_id,
                            "policy_name": report.policy_name,
                            "violation_type": rule_key,
                            "source_state": violation.source_state,
                            "target_state": violation.target_state,
                            "rule_id": violation.rule_id,
                            "risk_score": report.risk_score,
                            "security_posture": report.security_posture
                        }
                    }
                }

                # Step 7: Build CodeFlows tracing BFS Counterexample witness path
                if violation.witness_path and len(violation.witness_path) > 1:
                    thread_flow_locs = []
                    for step_idx, st in enumerate(violation.witness_path, 1):
                        step_loc = {
                            "location": {
                                "message": {
                                    "text": f"Step {step_idx}: Traversed state '{st}'"
                                },
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": artifact_uri,
                                        "uriBaseId": "%SRCROOT%"
                                    },
                                    "region": {"startLine": 1, "startColumn": 1}
                                },
                                "logicalLocations": [{
                                    "name": st,
                                    "kind": "state"
                                }]
                            },
                            "executionOrder": step_idx
                        }
                        thread_flow_locs.append(step_loc)

                    result_entry["codeFlows"] = [{
                        "message": {
                            "text": f"Counterexample witness trajectory demonstrating {rule_meta['name']}"
                        },
                        "threadFlows": [{
                            "locations": thread_flow_locs
                        }]
                    }]

                results.append(result_entry)

        # Build full SARIF schema document
        sarif_doc = {
            "$schema": cls.SARIF_SCHEMA,
            "version": cls.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": cls.TOOL_NAME,
                            "organization": "AxiomTrust Project",
                            "semanticVersion": cls.TOOL_VERSION,
                            "informationUri": cls.TOOL_URI,
                            "rules": rules_list
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat()
                        }
                    ],
                    "results": results
                }
            ]
        }

        return sarif_doc

    @classmethod
    def export_sarif_file(
        cls,
        reports: List[VerificationReport],
        output_path: str,
        policy_file_paths: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Exports verification reports to a formatted SARIF JSON file on disk.
        Returns the resolved absolute path of the written file.
        """
        sarif_dict = cls.to_sarif_dict(reports, policy_file_paths)
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(sarif_dict, f, indent=2)
        return str(out_p)

    @staticmethod
    def _map_severity_to_level(severity: ViolationSeverity) -> str:
        """Maps AxiomTrust ViolationSeverity to standard SARIF result levels."""
        val = severity.value if hasattr(severity, "value") else str(severity)
        if val in ("CRITICAL", "HIGH"):
            return "error"
        elif val == "MEDIUM":
            return "warning"
        elif val in ("LOW", "INFO"):
            return "note"
        return "warning"
