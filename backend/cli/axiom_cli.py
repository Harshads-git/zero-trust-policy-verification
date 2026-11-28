"""
AxiomTrust Shift-Left DevSecOps CLI
Command-line interface for automated Zero Trust policy verification,
OASIS SARIF v2.1.0 reporting, AWS IAM transpilation, and OPA Rego generation.
"""

import sys
import os
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional

from backend.models.policy import ZeroTrustPolicy
from backend.models.report import VerificationReport
from backend.core.verifier import ZeroTrustVerificationEngine
from backend.core.smt_solver import Z3ConstraintSolver
from backend.exporters.sarif import SARIFExporter
from backend.transpiler.aws_iam import AWSIAMTranspiler
from backend.transpiler.opa_rego import OPARegoGenerator
from backend.models.transpiler import OPARegoExportRequest
from backend.core.threat_simulator import AttackGraphSimulator
from backend.models.threat import ThreatSimulationRequest


# ANSI Color Codes for Terminal Output
class TerminalColors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def print_banner():
    banner = f"""{TerminalColors.CYAN}{TerminalColors.BOLD}
    ===============================================================
      AXIOMTRUST : ZERO TRUST POLICY VERIFICATION ENGINE (ZTPVE)   
                 Shift-Left DevSecOps Verification CLI             
    ==============================================================={TerminalColors.RESET}"""
    print(banner)


def load_policy_from_file(file_path: Path) -> ZeroTrustPolicy:
    """Loads and validates a ZeroTrustPolicy from a JSON file."""
    if not file_path.exists():
        raise FileNotFoundError(f"Policy file not found: {file_path}")
    
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    # If the file wraps the policy under a "policy" key, unwrap it
    if "policy" in data and isinstance(data["policy"], dict):
        data = data["policy"]
        
    return ZeroTrustPolicy(**data)


def collect_policy_files(paths: List[str]) -> List[Path]:
    """Expands file paths and directories into a list of JSON policy files."""
    collected: List[Path] = []
    for p_str in paths:
        p = Path(p_str)
        if not p.exists():
            continue
        if p.is_file() and p.suffix.lower() == ".json":
            collected.append(p)
        elif p.is_dir():
            for sub_p in p.rglob("*.json"):
                collected.append(sub_p)
    return sorted(list(set(collected)))


def run_verify_command(args: argparse.Namespace) -> int:
    """Executes formal verification across target policy files."""
    if not args.quiet and args.format == "text":
        print_banner()

    policy_files = collect_policy_files(args.targets)
    if not policy_files:
        print(f"{TerminalColors.RED}[ERROR] No JSON policy files found in specified targets.{TerminalColors.RESET}")
        return 2

    verifier = ZeroTrustVerificationEngine()
    smt_solver = Z3ConstraintSolver() if args.with_smt else None

    reports: List[VerificationReport] = []
    path_map: Dict[str, str] = {}
    any_violations = False
    max_risk_exceeded = False

    if not args.quiet and args.format == "text":
        print(f"{TerminalColors.BOLD}Scanning {len(policy_files)} policy file(s)...{TerminalColors.RESET}\n")

    for p_file in policy_files:
        try:
            policy = load_policy_from_file(p_file)
        except Exception as e:
            if args.format == "text":
                print(f"{TerminalColors.RED}[FAIL] Failed to parse {p_file.name}: {e}{TerminalColors.RESET}")
            any_violations = True
            continue

        report = verifier.verify(policy)
        reports.append(report)
        path_map[report.policy_id] = str(p_file.as_posix())

        if len(report.violations) > 0:
            any_violations = True

        if args.max_risk is not None and report.risk_score > args.max_risk:
            max_risk_exceeded = True

        # Terminal text display
        if args.format == "text" and not args.quiet:
            status_color = TerminalColors.GREEN if report.valid else TerminalColors.RED
            status_text = "PASSED" if report.valid else "VIOLATIONS DETECTED"
            print(f"Policy: {TerminalColors.BOLD}{report.policy_name}{TerminalColors.RESET} ({p_file.name})")
            print(f"  Status: {status_color}{status_text}{TerminalColors.RESET} | Risk Score: {report.risk_score}/100 ({report.security_posture}) | Time: {report.verification_time_ms:.2f}ms")
            print(f"  States: {report.total_states} | Transitions: {report.total_transitions} | Invariants Checked: {len(report.formal_invariants_checked)}")

            if report.violations:
                print(f"  {TerminalColors.YELLOW}Violations ({len(report.violations)}):{TerminalColors.RESET}")
                for idx, v in enumerate(report.violations, 1):
                    sev_color = TerminalColors.RED if v.severity.value in ("CRITICAL", "HIGH") else TerminalColors.YELLOW
                    print(f"    {idx}. [{sev_color}{v.severity.value}{TerminalColors.RESET}] {v.type.value}: {v.message}")
                    if v.witness_path:
                        print(f"       Trajectory: {' -> '.join(v.witness_path)}")
                    if v.remediation:
                        print(f"       Remediation: {v.remediation}")
            
            if smt_solver:
                smt_result = smt_solver.verify_policy_guards(policy)
                print(f"  SMT Satisfiability: {TerminalColors.CYAN}{'SAT (All Guards Consistent)' if smt_result['consistent'] else 'UNSAT (Dead/Conflicting Guards)'}{TerminalColors.RESET}")
            print("-" * 65)

    # Output SARIF if requested
    if args.sarif:
        sarif_path = SARIFExporter.export_sarif_file(reports, args.sarif, path_map)
        if not args.quiet:
            print(f"{TerminalColors.GREEN}[+] OASIS SARIF v2.1.0 report generated: {sarif_path}{TerminalColors.RESET}")

    # Output JSON if requested
    if args.json:
        out_p = Path(args.json).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump([r.model_dump() for r in reports], f, indent=2)
        if not args.quiet:
            print(f"{TerminalColors.GREEN}[+] Raw JSON audit report generated: {out_p}{TerminalColors.RESET}")

    # Direct formatting to stdout if not text
    if args.format == "sarif":
        sarif_dict = SARIFExporter.to_sarif_dict(reports, path_map)
        print(json.dumps(sarif_dict, indent=2))
    elif args.format == "json":
        print(json.dumps([r.model_dump() for r in reports], indent=2))

    # Exit code determination
    if any_violations and (args.strict or args.format == "text"):
        return 1
    if max_risk_exceeded:
        return 1
    return 0


def run_sarif_command(args: argparse.Namespace) -> int:
    """Generates OASIS SARIF v2.1.0 report from policy files."""
    policy_files = collect_policy_files(args.targets)
    if not policy_files:
        print(f"{TerminalColors.RED}[ERROR] No policy files found.{TerminalColors.RESET}", file=sys.stderr)
        return 2

    verifier = ZeroTrustVerificationEngine()
    reports = []
    path_map = {}

    for p_file in policy_files:
        try:
            policy = load_policy_from_file(p_file)
            report = verifier.verify(policy)
            reports.append(report)
            path_map[report.policy_id] = str(p_file.as_posix())
        except Exception as e:
            print(f"{TerminalColors.RED}[WARN] Skipping invalid file {p_file}: {e}{TerminalColors.RESET}", file=sys.stderr)

    if args.output:
        SARIFExporter.export_sarif_file(reports, args.output, path_map)
        print(f"{TerminalColors.GREEN}[+] SARIF v2.1.0 exported to: {args.output}{TerminalColors.RESET}")
    else:
        sarif_dict = SARIFExporter.to_sarif_dict(reports, path_map)
        print(json.dumps(sarif_dict, indent=2))

    return 0


def run_transpile_iam_command(args: argparse.Namespace) -> int:
    """Transpiles AWS IAM JSON policy into AxiomTrust Zero Trust FSM."""
    iam_path = Path(args.file)
    if not iam_path.exists():
        print(f"{TerminalColors.RED}[ERROR] File not found: {iam_path}{TerminalColors.RESET}")
        return 2

    with open(iam_path, "r", encoding="utf-8") as f:
        iam_doc = json.load(f)

    transpiler = AWSIAMTranspiler()
    resp = transpiler.transpile(
        iam_policy_doc=iam_doc,
        policy_name=args.name or iam_path.stem,
        auto_verify=args.verify
    )

    print(f"{TerminalColors.BOLD}AWS IAM Transpilation Results:{TerminalColors.RESET}")
    print(f"  FSM Policy ID: {resp.policy.policy_id}")
    print(f"  Allowed Actions: {len(resp.allowed_actions)} | Denied Actions: {len(resp.denied_actions)}")
    print(f"  Wildcard Detected: {resp.has_wildcard_actions} | Multi-Action Statements: {resp.has_multi_action_statements}")
    
    if resp.privilege_escalation_risks:
        print(f"  {TerminalColors.RED}Privilege Escalation Risks ({len(resp.privilege_escalation_risks)}):{TerminalColors.RESET}")
        for risk in resp.privilege_escalation_risks:
            print(f"    - [{risk.severity}] {risk.vector_name}: {risk.explanation}")
    else:
        print(f"  {TerminalColors.GREEN}No AWS IAM Privilege Escalation vectors detected.{TerminalColors.RESET}")

    if args.output:
        out_p = Path(args.output).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(resp.policy.model_dump(), f, indent=2)
        print(f"{TerminalColors.GREEN}[+] Transpiled FSM policy saved to: {out_p}{TerminalColors.RESET}")

    if args.verify and resp.verification_report:
        v_report = resp.verification_report
        status_color = TerminalColors.GREEN if v_report.valid else TerminalColors.RED
        print(f"  Verification Status: {status_color}{'PASSED' if v_report.valid else 'VIOLATIONS DETECTED'}{TerminalColors.RESET} (Risk: {v_report.risk_score}/100)")
        return 1 if not v_report.valid else 0

    return 0


def run_export_rego_command(args: argparse.Namespace) -> int:
    """Exports AxiomTrust FSM policy to Open Policy Agent (OPA) Rego."""
    fsm_path = Path(args.file)
    if not fsm_path.exists():
        print(f"{TerminalColors.RED}[ERROR] File not found: {fsm_path}{TerminalColors.RESET}")
        return 2

    policy = load_policy_from_file(fsm_path)
    rego_gen = OPARegoGenerator()
    req = OPARegoExportRequest(
        package_name=args.package or "axiomtrust.authz",
        target_framework=args.framework
    )
    resp = rego_gen.compile(
        policy=policy,
        request=req
    )

    if args.output:
        out_p = Path(args.output).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            f.write(resp.rego_code)
        print(f"{TerminalColors.GREEN}[+] OPA Rego compiled ({resp.rules_compiled} rules) to: {out_p}{TerminalColors.RESET}")
    else:
        print(resp.rego_code)

    return 0


def run_threat_command(args: argparse.Namespace) -> int:
    """Executes red-team lateral movement simulation from CLI."""
    fsm_path = Path(args.file)
    if not fsm_path.exists():
        print(f"{TerminalColors.RED}[ERROR] File not found: {fsm_path}{TerminalColors.RESET}")
        return 2

    policy = load_policy_from_file(fsm_path)
    simulator = AttackGraphSimulator()
    pivot_node = args.pivot or policy.initial_state
    req = ThreatSimulationRequest(compromised_node=pivot_node)
    result = simulator.simulate(policy=policy, request=req)

    print(f"{TerminalColors.BOLD}Adversary Threat Simulation (Pivot: '{result.compromised_node}'):{TerminalColors.RESET}")
    print(f"  Blast Radius Score: {TerminalColors.RED}{result.blast_radius_score:.2f}{TerminalColors.RESET} ({result.blast_radius_percentage:.1f}% of topology)")
    print(f"  Reachable States: {len(result.attacker_reachable_states)} / {result.total_policy_states}")
    print(f"  Exploit Trajectories: {len(result.exploit_paths)} to Crown Jewels")
    print(f"  Identified Choke Points: {len(result.choke_points)}")

    if result.exploit_paths:
        print(f"\n{TerminalColors.YELLOW}Exploit Paths:{TerminalColors.RESET}")
        for p in result.exploit_paths:
            print(f"  - Target '{p.target_crown_jewel}' ({p.hop_count} hops): {' -> '.join(p.path)}")

    if result.choke_points:
        print(f"\n{TerminalColors.MAGENTA}Key Articulation Choke Points:{TerminalColors.RESET}")
        for cp in result.choke_points:
            print(f"  - Node '{cp.node}': Interception Ratio {cp.interception_ratio*100:.0f}% (Single Point of Defense: {cp.is_critical_single_point_of_defense})")

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Constructs the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="axiom",
        description="AxiomTrust Shift-Left DevSecOps Zero Trust Policy Verification CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: verify
    verify_p = subparsers.add_parser("verify", help="Verify policy files against NIST SP 800-207 invariants")
    verify_p.add_argument("targets", nargs="+", help="Policy file(s) or directory paths to verify")
    verify_p.add_argument("--sarif", type=str, default=None, help="Output path for OASIS SARIF v2.1.0 report")
    verify_p.add_argument("--json", type=str, default=None, help="Output path for raw JSON verification audit report")
    verify_p.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="Terminal output format")
    verify_p.add_argument("--strict", action="store_true", help="Fail with exit code 1 on any policy violation")
    verify_p.add_argument("--max-risk", type=int, default=None, help="Fail if policy risk score exceeds specified threshold (0-100)")
    verify_p.add_argument("--with-smt", action="store_true", help="Execute Z3 SMT guard constraint satisfiability checks")
    verify_p.add_argument("-q", "--quiet", action="store_true", help="Suppress non-error output")

    # Command: sarif
    sarif_p = subparsers.add_parser("sarif", help="Generate OASIS SARIF v2.1.0 report for GitHub/GitLab SAST")
    sarif_p.add_argument("targets", nargs="+", help="Policy file(s) or directories to scan")
    sarif_p.add_argument("-o", "--output", type=str, default=None, help="Output file path (default stdout)")

    # Command: transpile-iam
    iam_p = subparsers.add_parser("transpile-iam", help="Transpile AWS IAM JSON policy into AxiomTrust FSM")
    iam_p.add_argument("-f", "--file", type=str, required=True, help="AWS IAM policy JSON file path")
    iam_p.add_argument("-n", "--name", type=str, default=None, help="Policy name")
    iam_p.add_argument("-o", "--output", type=str, default=None, help="Output FSM JSON file path")
    iam_p.add_argument("--verify", action="store_true", help="Immediately run formal verification on transpiled FSM")

    # Command: export-rego
    rego_p = subparsers.add_parser("export-rego", help="Compile verified FSM into Open Policy Agent (OPA) Rego")
    rego_p.add_argument("-f", "--file", type=str, required=True, help="AxiomTrust FSM policy JSON file path")
    rego_p.add_argument("-o", "--output", type=str, default=None, help="Output .rego file path")
    rego_p.add_argument("-p", "--package", type=str, default="axiomtrust.authz", help="Rego package namespace")
    rego_p.add_argument("--framework", choices=["general", "kubernetes_gatekeeper", "envoy_proxy"], default="general", help="Target framework binding")

    # Command: threat
    threat_p = subparsers.add_parser("threat", help="Simulate red-team lateral movement and blast radius")
    threat_p.add_argument("-f", "--file", type=str, required=True, help="AxiomTrust FSM policy JSON file path")
    threat_p.add_argument("--pivot", type=str, default=None, help="Compromised initial state pivot")

    return parser


def main(args: Optional[List[str]] = None) -> int:
    """CLI Entrypoint Function."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    if not parsed_args.command:
        parser.print_help()
        return 0

    if parsed_args.command == "verify":
        return run_verify_command(parsed_args)
    elif parsed_args.command == "sarif":
        return run_sarif_command(parsed_args)
    elif parsed_args.command == "transpile-iam":
        return run_transpile_iam_command(parsed_args)
    elif parsed_args.command == "export-rego":
        return run_export_rego_command(parsed_args)
    elif parsed_args.command == "threat":
        return run_threat_command(parsed_args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
