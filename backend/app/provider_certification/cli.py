"""Provider Certification Framework CLI (message 7).

Stable developer/CI entry point:

    python -m app.provider_certification.cli certify-all
    python -m app.provider_certification.cli certify-provider sentry
    python -m app.provider_certification.cli generate-reports
    python -m app.provider_certification.cli check-reports
    python -m app.provider_certification.cli affected --base <sha> --head <sha>

Every command is pure/read-only with respect to production systems: no
network call, no DB session, no connector instantiation, no credential
decryption, no sync trigger. ``generate-reports`` is the only command
that writes to disk, and it only ever writes the committed,
non-sensitive certification report files.

Exit codes:
    0 = certification passed / command succeeded
    1 = certification gate failed (certify-all / certify-provider)
    2 = invalid command or unknown provider
    3 = generated reports are stale (check-reports)
    4 = internal framework error (unexpected exception)
"""

from __future__ import annotations

import argparse
import json
import sys

from app.provider_certification import fingerprint as fingerprint_module
from app.provider_certification import impact as impact_module
from app.provider_certification import report_drift as report_drift_module
from app.provider_certification import runner

EXIT_PASS = 0
EXIT_GATE_FAILED = 1
EXIT_INVALID_COMMAND = 2
EXIT_REPORTS_STALE = 3
EXIT_INTERNAL_ERROR = 4

SCHEMA_VERSION = 1


def _text_gate_failure_summary(provider_id: str, result) -> str:
    lines = []
    for gate in result.gates:
        if gate.status not in ("fail", "unknown"):
            continue
        lines.append(f"Provider: {provider_id}")
        lines.append(f"Gate: {gate.gate_id}")
        lines.append(f"Status: {gate.status}")
        lines.append(f"Details: {gate.details}")
        if gate.remediation:
            lines.append("")
            lines.append("Remediation:")
            lines.append(gate.remediation)
        lines.append("")
    return "\n".join(lines)


def _result_to_dict(result) -> dict:
    return json.loads(result.to_json())


def _build_json_envelope(command: str, overall_status: str, providers: dict, failed_gates: list,
                          warnings: list, deferred: list, remediation: list, exit_code: int) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "overall_status": overall_status,
        "providers": providers,
        "failed_gates": failed_gates,
        "warnings": warnings,
        "deferred_gates": deferred,
        "remediation": remediation,
        "exit_code_category": {
            0: "pass",
            1: "gate_failed",
            2: "invalid_command",
            3: "reports_stale",
            4: "internal_error",
        }[exit_code],
    }


def _print_json(envelope: dict) -> None:
    print(json.dumps(envelope, sort_keys=True, indent=2))


def cmd_certify_all(args: argparse.Namespace) -> int:
    results = runner.certify_all_providers()
    providers = {pid: _result_to_dict(r) for pid, r in sorted(results.items())}
    overall = "pass" if all(r.overall_status == "pass" for r in results.values()) else "fail"

    failed_gates = []
    warnings = []
    deferred = []
    remediation = []
    for pid, r in sorted(results.items()):
        for g in r.gates:
            if g.status in ("fail", "unknown"):
                failed_gates.append({"provider": pid, "gate_id": g.gate_id, "status": g.status, "details": g.details})
                if g.remediation:
                    remediation.append({"provider": pid, "gate_id": g.gate_id, "remediation": g.remediation})
            elif g.status == "warning":
                warnings.append({"provider": pid, "gate_id": g.gate_id, "details": g.details})
            elif g.status == "deferred":
                deferred.append({"provider": pid, "gate_id": g.gate_id})

    exit_code = EXIT_PASS if overall == "pass" else EXIT_GATE_FAILED

    if args.format == "json":
        _print_json(_build_json_envelope("certify-all", overall, providers, failed_gates, warnings, deferred, remediation, exit_code))
    else:
        print(f"Certifying {len(results)} provider(s)...")
        for pid, r in sorted(results.items()):
            print(f"  {pid}: {r.overall_status}")
        if failed_gates:
            print()
            print("Failures:")
            print()
            for pid, r in sorted(results.items()):
                if r.overall_status != "pass":
                    print(_text_gate_failure_summary(pid, r))
        print()
        print(f"Overall: {overall.upper()}")

    return exit_code


def cmd_certify_provider(args: argparse.Namespace) -> int:
    provider_id = args.provider
    known = set(runner.known_provider_ids())
    if provider_id not in known:
        message = f"Unknown provider {provider_id!r}. Known providers: {sorted(known)}"
        if args.format == "json":
            _print_json(_build_json_envelope(
                "certify-provider", "invalid", {}, [], [], [], [],
                EXIT_INVALID_COMMAND,
            ) | {"error": message})
        else:
            print(f"ERROR: {message}", file=sys.stderr)
        return EXIT_INVALID_COMMAND

    result = runner.certify_provider(provider_id)
    providers = {provider_id: _result_to_dict(result)}
    failed_gates = [
        {"provider": provider_id, "gate_id": g.gate_id, "status": g.status, "details": g.details}
        for g in result.gates if g.status in ("fail", "unknown")
    ]
    warnings = [
        {"provider": provider_id, "gate_id": g.gate_id, "details": g.details}
        for g in result.gates if g.status == "warning"
    ]
    deferred = [{"provider": provider_id, "gate_id": g.gate_id} for g in result.gates if g.status == "deferred"]
    remediation = [
        {"provider": provider_id, "gate_id": g.gate_id, "remediation": g.remediation}
        for g in result.gates if g.status in ("fail", "unknown") and g.remediation
    ]

    exit_code = EXIT_PASS if result.overall_status == "pass" else EXIT_GATE_FAILED

    if args.format == "json":
        _print_json(_build_json_envelope("certify-provider", result.overall_status, providers, failed_gates, warnings, deferred, remediation, exit_code))
    else:
        print(f"Provider: {provider_id}")
        print(f"Overall: {result.overall_status.upper()}")
        if failed_gates:
            print()
            print(_text_gate_failure_summary(provider_id, result))

    return exit_code


def cmd_generate_reports(args: argparse.Namespace) -> int:
    try:
        written = report_drift_module.generate_reports()
    except Exception as exc:  # noqa: BLE001 - surface as internal error, never crash silently
        if args.format == "json":
            _print_json({"schema_version": SCHEMA_VERSION, "command": "generate-reports", "overall_status": "error", "error": str(exc), "exit_code_category": "internal_error"})
        else:
            print(f"INTERNAL ERROR: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    rel_paths = sorted(str(p.relative_to(runner._BACKEND_ROOT)) for p in written)
    if args.format == "json":
        _print_json({"schema_version": SCHEMA_VERSION, "command": "generate-reports", "overall_status": "pass", "files_written": rel_paths, "exit_code_category": "pass"})
    else:
        print(f"Wrote {len(rel_paths)} report file(s):")
        for p in rel_paths:
            print(f"  {p}")

    return EXIT_PASS


def cmd_check_reports(args: argparse.Namespace) -> int:
    drift = report_drift_module.check_report_drift()
    exit_code = EXIT_PASS if drift.is_clean else EXIT_REPORTS_STALE

    if args.format == "json":
        _print_json({
            "schema_version": SCHEMA_VERSION,
            "command": "check-reports",
            "overall_status": "pass" if drift.is_clean else "fail",
            **drift.as_dict(),
            "exit_code_category": "pass" if drift.is_clean else "reports_stale",
        })
    else:
        if drift.is_clean:
            print("Generated reports are clean — no drift detected.")
        else:
            print(drift.remediation())

    return exit_code


def cmd_affected(args: argparse.Namespace) -> int:
    try:
        result = impact_module.analyze_impact_from_git(args.base, args.head)
    except Exception as exc:  # noqa: BLE001
        if args.format == "json":
            _print_json({"schema_version": SCHEMA_VERSION, "command": "affected", "overall_status": "error", "error": str(exc), "exit_code_category": "internal_error"})
        else:
            print(f"INTERNAL ERROR: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR

    if args.format == "json":
        _print_json({
            "schema_version": SCHEMA_VERSION,
            "command": "affected",
            "overall_status": "pass",
            **result.as_dict(),
            "exit_code_category": "pass",
        })
    else:
        print(f"Directly affected providers: {', '.join(result.directly_affected_providers) or '(none)'}")
        print(f"Globally affected dimensions: {', '.join(result.globally_affected_dimensions) or '(none)'}")
        print(f"Full-catalog certification required: {result.full_catalog_required}")
        if result.unknown_provider_files:
            print(f"Unknown provider-shaped files: {', '.join(result.unknown_provider_files)}")

    return EXIT_PASS


def build_parser() -> argparse.ArgumentParser:
    # --format is accepted BOTH before and after the subcommand (e.g.
    # `cli --format json certify-all` and `cli certify-all --format json`
    # both work) by declaring it on the top-level parser AND on every
    # subparser via a shared `parent` parser.
    format_parent = argparse.ArgumentParser(add_help=False)
    format_parent.add_argument("--format", choices=("text", "json"), default="text")

    parser = argparse.ArgumentParser(
        prog="python -m app.provider_certification.cli",
        description="Provider Certification Framework CLI",
        parents=[format_parent],
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("certify-all", help="Certify every known provider", parents=[format_parent])

    p_provider = subparsers.add_parser("certify-provider", help="Certify a single provider by canonical ID", parents=[format_parent])
    p_provider.add_argument("provider", help="Canonical provider ID (e.g. 'sentry')")

    subparsers.add_parser("generate-reports", help="Regenerate every deterministic certification report on disk", parents=[format_parent])
    subparsers.add_parser("check-reports", help="Check committed reports for drift without writing anything", parents=[format_parent])

    p_affected = subparsers.add_parser("affected", help="Analyze changed-provider impact between two git refs", parents=[format_parent])
    p_affected.add_argument("--base", required=True, help="Base git SHA/ref")
    p_affected.add_argument("--head", required=True, help="Head git SHA/ref")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse calls sys.exit(2) on malformed arguments — normalize
        # to our EXIT_INVALID_COMMAND convention (argparse already uses 2).
        code = exc.code if isinstance(exc.code, int) else EXIT_INVALID_COMMAND
        return code if code != 0 else EXIT_PASS

    dispatch = {
        "certify-all": cmd_certify_all,
        "certify-provider": cmd_certify_provider,
        "generate-reports": cmd_generate_reports,
        "check-reports": cmd_check_reports,
        "affected": cmd_affected,
    }
    handler = dispatch.get(args.command)
    if handler is None:
        print(f"Unknown command: {args.command!r}", file=sys.stderr)
        return EXIT_INVALID_COMMAND

    try:
        return handler(args)
    except Exception as exc:  # noqa: BLE001 - never let an unhandled exception produce a misleading exit code
        print(f"INTERNAL ERROR: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR


if __name__ == "__main__":
    sys.exit(main())
