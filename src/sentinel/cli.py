"""Command line entry point."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.error import URLError

from . import __version__
from .dependencies import audit_dependencies
from .rules import RULES
from .scanner import load_baseline, load_config, scan, write_baseline


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Review a repository for common security risks and unfinished code.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository directory to scan (default: current directory)")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="Report format")
    parser.add_argument("--config", help="JSON config path (default: .sentinel.json in the scan directory)")
    parser.add_argument("--output", help="Write the report to a file instead of stdout")
    baseline = parser.add_mutually_exclusive_group()
    baseline.add_argument("--baseline", help="Report only findings not present in this baseline file")
    baseline.add_argument("--write-baseline", help="Write the current findings as a new baseline and exit")
    parser.add_argument("--fail-on", choices=("never", "low", "medium", "high"), default="never",
                        help="Return exit code 1 when a finding at this severity or higher exists")
    parser.add_argument("--dependencies", action="store_true", help="Query OSV for pinned dependencies (requires network)")
    parser.add_argument("--fail-on-dependency", action="store_true", help="Return exit code 1 when OSV reports any dependency advisory")
    return parser


def main() -> int:
    args = _parser().parse_args()
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Error: scan path is not a directory: {root}")
        return 2
    config_path = Path(args.config).resolve() if args.config else root / ".sentinel.json"
    try:
        config = load_config(config_path)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Error: invalid config {config_path}: {error}")
        return 2
    findings = scan(root, config)
    dependency_findings = []
    if args.dependencies:
        try:
            dependency_findings = audit_dependencies(root, config.get("exclude", []))
        except (OSError, URLError, json.JSONDecodeError, TimeoutError) as error:
            print(f"Error: OSV dependency query failed: {error}")
            return 2
    if args.write_baseline:
        try:
            write_baseline(Path(args.write_baseline), findings)
        except OSError as error:
            print(f"Error: cannot write baseline {args.write_baseline}: {error}")
            return 2
        print(f"Baseline written with {len(findings)} finding(s): {args.write_baseline}")
        return 0
    if args.baseline:
        try:
            known = load_baseline(Path(args.baseline))
        except (OSError, json.JSONDecodeError, ValueError) as error:
            print(f"Error: invalid baseline {args.baseline}: {error}")
            return 2
        findings = [finding for finding in findings if finding.fingerprint() not in known]
    if args.format == "json":
        report = json.dumps({"tool": "repo-sentinel", "version": __version__, "root": str(root),
                             "summary": {severity: sum(f.severity == severity for f in findings)
                                         for severity in ("high", "medium", "low")},
                             "findings": [finding.to_dict() for finding in findings],
                             "dependency_findings": [finding.to_dict() for finding in dependency_findings]}, indent=2)
    elif args.format == "sarif":
        severity = {"high": "error", "medium": "warning", "low": "note"}
        report = json.dumps({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Repo Sentinel", "version": __version__,
                    "rules": [{"id": rule.id, "name": rule.title,
                               "shortDescription": {"text": rule.title},
                               "help": {"text": rule.recommendation}}
                              for rule in RULES] + [{"id": "DEP001", "name": "Known vulnerable dependency",
                               "shortDescription": {"text": "Known vulnerable dependency"}}]}},
                "results": [{"ruleId": f.rule_id, "level": severity[f.severity],
                             "message": {"text": f.message},
                             "partialFingerprints": {"repoSentinel/v1": f.fingerprint()},
                             "locations": [{"physicalLocation": {
                                 "artifactLocation": {"uri": f.path},
                                 "region": {"startLine": f.line}}}]}
                            for f in findings] + [{"ruleId": "DEP001", "level": "warning",
                             "message": {"text": f"{f.package}@{f.version} has advisory {f.advisory_id} ({f.ecosystem})"},
                             "partialFingerprints": {"repoSentinel/v1": hashlib.sha256(
                                 f"{f.manifest}\0{f.package}\0{f.version}\0{f.advisory_id}".encode()).hexdigest()},
                             "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.manifest},
                                 "region": {"startLine": 1}}}]}
                            for f in dependency_findings]
            }]
        }, indent=2)
    else:
        counts = {severity: sum(f.severity == severity for f in findings) for severity in ("high", "medium", "low")}
        rows = [f"Repo Sentinel · {root}",
                f"{len(findings)} finding(s): {counts['high']} high · {counts['medium']} medium · {counts['low']} low", ""]
        for finding in findings:
            rows.extend((f"[{finding.severity.upper()}] {finding.rule_id} {finding.title}",
                         f"  {finding.path}:{finding.line} — {finding.message}",
                         f"  Suggestion: {finding.recommendation}", f"  > {finding.excerpt}", ""))
        if not findings:
            rows.append("No findings. Heuristic scans cannot prove that code is secure or complete.")
        if args.dependencies:
            rows.extend((f"Dependency advisories: {len(dependency_findings)}", ""))
            for finding in dependency_findings:
                rows.append(f"[DEPENDENCY] {finding.advisory_id} {finding.package}@{finding.version} ({finding.ecosystem})")
                rows.append(f"  {finding.manifest} — {finding.url}")
        report = "\n".join(rows)
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(report)
    levels = {"never": 99, "low": 1, "medium": 2, "high": 3}
    weights = {"low": 1, "medium": 2, "high": 3}
    return 1 if (any(weights[f.severity] >= levels[args.fail_on] for f in findings)
                 or args.fail_on_dependency and bool(dependency_findings)) else 0


if __name__ == "__main__":
    raise SystemExit(main())
