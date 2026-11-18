"""Optional dependency advisory lookups through the OSV public API."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import fnmatch
import json
from pathlib import Path
import re
from urllib.request import Request, urlopen

from .scanner import IGNORED_DIRS


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    manifest: str


@dataclass(frozen=True)
class DependencyFinding:
    advisory_id: str
    package: str
    version: str
    ecosystem: str
    manifest: str
    url: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def parse_dependencies(root: Path, exclusions: list[str] | None = None) -> list[Dependency]:
    """Read exact versions from supported lockfiles and pinned requirements."""
    exclusions = exclusions or []
    packages: set[Dependency] = set()
    for manifest in root.rglob("*"):
        if not manifest.is_file() or any(part in IGNORED_DIRS for part in manifest.relative_to(root).parts):
            continue
        relative = manifest.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(relative, pattern) for pattern in exclusions):
            continue
        try:
            if manifest.name == "package-lock.json":
                data = json.loads(manifest.read_text(encoding="utf-8"))
                entries = data.get("packages")
                if isinstance(entries, dict):
                    for install_path, item in entries.items():
                        if install_path and isinstance(item, dict) and item.get("version"):
                            name = item.get("name") or install_path.rsplit("node_modules/", 1)[-1]
                            packages.add(Dependency(name, str(item["version"]), "npm", relative))
                else:
                    def walk(dependencies: object) -> None:
                        if not isinstance(dependencies, dict):
                            return
                        for name, item in dependencies.items():
                            if isinstance(item, dict):
                                if item.get("version"):
                                    packages.add(Dependency(name, str(item["version"]), "npm", relative))
                                walk(item.get("dependencies"))
                    walk(data.get("dependencies"))
            elif manifest.name.startswith("requirements") and manifest.suffix == ".txt":
                for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
                    match = re.match(r"\s*([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*==\s*([A-Za-z0-9_.+!-]+)", line)
                    if match:
                        packages.add(Dependency(match.group(1), match.group(2), "PyPI", relative))
            elif manifest.name == "go.mod":
                in_require = False
                for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
                    stripped = line.split("//", 1)[0].strip()
                    if stripped.startswith("require ("):
                        in_require = True
                        continue
                    if in_require and stripped == ")":
                        in_require = False
                        continue
                    candidate = stripped[len("require "):].strip() if stripped.startswith("require ") else stripped
                    match = re.match(r"([A-Za-z0-9._~!+/-]+)\s+(v[0-9][^\s]*)", candidate)
                    if match and (in_require or stripped.startswith("require ")):
                        packages.add(Dependency(match.group(1), match.group(2), "Go", relative))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
    return sorted(packages, key=lambda item: (item.ecosystem, item.name.lower(), item.version, item.manifest))


def audit_dependencies(root: Path, exclusions: list[str] | None = None) -> list[DependencyFinding]:
    """Query OSV in batches; network access is used only when explicitly requested."""
    packages = parse_dependencies(root, exclusions)
    findings: list[DependencyFinding] = []
    for start in range(0, len(packages), 100):
        batch = packages[start:start + 100]
        payload = {"queries": [{"package": {"name": item.name, "ecosystem": item.ecosystem},
                                "version": item.version} for item in batch]}
        request = Request("https://api.osv.dev/v1/querybatch", data=json.dumps(payload).encode("utf-8"),
                          headers={"Content-Type": "application/json", "User-Agent": "repo-sentinel/0.1.0"},
                          method="POST")
        with urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
        for package, response_item in zip(batch, result.get("results", [])):
            for advisory in response_item.get("vulns", []):
                advisory_id = advisory.get("id")
                if advisory_id:
                    findings.append(DependencyFinding(
                        advisory_id=advisory_id, package=package.name, version=package.version,
                        ecosystem=package.ecosystem, manifest=package.manifest,
                        url=f"https://osv.dev/vulnerability/{advisory_id}"))
    return findings
