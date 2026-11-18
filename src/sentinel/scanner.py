"""Repository walking and finding generation."""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
import fnmatch
import hashlib
import json
from pathlib import Path
import re
from typing import Iterable

from .rules import RULES

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".kt", ".kts",
    ".go", ".rs", ".c", ".h", ".cc", ".cpp", ".cs", ".php", ".rb", ".swift", ".scala",
    ".sh", ".bash", ".sql", ".yaml", ".yml", ".json", ".toml", ".env", ".html", ".vue", ".svelte",
}
IGNORED_DIRS = {".git", ".venv", ".build-tools", "venv", "node_modules", "vendor", "dist", "build", "coverage", "__pycache__"}
MAX_FILE_BYTES = 1_000_000
SUPPRESSION = re.compile(r"sentinel:\s*ignore\s+([A-Z]+\d{3})\s+--\s+\S", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    message: str
    recommendation: str
    path: str
    line: int
    excerpt: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def fingerprint(self) -> str:
        identity = "\0".join((self.rule_id, self.path, " ".join(self.excerpt.split())))
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def load_baseline(path: Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("fingerprints"), list):
        raise ValueError("Baseline must have schema 1 and a fingerprints array")
    if not all(isinstance(value, str) for value in data["fingerprints"]):
        raise ValueError("Baseline fingerprints must be strings")
    return set(data["fingerprints"])


def write_baseline(path: Path, findings: list[Finding]) -> None:
    data = {"schema": 1, "fingerprints": sorted({finding.fingerprint() for finding in findings})}
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load_config(config_path: Path | None) -> dict[str, object]:
    """Load optional JSON configuration, validating its supported fields."""
    if config_path is None or not config_path.exists():
        return {"exclude": [], "disable_rules": []}
    data = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Configuration must be a JSON object")
    for key in ("exclude", "disable_rules"):
        if key in data and (not isinstance(data[key], list) or not all(isinstance(v, str) for v in data[key])):
            raise ValueError(f"'{key}' must be an array of strings")
    unknown = set(data) - {"exclude", "disable_rules"}
    if unknown:
        raise ValueError(f"Unknown configuration field(s): {', '.join(sorted(unknown))}")
    return {"exclude": data.get("exclude", []), "disable_rules": data.get("disable_rules", [])}


def _files(root: Path, exclusions: list[str]) -> Iterable[Path]:
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if not path.is_file() or any(part in IGNORED_DIRS for part in path.relative_to(root).parts):
            continue
        if any(fnmatch.fnmatch(relative, pattern) for pattern in exclusions):
            continue
        if path.suffix.lower() in SOURCE_EXTENSIONS or path.name == ".env":
            try:
                if path.stat().st_size <= MAX_FILE_BYTES:
                    yield path
            except OSError:
                continue


def _tainted_names(lines: list[str], suffix: str) -> set[str]:
    """Track simple request-derived variables for SQL checks in JS/TS and Java."""
    source = re.compile(r"\b(?:req|request)\.(?:body|query|params|headers)\b|\.getParameter\s*\(")
    tainted: set[str] = set()
    if suffix.lower() == ".java":
        for line in lines:
            tainted.update(re.findall(
                r"@(?:RequestParam|PathVariable)(?:\([^)]*\))?\s+(?:String|int|long|Integer|Long)\s+(\w+)", line))
    assignment = re.compile(r"\b(?:const|let|var)?\s*([A-Za-z_$]\w*)\s*(?::[^=;]+)?\s*=\s*(.*)")
    changed = True
    while changed:
        changed = False
        for line in lines:
            match = assignment.search(line)
            if not match:
                continue
            rhs = match.group(2)
            if source.search(rhs) or any(re.search(rf"\b{re.escape(name)}\b", rhs) for name in tainted):
                if match.group(1) not in tainted:
                    tainted.add(match.group(1))
                    changed = True
    return tainted


def scan(root: Path, config: dict[str, object] | None = None) -> list[Finding]:
    config = config or {"exclude": [], "disable_rules": []}
    exclusions = config.get("exclude", [])
    disabled = set(config.get("disable_rules", []))
    findings: list[Finding] = []
    for path in _files(root, exclusions):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        tainted = _tainted_names(lines, path.suffix)
        for index, line in enumerate(lines):
            line_number = index + 1
            for rule in RULES:
                if rule.id in disabled:
                    continue
                if rule.id == "SEC006" and path.suffix.lower() in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java"}:
                    direct_source = re.search(
                        r"\b(?:req|request)\.(?:body|query|params|headers)\b|\.getParameter\s*\(", line)
                    if not direct_source and not any(re.search(rf"\b{re.escape(name)}\b", line) for name in tainted):
                        continue
                if path.suffix.lower() == ".py" and rule.id in {"SEC002", "QUAL004"}:
                    continue
                directive_lines = [line]
                if index > 0:
                    directive_lines.append(lines[index - 1])
                if any(match.group(1).upper() == rule.id
                       for candidate in directive_lines
                       for match in SUPPRESSION.finditer(candidate)):
                    continue
                matched = bool(rule.pattern.search(line))
                if matched:
                    findings.append(Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        category=rule.category,
                        message=rule.message,
                        recommendation=rule.recommendation,
                        path=path.relative_to(root).as_posix(),
                        line=line_number,
                        excerpt=line.strip()[:240],
                    ))
        if path.suffix.lower() == ".py":
            try:
                tree = ast.parse("\n".join(lines), filename=str(path))
            except SyntaxError:
                tree = None
            if tree is not None:
                by_id = {rule.id: rule for rule in RULES}
                for node in ast.walk(tree):
                    rule_id = None
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                        rule_id = "SEC002"
                    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                          and isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml"
                          and node.func.attr == "load"):
                        loader = next((keyword.value for keyword in node.keywords if keyword.arg == "Loader"), None)
                        loader_name = loader.id if isinstance(loader, ast.Name) else (
                            loader.attr if isinstance(loader, ast.Attribute) else None)
                        if loader_name not in {"SafeLoader", "CSafeLoader", "FullLoader", "CFullLoader"}:
                            rule_id = "SEC007"
                    elif (isinstance(node, ast.ExceptHandler) and node.type is None
                          and len(node.body) == 1
                          and (isinstance(node.body[0], ast.Pass)
                               or isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant)
                               and node.body[0].value.value is Ellipsis)):
                        rule_id = "QUAL004"
                    if rule_id is None or rule_id in disabled:
                        continue
                    lineno = node.lineno
                    directive_lines = [lines[lineno - 1]]
                    if lineno > 1:
                        directive_lines.append(lines[lineno - 2])
                    if any(match.group(1).upper() == rule_id
                           for candidate in directive_lines
                           for match in SUPPRESSION.finditer(candidate)):
                        continue
                    rule = by_id[rule_id]
                    findings.append(Finding(
                        rule_id=rule.id, title=rule.title, severity=rule.severity,
                        category=rule.category, message=rule.message,
                        recommendation=rule.recommendation,
                        path=path.relative_to(root).as_posix(), line=lineno,
                        excerpt=lines[lineno - 1].strip()[:240],
                    ))
                if "QUAL006" not in disabled:
                    imported: list[tuple[str, int]] = []
                    referenced = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                bound_name = alias.asname or alias.name.split(".")[0]
                                imported.append((bound_name, node.lineno))
                        elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
                            imported.extend((alias.asname or alias.name, node.lineno)
                                            for alias in node.names if alias.name != "*")
                    rule = next(item for item in RULES if item.id == "QUAL006")
                    reported_lines: set[int] = set()
                    for name, lineno in imported:
                        if name.startswith("_") or name in referenced or lineno in reported_lines:
                            continue
                        directive_lines = [lines[lineno - 1]]
                        if lineno > 1:
                            directive_lines.append(lines[lineno - 2])
                        if any(match.group(1).upper() == rule.id
                               for candidate in directive_lines
                               for match in SUPPRESSION.finditer(candidate)):
                            continue
                        findings.append(Finding(
                            rule_id=rule.id, title=rule.title, severity=rule.severity,
                            category=rule.category, message=rule.message,
                            recommendation=rule.recommendation,
                            path=path.relative_to(root).as_posix(), line=lineno,
                            excerpt=lines[lineno - 1].strip()[:240],
                        ))
                        reported_lines.add(lineno)
    return sorted(findings, key=lambda item: (item.path, item.line, item.rule_id))
