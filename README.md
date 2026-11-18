# Repo Sentinel

Repo Sentinel is a small, architecture-agnostic review agent for finding common security risks and unfinished code in a repository. It uses explainable static heuristics, so it works across popular languages without requiring a particular framework, build system, or hosted AI service.

## Quick start

Requires Python 3.10 or newer. From this directory:

```powershell
python -m pip install -e .
sentinel .
```

Or run without installing:

```powershell
$env:PYTHONPATH = "src"
python -m sentinel.cli .
```

For a guided presentation using the intentionally vulnerable sample project, see [DEMO.md](DEMO.md).

## Use in automation

```powershell
sentinel ./my-repo --format json --output sentinel-report.json --fail-on high
sentinel ./my-repo --format sarif --output sentinel.sarif
```

The text report is meant for developers. JSON output includes each rule, severity, file, line, excerpt, and remediation suggestion so another CI system or dashboard can consume it. SARIF output can be uploaded to GitHub code scanning. `--fail-on` lets the scanner act as a CI gate; it is `never` by default.

Dependency checks are optional and require network access:

```powershell
sentinel . --dependencies --format json --fail-on-dependency
```

This queries the [OSV public API](https://google.github.io/osv.dev/api/) for exact versions found in npm `package-lock.json`, pinned `requirements*.txt`, and Go `go.mod` files. It does not resolve version ranges or inspect transitive dependencies unless they are present in a supported lockfile.

## Configuration

An optional `.sentinel.json` in the scan root supports glob patterns and rule IDs:

```json
{
  "exclude": ["**/generated/**", "**/fixtures/**"],
  "disable_rules": ["QUAL001"]
}
```

Use `--config path/to/config.json` to select another config. Exclusions are relative to the scan root. Unknown fields and invalid value types are reported as configuration errors.

To suppress one finding, add a directive on that line or the line immediately before it. Include a short reason:

```python
# sentinel: ignore QUAL001 -- tracked in issue SEC-14
# TODO: known follow-up
```

The directive only suppresses the named rule and requires a reason, so unrelated findings on the same line remain visible.

## Baselines

Capture existing findings and then gate only on new ones:

```powershell
sentinel . --write-baseline .sentinel-baseline.json
sentinel . --baseline .sentinel-baseline.json --fail-on high
```

Baseline identity uses the rule ID, relative path, and normalized source excerpt, so line movement alone does not make a finding new. If the relevant code changes, review the new finding and regenerate the baseline when appropriate.

The included `.github/workflows/sentinel.yml` runs the scan on pushes and pull requests, uploads SARIF on pushes and same-repository pull requests, archives it for all runs, and fails the job for high-severity findings. Fork pull requests get the SARIF artifact because GitHub does not grant the workflow the write token needed to publish code-scanning results for forks.

## Regression checks

Run the built-in checks with:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

The suite checks the planted findings in `fixtures/sample-app` and verifies that its clean examples stay unflagged.

## Current checks

| Rule | What it looks for |
| --- | --- |
| SEC001 | Credential-like hardcoded values |
| SEC002 | Dynamic `eval`/`exec` calls |
| SEC003 | Shell-enabled process execution |
| SEC004 | Disabled TLS verification |
| SEC005 | MD5/SHA-1 use |
| SEC006 | Likely interpolated SQL calls |
| SEC007 | Unsafe deserialization APIs |
| SEC008 | Wildcard CORS policies |
| SEC009 | Predictable randomness used for secret values |
| SEC010 | User-controlled URLs passed to server-side HTTP clients |
| SEC011 | Archive extraction path traversal risks |
| SEC012 | Go shell command strings |
| SEC013 | Django debug mode enabled |
| SEC014 | Django wildcard host allowlist |
| QUAL001 | TODO/FIXME/HACK/XXX markers |
| QUAL002 | Debug output or debugger statements |
| QUAL003 | Placeholder/unimplemented paths |
| QUAL004 | Silently swallowed exceptions |
| QUAL005 | Explicitly unimplemented paths |
| QUAL006 | Possibly unused Python imports |

## Design

Repo Sentinel is architecture agnostic: point it at a source repository and it scans files directly. It does not need the target application's framework, build system, database, or runtime. The scanner separates repository walking, rule definitions, language-aware checks, and report formatting. Most checks are language-neutral heuristics; Python files also receive AST checks for dynamic execution, swallowed bare exceptions, unused imports, and YAML loader safety. SQL checks in JavaScript/TypeScript and Java track simple request-derived variables within one file. It skips common generated/dependency directories and files larger than 1 MB. Current fixture coverage includes Python, JavaScript, Go, and Java.

The run follows this path:

```text
Repository path
      ↓
File walker and exclusions
      ↓
Security and code-quality rules
      ↓
Findings with evidence and remediation
      ↓
Text, JSON, or SARIF report
      ↓
Optional baseline and CI severity gate
```

## Limits

This is a lightweight static-analysis agent, not a proof of security or correctness. Python AST checks reduce comment/string false positives for selected rules; most cross-language checks remain line-based heuristics. Request-data tracking is intrafile and covers selected SQL patterns only; it does not trace across method or file boundaries. Dependency checks require an explicit OSV query, and secret-provider integrations are not included. Review findings before acting on them; absence of findings does not mean a repository is safe. The bundled fixtures provide representative evaluation, but results should still be reviewed against the frameworks and languages used in each target repository.
