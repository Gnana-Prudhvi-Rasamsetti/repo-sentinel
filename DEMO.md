# Repo Sentinel demo walkthrough

This 5–7 minute walkthrough demonstrates how Repo Sentinel reviews a repository without depending on that repository's architecture.

## Before the demo

Use Python 3.10 or newer. From the project root, install Repo Sentinel in editable mode:

```powershell
python -m pip install -e .
```

The demo target is `fixtures/sample-app`. It intentionally contains planted security and code-quality issues; it is a scanner fixture, not an application template. Do not add real credentials to it.

## 1. Scan the sample repository

```powershell
sentinel fixtures/sample-app
```

Point out that the scanner needs only a directory path. It reads the source and reports rule ID, severity, file and line, a code excerpt, and a suggested remediation. The fixture spans Python, JavaScript, Go, and Java, so it illustrates the language-aware checks without requiring four separate application runtimes.

Walk through a few representative findings:

- A credential-like hardcoded value (`SEC001`).
- A risky code construct, such as dynamic execution, shell execution, or unsafe deserialization, where present in the fixture.
- An unfinished-code marker or placeholder (`QUAL001`, `QUAL003`, or `QUAL005`).

Explain that findings are review leads. The scanner uses static heuristics and does not prove exploitability or correctness.

## 2. Show machine-readable output

```powershell
sentinel fixtures/sample-app --format json --output sentinel-report.json
```

Open `sentinel-report.json` and show that each finding has structured fields that another dashboard or CI system can consume. The report includes a severity summary and remediation text.

## 3. Show a CI gate

```powershell
sentinel fixtures/sample-app --fail-on high
```

The command returns exit code `1` when it finds a high-severity issue. That is the signal a CI job can use to block a change. Check the exit code in PowerShell with:

```powershell
$LASTEXITCODE
```

Use a clean repository or a reviewed baseline for normal development; the deliberately vulnerable fixture is expected to trip the gate.

## 4. Show baselines for existing findings

```powershell
sentinel fixtures/sample-app --write-baseline .sentinel-baseline.json
sentinel fixtures/sample-app --baseline .sentinel-baseline.json --fail-on high
```

The baseline lets a team gate newly introduced findings while it works through existing ones. Repo Sentinel fingerprints findings using the rule, relative path, and normalized excerpt, so line movement alone does not make an existing finding new.

## 5. Show SARIF integration

```powershell
sentinel fixtures/sample-app --format sarif --output sentinel.sarif
```

SARIF is a standard format that GitHub code scanning and other compatible tools can ingest. The project includes a GitHub Actions workflow that runs Repo Sentinel and uploads SARIF on supported events; see `.github/workflows/sentinel.yml`.

## Architecture in one minute

```text
CLI (src/sentinel/cli.py)
  ├─ loads configuration and baseline
  ├─ invokes repository scanner (src/sentinel/scanner.py)
  │    ├─ walks source files and applies exclusions
  │    └─ runs rule checks (src/sentinel/rules.py)
  ├─ optionally queries OSV for pinned dependency versions
  └─ formats text, JSON, or SARIF and returns a CI exit code
```

Because the input is a repository directory and the checks inspect source and supported manifests directly, Repo Sentinel is not tied to a web framework, service architecture, or hosted AI provider. Python AST checks and selected JavaScript/TypeScript, Java, and Go rules add language-specific analysis where available.

## Suggested closing

“Repo Sentinel is a lightweight, architecture-agnostic review agent. It surfaces explainable security and unfinished-code findings with file-level evidence, produces formats for people and automation, and can help teams focus CI on new high-severity issues. It is a useful review aid, not a substitute for human validation or a full security audit.”

## Demo notes

- Do not describe the checks as comprehensive or claim a clean scan proves a repository is secure.
- Use the included fixture to demonstrate detection. Its findings are intentionally planted.
- Dependency auditing is opt-in and needs network access: `sentinel fixtures/sample-app --dependencies`.
- See [EVALUATION.md](EVALUATION.md) for the current real-repository tuning notes and known limitations.
