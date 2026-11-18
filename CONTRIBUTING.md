# Contributing

## Report scanner feedback

Use the GitHub issue form for a [false positive](.github/ISSUE_TEMPLATE/false-positive.yml) or a [missed finding](.github/ISSUE_TEMPLATE/missed-pattern.yml). Provide a small sanitized example, the language/framework, and the behavior you expected. Never post real credentials, private source, or personal data.

## Change a rule

1. Add a minimal positive and a clean counterexample to `fixtures/sample-app` or a focused temporary-repository test.
2. Keep the rule explanation and remediation actionable; note language-specific assumptions.
3. Run `python -m unittest discover -s tests -v` with `PYTHONPATH=src`.
4. Review scans of the evaluation repositories in `EVALUATION.md` for regressions.

## Dependency checks

Dependency auditing sends package names and exact versions from supported manifests to the public OSV API only when `--dependencies` is requested. Do not include private package names in an audit without first considering that disclosure.
