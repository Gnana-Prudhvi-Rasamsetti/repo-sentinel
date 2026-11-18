# Release checklist

1. Update the version in `pyproject.toml` and `src/sentinel/__init__.py`.
2. Run `python -m unittest discover -s tests -v` with `PYTHONPATH=src` in a clean environment.
3. Run the CLI against the repository and the evaluation fixture; review changes in both reports.
4. Build a wheel and source archive with `python -m build` in an environment with the `build` package installed.
5. Inspect the artifacts and release notes, then publish through the project's chosen package registry.

Releases should include the supported Python range, rule changes, known heuristic limitations, and any baseline or SARIF compatibility notes.
