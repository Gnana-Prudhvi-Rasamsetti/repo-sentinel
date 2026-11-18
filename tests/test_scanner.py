"""Regression checks for the bundled cross-language evaluation fixture."""

from pathlib import Path
from dataclasses import replace
import json
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from sentinel.dependencies import audit_dependencies, parse_dependencies
from sentinel.scanner import load_baseline, scan, write_baseline


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "fixtures" / "sample-app"


class ScannerRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = scan(SAMPLE)

    def test_planted_security_and_quality_issues_are_reported(self):
        rule_ids = {finding.rule_id for finding in self.findings}
        self.assertTrue({
            "SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006",
            "SEC007", "SEC008", "SEC009", "QUAL001", "QUAL002", "QUAL004", "QUAL005",
            "SEC010", "SEC011", "SEC012", "SEC013", "SEC014", "QUAL006",
        }.issubset(rule_ids))

    def test_multiline_silent_exception_is_reported_at_except_line(self):
        matches = [finding for finding in self.findings
                   if finding.rule_id == "QUAL004" and finding.path == "app.py"]
        self.assertEqual([28], [finding.line for finding in matches])

    def test_clean_examples_have_no_findings(self):
        self.assertFalse([finding for finding in self.findings if finding.path == "clean.py"])

    def test_suppression_requires_a_rule_and_reason(self):
        source = '''# sentinel: ignore QUAL001 -- tracked in issue SEC-14\n# TODO: known follow-up\n# sentinel: ignore SEC002 -- input is a trusted expression\neval(expression)\n# sentinel: ignore SEC001\nAPI_KEY = "literal_example_key_12345"\n'''
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "example.py").write_text(source, encoding="utf-8")
            findings = scan(root)
        reported = {finding.rule_id for finding in findings}
        self.assertNotIn("QUAL001", reported)
        self.assertNotIn("SEC002", reported)
        self.assertIn("SEC001", reported)

    def test_python_ast_checks_ignore_comments(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "comment_only.py").write_text("# eval(user_input)\n# except:\n#     pass\n", encoding="utf-8")
            self.assertFalse(scan(root))

    def test_yaml_loader_rule_is_python_aware(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "unsafe.py").write_text("import yaml\nvalue = yaml.load(content)\n", encoding="utf-8")
            (root / "safe.py").write_text("import yaml\nvalue = yaml.load(content, Loader=yaml.SafeLoader)\n", encoding="utf-8")
            self.assertEqual([("unsafe.py", "SEC007")],
                             [(finding.path, finding.rule_id) for finding in scan(root)])

    def test_javascript_rules_avoid_common_non_findings(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "example.js").write_text(
                "const result = regexp.exec(input);\nconsole.log('request complete');\n"
                "const field = '<input placeholder=\"Email\">';\n",
                encoding="utf-8",
            )
            self.assertFalse(scan(root))

    def test_sql_check_tracks_request_data_and_ignores_untainted_ids(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "routes.ts").write_text(
                "const criteria = req.query.q;\nsequelize.query(`SELECT * FROM items WHERE name='${criteria}'`);\n",
                encoding="utf-8")
            (root / "repository.java").write_text(
                'String petId = pet.getId().toString();\nem.createQuery("DELETE FROM Pet WHERE id=" + petId);\n',
                encoding="utf-8")
            (root / "controller.java").write_text(
                'void search(@RequestParam String term) {\n'
                'entityManager.createQuery("FROM Item WHERE name=" + term);\n}\n', encoding="utf-8")
            matches = [(finding.path, finding.rule_id) for finding in scan(root)]
        self.assertEqual([("controller.java", "SEC006"), ("routes.ts", "SEC006")], matches)

    def test_baseline_fingerprint_survives_line_movement(self):
        finding = self.findings[0]
        moved = replace(finding, line=finding.line + 20)
        with TemporaryDirectory() as temp_dir:
            baseline = Path(temp_dir) / "baseline.json"
            write_baseline(baseline, [finding])
            self.assertIn(moved.fingerprint(), load_baseline(baseline))

    def test_dependency_manifest_parsers_find_pinned_packages(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "package-lock.json").write_text(
                '{"lockfileVersion":3,"packages":{"":{"name":"demo"},'
                '"node_modules/lodash":{"version":"4.17.20"}}}', encoding="utf-8")
            (root / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
            (root / "go.mod").write_text("module example.com/demo\nrequire github.com/example/lib v1.2.3\n", encoding="utf-8")
            dependencies = {(item.ecosystem, item.name, item.version) for item in parse_dependencies(root)}
        self.assertEqual({("npm", "lodash", "4.17.20"), ("PyPI", "requests", "2.31.0"),
                          ("Go", "github.com/example/lib", "v1.2.3")}, dependencies)

    def test_osv_batch_response_becomes_dependency_findings(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "requirements.txt").write_text("demo==1.0.0\n", encoding="utf-8")
            response = unittest.mock.MagicMock()
            response.__enter__.return_value.read.return_value = json.dumps(
                {"results": [{"vulns": [{"id": "GHSA-demo-1234"}]}]}).encode()
            with patch("sentinel.dependencies.urlopen", return_value=response):
                findings = audit_dependencies(root)
        self.assertEqual("GHSA-demo-1234", findings[0].advisory_id)
        self.assertEqual("demo", findings[0].package)

    def test_go_and_java_fixtures_are_scanned(self):
        pairs = {(finding.rule_id, finding.path) for finding in self.findings}
        self.assertIn(("SEC004", "service.go"), pairs)
        self.assertIn(("SEC012", "service.go"), pairs)
        self.assertNotIn(("SEC006", "DataAccess.java"), pairs)


if __name__ == "__main__":
    unittest.main()
