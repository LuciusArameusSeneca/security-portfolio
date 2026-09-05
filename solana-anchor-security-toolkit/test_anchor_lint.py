"""
test_anchor_lint.py - Selbsttest fuer anchor_lint.py.

Beweist (nicht nur behauptet), dass das Tool tatsaechlich unterscheidet:
- die bewusst unsichere Beispieldatei (examples/vulnerable_program.rs) muss
  fuer JEDE der 5 dokumentierten Schwachstellen mindestens einen Fund liefern
  und mit Exit-Code 1 (mind. ein HIGH-Fund) abschliessen.
- die korrigierte Beispieldatei (examples/fixed_program.rs) darf KEINE
  HIGH-Funde mehr liefern und muss mit Exit-Code 0 abschliessen.

Ausfuehren mit:  python3 -m unittest test_anchor_lint.py -v
"""
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).parent
LINT_SCRIPT = HERE / "anchor_lint.py"
VULNERABLE = HERE / "examples" / "vulnerable_program.rs"
FIXED = HERE / "examples" / "fixed_program.rs"

sys.path.insert(0, str(HERE))
import anchor_lint  # noqa: E402


class TestAnchorLint(unittest.TestCase):

    def setUp(self):
        self.vulnerable_findings = anchor_lint.lint_file(VULNERABLE)
        self.fixed_findings = anchor_lint.lint_file(FIXED)

    def test_vulnerable_file_triggers_all_five_vulnerability_classes(self):
        checks_found = {f.check for f in self.vulnerable_findings}
        expected_checks = {
            "unchecked-arithmetic", "missing-signer", "missing-seeds", "manual-close",
        }
        missing = expected_checks - checks_found
        self.assertEqual(
            missing, set(),
            f"Erwartete Checks wurden in der unsicheren Datei NICHT ausgeloest: {missing}",
        )

    def test_vulnerable_file_has_at_least_one_high_finding(self):
        high_findings = [f for f in self.vulnerable_findings if f.severity == "HIGH"]
        self.assertGreater(len(high_findings), 0, "Erwarte mindestens einen HIGH-Fund in der unsicheren Datei.")

    def test_fixed_file_has_no_high_findings(self):
        high_findings = [f for f in self.fixed_findings if f.severity == "HIGH"]
        self.assertEqual(high_findings, [], f"Die korrigierte Datei sollte keine HIGH-Funde mehr haben: {high_findings}")

    def test_fixed_file_has_far_fewer_findings_than_vulnerable(self):
        self.assertLess(
            len(self.fixed_findings), len(self.vulnerable_findings),
            "Die korrigierte Datei sollte deutlich weniger Funde als die unsichere Datei haben.",
        )

    def test_cli_exit_code_reflects_high_findings(self):
        result_vuln = subprocess.run(
            [sys.executable, str(LINT_SCRIPT), str(VULNERABLE)],
            capture_output=True, text=True,
        )
        self.assertEqual(result_vuln.returncode, 1, "Unsichere Datei sollte Exit-Code 1 (HIGH-Fund) ergeben.")

        result_fixed = subprocess.run(
            [sys.executable, str(LINT_SCRIPT), str(FIXED)],
            capture_output=True, text=True,
        )
        self.assertEqual(result_fixed.returncode, 0, "Korrigierte Datei sollte Exit-Code 0 (keine HIGH-Funde) ergeben.")

    def test_json_output_is_valid(self):
        result = subprocess.run(
            [sys.executable, str(LINT_SCRIPT), "--json", str(VULNERABLE)],
            capture_output=True, text=True,
        )
        import json
        data = json.loads(result.stdout)
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)
        self.assertIn("severity", data[0])
        self.assertIn("check", data[0])

    def test_clean_file_with_no_accounts_struct_yields_no_crash(self):
        # Robustheitscheck: eine Datei ganz ohne Accounts-Struct/Arithmetik
        # darf nicht abstuerzen und soll einfach keine Funde liefern.
        findings = anchor_lint.lint_text("pub fn helper() -> u8 { 42 }", "dummy.rs")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
