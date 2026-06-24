"""
Tests for tools/sarif.py — SARIF 2.1.0 document generation.

All tests are fully offline: no network, no API keys, no file I/O.
findings_to_sarif() is a pure function; tests cover:
  - Document structure (version, $schema, runs shape)
  - Rule derivation from distinct CWE identifiers
  - Result mapping (ruleId, level, startLine)
  - Severity → SARIF level mapping
  - Empty findings list (valid empty results)
  - Edge cases: missing fields, unparseable line numbers, no CWE
"""
from __future__ import annotations

import pytest

from tools.sarif import findings_to_sarif


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    title: str = "Test Finding",
    severity: str = "HIGH",
    description: str = "A vulnerability",
    file_path: str = "src/app.py",
    lines: str = "42",
    cwe: str = "CWE-89",
    fix: str = "Use parameterised queries",
) -> dict:
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "file_path": file_path,
        "lines": lines,
        "cwe": cwe,
        "fix": fix,
    }


# ---------------------------------------------------------------------------
# Document structure
# ---------------------------------------------------------------------------

class TestDocumentStructure:
    def test_version_is_2_1_0(self):
        doc = findings_to_sarif([])
        assert doc["version"] == "2.1.0"

    def test_schema_field_present(self):
        doc = findings_to_sarif([])
        assert "$schema" in doc
        assert "sarif" in doc["$schema"].lower() or "oasis" in doc["$schema"].lower()

    def test_runs_is_a_list_with_one_run(self):
        doc = findings_to_sarif([])
        assert isinstance(doc["runs"], list)
        assert len(doc["runs"]) == 1

    def test_tool_driver_name(self):
        doc = findings_to_sarif([])
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver["name"] == "vulnscan-agent"

    def test_tool_driver_has_information_uri(self):
        doc = findings_to_sarif([])
        driver = doc["runs"][0]["tool"]["driver"]
        assert "informationUri" in driver
        assert driver["informationUri"]  # non-empty string


# ---------------------------------------------------------------------------
# Empty findings list
# ---------------------------------------------------------------------------

class TestEmptyFindings:
    def test_empty_results_list(self):
        doc = findings_to_sarif([])
        results = doc["runs"][0]["results"]
        assert isinstance(results, list)
        assert results == []

    def test_empty_rules_list(self):
        doc = findings_to_sarif([])
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert isinstance(rules, list)
        assert rules == []

    def test_valid_sarif_structure_when_empty(self):
        """Minimal structural check: all required top-level keys present."""
        doc = findings_to_sarif([])
        assert set(doc.keys()) >= {"version", "$schema", "runs"}


# ---------------------------------------------------------------------------
# Rule derivation
# ---------------------------------------------------------------------------

class TestRuleDerivation:
    def test_one_rule_per_distinct_cwe(self):
        findings = [
            _make_finding(cwe="CWE-89"),
            _make_finding(cwe="CWE-79"),
            _make_finding(cwe="CWE-89"),  # duplicate — should not produce extra rule
        ]
        doc = findings_to_sarif(findings)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert sorted(rule_ids) == ["CWE-79", "CWE-89"]

    def test_rule_has_required_fields(self):
        doc = findings_to_sarif([_make_finding(cwe="CWE-22")])
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert "id" in rule
        assert "name" in rule
        assert "shortDescription" in rule
        assert "text" in rule["shortDescription"]

    def test_no_cwe_produces_no_cwe_rule(self):
        doc = findings_to_sarif([_make_finding(cwe="")])
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        ids = [r["id"] for r in rules]
        assert "NO_CWE" in ids

    def test_multiple_no_cwe_findings_share_one_rule(self):
        findings = [_make_finding(cwe=""), _make_finding(cwe="")]
        doc = findings_to_sarif(findings)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        no_cwe_rules = [r for r in rules if r["id"] == "NO_CWE"]
        assert len(no_cwe_rules) == 1


# ---------------------------------------------------------------------------
# Result mapping
# ---------------------------------------------------------------------------

class TestResultMapping:
    def test_one_result_per_finding(self):
        findings = [_make_finding(), _make_finding(title="Another")]
        doc = findings_to_sarif(findings)
        assert len(doc["runs"][0]["results"]) == 2

    def test_result_rule_id_matches_cwe(self):
        doc = findings_to_sarif([_make_finding(cwe="CWE-78")])
        result = doc["runs"][0]["results"][0]
        assert result["ruleId"] == "CWE-78"

    def test_result_has_message_text(self):
        doc = findings_to_sarif([_make_finding(title="SQL Injection", description="Bad SQL")])
        result = doc["runs"][0]["results"][0]
        assert "text" in result["message"]
        assert "SQL Injection" in result["message"]["text"]

    def test_result_location_uri(self):
        doc = findings_to_sarif([_make_finding(file_path="app/auth.py")])
        loc = doc["runs"][0]["results"][0]["locations"][0]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "app/auth.py"

    def test_result_start_line_parsed_from_integer_string(self):
        doc = findings_to_sarif([_make_finding(lines="57")])
        loc = doc["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["region"]["startLine"] == 57

    def test_result_start_line_parsed_from_range_string(self):
        doc = findings_to_sarif([_make_finding(lines="42-45")])
        loc = doc["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["region"]["startLine"] == 42

    def test_result_start_line_defaults_to_1_when_unparseable(self):
        doc = findings_to_sarif([_make_finding(lines="unknown")])
        loc = doc["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["region"]["startLine"] == 1

    def test_result_start_line_defaults_to_1_when_empty(self):
        doc = findings_to_sarif([_make_finding(lines="")])
        loc = doc["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["region"]["startLine"] == 1

    def test_result_location_uses_placeholder_when_no_file(self):
        doc = findings_to_sarif([_make_finding(file_path="")])
        loc = doc["runs"][0]["results"][0]["locations"][0]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri  # not empty — uses placeholder


# ---------------------------------------------------------------------------
# Severity → SARIF level mapping
# ---------------------------------------------------------------------------

class TestSeverityLevelMapping:
    def test_critical_maps_to_error(self):
        doc = findings_to_sarif([_make_finding(severity="CRITICAL")])
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_high_maps_to_error(self):
        doc = findings_to_sarif([_make_finding(severity="HIGH")])
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_medium_maps_to_warning(self):
        doc = findings_to_sarif([_make_finding(severity="MEDIUM")])
        assert doc["runs"][0]["results"][0]["level"] == "warning"

    def test_low_maps_to_note(self):
        doc = findings_to_sarif([_make_finding(severity="LOW")])
        assert doc["runs"][0]["results"][0]["level"] == "note"

    def test_unknown_severity_maps_to_note(self):
        """Unknown severity should degrade gracefully to "note"."""
        doc = findings_to_sarif([_make_finding(severity="UNKNOWN")])
        assert doc["runs"][0]["results"][0]["level"] == "note"


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

class TestInputValidation:
    def test_raises_on_non_list_input(self):
        with pytest.raises(ValueError, match="list"):
            findings_to_sarif({"not": "a list"})  # type: ignore[arg-type]

    def test_raises_on_none_input(self):
        with pytest.raises((ValueError, TypeError)):
            findings_to_sarif(None)  # type: ignore[arg-type]
