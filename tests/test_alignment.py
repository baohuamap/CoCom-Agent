# File: tests/test_alignment.py

"""
Unit tests for CPGAlignmentLayer and CodeQLToJoernAligner.

The Neo4j driver is mocked throughout — no live database required.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.core.alignment import CPGAlignmentLayer, CodeQLToJoernAligner


# ---------------------------------------------------------------------------
# CPGAlignmentLayer
# ---------------------------------------------------------------------------

class TestCPGAlignmentLayer:

    @patch("src.core.alignment.GraphDatabase")
    def test_get_joern_nodes_returns_set_of_ids(self, MockGDB):
        mock_driver = MagicMock()
        MockGDB.driver.return_value = mock_driver

        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)

        mock_session.run.return_value = [
            {"node_id": 101},
            {"node_id": 202},
        ]

        aligner = CPGAlignmentLayer()
        result = aligner.get_joern_nodes("app/views.py", 42)

        assert result == {101, 202}
        mock_session.run.assert_called_once()
        call_kwargs = mock_session.run.call_args
        assert call_kwargs[1]["line"] == 42
        assert call_kwargs[1]["file"] == "views.py"  # basename only

    @patch("src.core.alignment.GraphDatabase")
    def test_get_joern_nodes_returns_empty_set_when_no_match(self, MockGDB):
        mock_driver = MagicMock()
        MockGDB.driver.return_value = mock_driver

        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.run.return_value = []

        aligner = CPGAlignmentLayer()
        result = aligner.get_joern_nodes("unknown/file.py", 999)
        assert result == set()

    @patch("src.core.alignment.GraphDatabase")
    def test_close_delegates_to_driver(self, MockGDB):
        mock_driver = MagicMock()
        MockGDB.driver.return_value = mock_driver
        aligner = CPGAlignmentLayer()
        aligner.close()
        mock_driver.close.assert_called_once()

    @patch("src.core.alignment.GraphDatabase")
    def test_uses_env_credentials(self, MockGDB, monkeypatch):
        monkeypatch.setenv("NEO4J_URI", "bolt://custom:9999")
        monkeypatch.setenv("NEO4J_USER", "testuser")
        monkeypatch.setenv("NEO4J_PASSWORD", "testpass")

        CPGAlignmentLayer()
        MockGDB.driver.assert_called_once_with(
            "bolt://custom:9999", auth=("testuser", "testpass")
        )


# ---------------------------------------------------------------------------
# CodeQLToJoernAligner — SARIF parsing
# ---------------------------------------------------------------------------

class TestCodeQLToJoernAlignerSARIF:

    @patch("src.core.alignment.GraphDatabase")
    def test_load_sarif_extracts_findings(self, MockGDB, tmp_path):
        sarif = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "CWE-89",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/app.py"},
                                        "region": {"startLine": 10, "startColumn": 5},
                                    }
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        sarif_file = tmp_path / "result.sarif"
        sarif_file.write_text(json.dumps(sarif))

        MockGDB.driver.return_value = MagicMock()
        aligner = CodeQLToJoernAligner()
        findings = aligner.load_sarif(str(sarif_file))

        assert len(findings) == 1
        assert findings[0]["rule_id"] == "CWE-89"
        assert findings[0]["file"] == "src/app.py"
        assert findings[0]["line"] == 10
        assert findings[0]["col"] == 5

    @patch("src.core.alignment.GraphDatabase")
    def test_load_sarif_empty_runs(self, MockGDB, tmp_path):
        sarif_file = tmp_path / "empty.sarif"
        sarif_file.write_text(json.dumps({"runs": []}))

        MockGDB.driver.return_value = MagicMock()
        aligner = CodeQLToJoernAligner()
        assert aligner.load_sarif(str(sarif_file)) == []
