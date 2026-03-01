# File: tests/test_orchestrator.py

"""
Unit tests for CoComOrchestrator.

External dependencies (Neo4j, Joern, CodeQL, OpenAI) are mocked so the
tests execute without any live infrastructure.
"""

import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.orchestrator import (
    CodeLocation,
    CoComOrchestrator,
    VulnerabilityHypothesis,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def orchestrator(tmp_path):
    return CoComOrchestrator(
        repo_path=str(tmp_path / "repo"),
        working_dir=str(tmp_path / "work"),
        language="python",
    )


@pytest.fixture
def sarif_fixture(tmp_path):
    """Writes a minimal codeFlows SARIF file and returns its path."""
    sarif = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "CWE-89",
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {"uri": "app/views.py"},
                                                        "region": {"startLine": 42},
                                                    }
                                                }
                                            },
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {"uri": "app/db.py"},
                                                        "region": {"startLine": 17},
                                                    }
                                                }
                                            },
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                ]
            }
        ]
    }
    sarif_path = tmp_path / "work" / "codeql_python.sarif"
    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    sarif_path.write_text(json.dumps(sarif))
    return sarif_path


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestCoComOrchestratorInit:

    def test_invalid_language_raises(self, tmp_path):
        with pytest.raises(ValueError, match="Supported languages"):
            CoComOrchestrator(str(tmp_path), str(tmp_path), language="rust")

    def test_valid_languages_accepted(self, tmp_path):
        for lang in ("python", "java"):
            orc = CoComOrchestrator(str(tmp_path), str(tmp_path / lang), language=lang)
            assert orc.language == lang

    def test_working_dir_created(self, tmp_path):
        work = tmp_path / "nested" / "work"
        CoComOrchestrator(str(tmp_path), str(work), language="python")
        assert work.exists()


# ---------------------------------------------------------------------------
# SARIF Parsing
# ---------------------------------------------------------------------------

class TestSARIFParsing:

    def test_parse_sarif_populates_hypotheses(self, orchestrator, sarif_fixture):
        orchestrator.sarif_path = sarif_fixture
        orchestrator._parse_sarif()

        assert len(orchestrator.initial_hypotheses) == 1
        hyp = orchestrator.initial_hypotheses[0]
        assert hyp.rule_id == "CWE-89"
        assert hyp.source.line_number == 42
        assert hyp.sink.line_number == 17

    def test_parse_sarif_skips_single_location(self, orchestrator, tmp_path):
        """A codeFlow with only one step produces no hypothesis (need source + sink)."""
        sarif = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "CWE-78",
                            "codeFlows": [
                                {
                                    "threadFlows": [
                                        {
                                            "locations": [
                                                {
                                                    "location": {
                                                        "physicalLocation": {
                                                            "artifactLocation": {"uri": "app.py"},
                                                            "region": {"startLine": 5},
                                                        }
                                                    }
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        p = orchestrator.sarif_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(sarif))
        orchestrator._parse_sarif()
        assert len(orchestrator.initial_hypotheses) == 0

    def test_parse_sarif_fallback_to_related_locations(self, orchestrator, tmp_path):
        """When codeFlows is absent, relatedLocations[0]+locations[0] is used."""
        sarif = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "CWE-78",
                            "relatedLocations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app/source.py"},
                                        "region": {"startLine": 10},
                                    }
                                }
                            ],
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app/sink.py"},
                                        "region": {"startLine": 20},
                                    }
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        p = orchestrator.sarif_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(sarif))
        orchestrator._parse_sarif()
        assert len(orchestrator.initial_hypotheses) == 1
        hyp = orchestrator.initial_hypotheses[0]
        assert hyp.source.line_number == 10
        assert hyp.sink.line_number == 20

    def test_parse_sarif_missing_file_is_noop(self, orchestrator):
        orchestrator.sarif_path = Path("/nonexistent/path.sarif")
        orchestrator._parse_sarif()  # must not raise
        assert orchestrator.initial_hypotheses == []


# ---------------------------------------------------------------------------
# Alignment (mocked Neo4j)
# ---------------------------------------------------------------------------

class TestExtractAndAlign:

    @patch("src.core.orchestrator.CPGAlignmentLayer")
    def test_alignment_populates_node_ids(self, MockAligner, orchestrator, sarif_fixture):
        orchestrator.sarif_path = sarif_fixture

        mock_aligner = MagicMock()
        mock_aligner.get_joern_nodes.side_effect = [{101, 102}, {201}]
        MockAligner.return_value = mock_aligner

        with patch.object(orchestrator, "_run_joern", new_callable=AsyncMock), \
             patch.object(orchestrator, "_run_codeql", new_callable=AsyncMock):
            asyncio.run(orchestrator.extract_and_align())

        assert len(orchestrator.initial_hypotheses) == 1
        hyp = orchestrator.initial_hypotheses[0]
        assert hyp.joern_source_ids == {101, 102}
        assert hyp.joern_sink_ids == {201}
        mock_aligner.close.assert_called_once()


# ---------------------------------------------------------------------------
# Reasoning Pipeline (mocked external systems)
# ---------------------------------------------------------------------------

class TestReasoningPipeline:

    def _make_orchestrator_with_hypothesis(self, tmp_path):
        orc = CoComOrchestrator(str(tmp_path), str(tmp_path / "w"), language="python")
        hyp = VulnerabilityHypothesis(
            rule_id="CWE-89",
            source=CodeLocation("app.py", 10),
            sink=CodeLocation("db.py", 20),
            joern_source_ids={1},
            joern_sink_ids={2},
        )
        orc.initial_hypotheses = [hyp]
        return orc

    @patch("src.core.orchestrator.LedgerLLMOracle")
    @patch("src.core.orchestrator.AssumptionLedgerDAG")
    @patch("src.core.orchestrator.KBEntailmentEngine")
    @patch("src.core.orchestrator.AACCEngine")
    def test_pipeline_skips_hypothesis_without_nodes(
        self, MockAACCEngine, MockKB, MockLedger, MockOracle, tmp_path
    ):
        orc = CoComOrchestrator(str(tmp_path), str(tmp_path / "w"), language="python")
        # Hypothesis with no aligned nodes
        orc.initial_hypotheses = [
            VulnerabilityHypothesis(
                rule_id="CWE-89",
                source=CodeLocation("a.py", 1),
                sink=CodeLocation("b.py", 2),
                joern_source_ids=set(),
                joern_sink_ids=set(),
            )
        ]

        mock_aacc = MagicMock()
        MockAACCEngine.return_value = mock_aacc
        mock_ledger = MagicMock()
        mock_ledger.collect_non_invalid.return_value = []
        MockLedger.return_value = mock_ledger

        result = orc.execute_reasoning_pipeline()

        mock_aacc.extract_compressed_graph.assert_not_called()
        assert result == []


# ---------------------------------------------------------------------------
# KB evaluated before LLM (Rule 2 enforcement)
# ---------------------------------------------------------------------------

class TestKBBeforeLLM:

    @patch("src.core.orchestrator.LedgerLLMOracle")
    @patch("src.core.orchestrator.AssumptionLedgerDAG")
    @patch("src.core.orchestrator.KBEntailmentEngine")
    @patch("src.core.orchestrator.AACCEngine")
    def test_llm_not_called_when_kb_returns_non_neutral(
        self, MockAACCEngine, MockKB, MockLedger, MockOracle, tmp_path
    ):
        """LLM oracle must NOT be invoked when KBEntailmentEngine returns a definitive state."""
        orc = CoComOrchestrator(str(tmp_path), str(tmp_path / "w"), language="python")
        orc.initial_hypotheses = [
            VulnerabilityHypothesis(
                rule_id="CWE-89",
                source=CodeLocation("a.py", 1),
                sink=CodeLocation("b.py", 2),
                joern_source_ids={1},
                joern_sink_ids={2},
            )
        ]

        mock_aacc = MagicMock()
        MockAACCEngine.return_value = mock_aacc
        mock_kb = MagicMock()
        # KB always returns VALIDATED — LLM must never be called
        mock_kb.evaluate.return_value = {"state": "validated", "justification": "KB match"}
        MockKB.return_value = mock_kb
        mock_ledger = MagicMock()
        mock_ledger.collect_non_invalid.return_value = ["CWE-89"]
        MockLedger.return_value = mock_ledger
        mock_oracle = MagicMock()
        MockOracle.return_value = mock_oracle

        orc.execute_reasoning_pipeline()

        mock_oracle.evaluate_assumption.assert_not_called()

    @patch("src.core.orchestrator.LedgerLLMOracle")
    @patch("src.core.orchestrator.AssumptionLedgerDAG")
    @patch("src.core.orchestrator.KBEntailmentEngine")
    @patch("src.core.orchestrator.AACCEngine")
    def test_llm_called_when_kb_returns_neutral(
        self, MockAACCEngine, MockKB, MockLedger, MockOracle, tmp_path
    ):
        """LLM oracle MUST be invoked when KBEntailmentEngine returns NEUTRAL."""
        orc = CoComOrchestrator(str(tmp_path), str(tmp_path / "w"), language="python")
        orc.initial_hypotheses = [
            VulnerabilityHypothesis(
                rule_id="CWE-89",
                source=CodeLocation("a.py", 1),
                sink=CodeLocation("b.py", 2),
                joern_source_ids={1},
                joern_sink_ids={2},
            )
        ]

        mock_aacc = MagicMock()
        MockAACCEngine.return_value = mock_aacc
        mock_kb = MagicMock()
        mock_kb.evaluate.return_value = {"state": "neutral", "justification": "no match"}
        MockKB.return_value = mock_kb
        mock_ledger = MagicMock()
        mock_ledger.collect_non_invalid.return_value = []
        MockLedger.return_value = mock_ledger
        mock_oracle = MagicMock()
        mock_oracle.evaluate_assumption.return_value = {"state": "neutral", "justification": ""}
        MockOracle.return_value = mock_oracle

        orc.execute_reasoning_pipeline()

        # Two assumptions per hypothesis → oracle called twice
        assert mock_oracle.evaluate_assumption.call_count == 2
