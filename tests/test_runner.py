# File: tests/test_runner.py

"""
Unit tests for the PrimeVulCTX evaluation runner.

CoComOrchestrator is fully mocked so no live infrastructure is required.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.evaluation.runner import RepoResult, process_single_repository, run_primevulctx_evaluation


# ---------------------------------------------------------------------------
# RepoResult
# ---------------------------------------------------------------------------

class TestRepoResult:

    def test_defaults_are_zero(self):
        r = RepoResult(repo_id="test-repo")
        assert r.tp == 0
        assert r.fp == 0
        assert r.fn == 0
        assert r.error == ""

    def test_fields_assignable(self):
        r = RepoResult(repo_id="x", tp=3, fp=1, fn=2)
        assert r.tp == 3


# ---------------------------------------------------------------------------
# process_single_repository
# ---------------------------------------------------------------------------

class TestProcessSingleRepository:

    def _repo_data(self, tmp_path, gt=None):
        return {
            "repo_id": "repo-001",
            "path": str(tmp_path / "repo"),
            "language": "python",
            "ground_truth_cves": gt or ["CWE-89", "CWE-22"],
        }

    @patch("src.evaluation.runner.asyncio.run")
    @patch("src.evaluation.runner.CoComOrchestrator")
    def test_tp_fp_fn_computed_correctly(self, MockOrch, mock_asyncio_run, tmp_path):
        mock_orc = MagicMock()
        mock_orc.execute_reasoning_pipeline.return_value = ["CWE-89", "CWE-78"]
        MockOrch.return_value = mock_orc

        result = process_single_repository(self._repo_data(tmp_path, gt=["CWE-89", "CWE-22"]))

        # TP: CWE-89 (in both), FP: CWE-78 (predicted not in GT), FN: CWE-22 (GT not predicted)
        assert result.tp == 1
        assert result.fp == 1
        assert result.fn == 1
        assert result.error == ""

    @patch("src.evaluation.runner.asyncio.run")
    @patch("src.evaluation.runner.CoComOrchestrator")
    def test_all_correct_predictions(self, MockOrch, mock_asyncio_run, tmp_path):
        mock_orc = MagicMock()
        mock_orc.execute_reasoning_pipeline.return_value = ["CWE-89", "CWE-22"]
        MockOrch.return_value = mock_orc

        result = process_single_repository(self._repo_data(tmp_path))
        assert result.tp == 2
        assert result.fp == 0
        assert result.fn == 0

    @patch("src.evaluation.runner.asyncio.run")
    @patch("src.evaluation.runner.CoComOrchestrator")
    def test_exception_sets_error_field(self, MockOrch, mock_asyncio_run, tmp_path):
        MockOrch.side_effect = RuntimeError("connection refused")

        result = process_single_repository(self._repo_data(tmp_path))
        assert result.tp == 0
        assert result.fp == 0
        assert result.fn == 0
        assert "connection refused" in result.error

    @patch("src.evaluation.runner.asyncio.run")
    @patch("src.evaluation.runner.CoComOrchestrator")
    def test_missing_ground_truth_key(self, MockOrch, mock_asyncio_run, tmp_path):
        mock_orc = MagicMock()
        mock_orc.execute_reasoning_pipeline.return_value = ["CWE-89"]
        MockOrch.return_value = mock_orc

        repo_data = {"repo_id": "r", "path": str(tmp_path), "language": "python"}
        result = process_single_repository(repo_data)
        # No ground truth → 1 FP
        assert result.tp == 0
        assert result.fp == 1
        assert result.fn == 0


# ---------------------------------------------------------------------------
# run_primevulctx_evaluation — metric formulas
# ---------------------------------------------------------------------------

class TestMetricAggregation:

    def _write_dataset(self, tmp_path, data):
        p = tmp_path / "dataset.json"
        p.write_text(json.dumps(data))
        return str(p)

    @patch("src.evaluation.runner.process_single_repository")
    def test_precision_recall_f1_fdr(self, mock_process, tmp_path):
        # Inject pre-computed results directly via mock
        mock_process.side_effect = [
            RepoResult("r1", tp=3, fp=1, fn=1),
            RepoResult("r2", tp=1, fp=0, fn=2),
        ]

        dataset = [
            {"repo_id": "r1", "path": "/x", "language": "python", "ground_truth_cves": []},
            {"repo_id": "r2", "path": "/y", "language": "python", "ground_truth_cves": []},
        ]
        ds_path = self._write_dataset(tmp_path, dataset)
        out_csv = str(tmp_path / "out.csv")

        # Run with 1 worker to avoid multiprocessing pickle issues in tests
        with patch("src.evaluation.runner.ProcessPoolExecutor") as MockPool:
            from concurrent.futures import Future

            futures = {}
            for i, repo in enumerate(dataset):
                f = Future()
                f.set_result(mock_process.side_effect[i])
                futures[f] = repo

            mock_executor = MagicMock()
            mock_executor.__enter__ = MagicMock(return_value=mock_executor)
            mock_executor.__exit__ = MagicMock(return_value=False)
            mock_executor.submit.side_effect = list(futures.keys())
            MockPool.return_value = mock_executor

            with patch("src.evaluation.runner.as_completed", return_value=list(futures.keys())):
                df = run_primevulctx_evaluation(ds_path, out_csv, workers=1)

        # Aggregates: TP=4, FP=1, FN=3
        assert df["TP"].iloc[0] == 4
        assert df["FP"].iloc[0] == 1
        assert df["FN"].iloc[0] == 3
        precision = 4 / 5
        recall = 4 / 7
        assert abs(df["Precision"].iloc[0] - round(precision, 4)) < 1e-4
        assert abs(df["Recall"].iloc[0] - round(recall, 4)) < 1e-4
        assert abs(df["FDR"].iloc[0] - round(1 / 5, 4)) < 1e-4
        assert Path(out_csv).exists()

    @patch("src.evaluation.runner.process_single_repository")
    def test_zero_division_guard(self, mock_process, tmp_path):
        """All FN (nothing predicted) must return 0.0 for Precision and FDR."""
        mock_process.return_value = RepoResult("r1", tp=0, fp=0, fn=5)

        dataset = [{"repo_id": "r1", "path": "/x", "language": "python", "ground_truth_cves": []}]
        ds_path = self._write_dataset(tmp_path, dataset)
        out_csv = str(tmp_path / "z.csv")

        with patch("src.evaluation.runner.ProcessPoolExecutor") as MockPool:
            from concurrent.futures import Future

            f = Future()
            f.set_result(mock_process.return_value)

            mock_executor = MagicMock()
            mock_executor.__enter__ = MagicMock(return_value=mock_executor)
            mock_executor.__exit__ = MagicMock(return_value=False)
            mock_executor.submit.return_value = f
            MockPool.return_value = mock_executor

            with patch("src.evaluation.runner.as_completed", return_value=[f]):
                df = run_primevulctx_evaluation(ds_path, out_csv, workers=1)

        assert df["Precision"].iloc[0] == 0.0
        assert df["FDR"].iloc[0] == 0.0
