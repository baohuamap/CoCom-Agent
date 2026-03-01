# File: src/evaluation/runner.py

import asyncio
import json
import os
import pandas as pd
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from tqdm import tqdm

from src.core.orchestrator import CoComOrchestrator


@dataclass
class RepoResult:
    """Stores per-repository TP/FP/FN counts for metric aggregation."""

    repo_id: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    error: str = ""


def process_single_repository(repo_data: Dict) -> RepoResult:
    """
    Worker function for isolated, single-repository evaluation.
    Runs inside a subprocess spawned by ProcessPoolExecutor.

    Expected keys in ``repo_data``:
        repo_id          — unique identifier string
        path             — absolute path to the repo on disk
        language         — "java" or "python"
        ground_truth_cves — list of known-vulnerable rule IDs (ground truth)
    """
    repo_id = repo_data["repo_id"]
    result = RepoResult(repo_id=repo_id)

    try:
        working_dir = f"/tmp/cocom_eval/{repo_id}"
        os.makedirs(working_dir, exist_ok=True)

        orchestrator = CoComOrchestrator(
            repo_path=repo_data["path"],
            working_dir=working_dir,
            language=repo_data["language"],
        )

        # Execute full pipeline (extraction is async; run inside the worker)
        asyncio.run(orchestrator.extract_and_align())
        verified_hypotheses = orchestrator.execute_reasoning_pipeline()

        # Compute ground-truth deltas
        predicted_set = set(verified_hypotheses)
        ground_truth_set = set(repo_data.get("ground_truth_cves", []))

        result.tp = len(predicted_set & ground_truth_set)
        result.fp = len(predicted_set - ground_truth_set)
        result.fn = len(ground_truth_set - predicted_set)

    except Exception as e:
        result.error = str(e)
        print(f"[{repo_id}] Execution failed: {e}")

    return result


def run_primevulctx_evaluation(
    dataset_json_path: str,
    output_csv: str,
    workers: int = 4,
) -> pd.DataFrame:
    """
    Distributes evaluation across the PrimeVulCTX dataset and computes the
    aggregate Precision, Recall, F1, and FDR metrics required for Table 6.

    Args:
        dataset_json_path: Path to a JSON file containing a list of repo_data dicts.
        output_csv:        Destination path for the CSV export of Table 6 results.
        workers:           Number of parallel worker processes.

    Returns:
        Single-row DataFrame with the Table 6 metrics.
    """
    print(f"[EvaluationRunner] Loading dataset from {dataset_json_path}...")
    with open(dataset_json_path, "r") as f:
        dataset: List[Dict] = json.load(f)

    results: List[RepoResult] = []
    print(f"[EvaluationRunner] Dispatching {len(dataset)} repos to {workers} worker processes...")

    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(process_single_repository, repo): repo
            for repo in dataset
        }
        for future in tqdm(
            as_completed(futures), total=len(dataset), desc="Evaluating PrimeVulCTX"
        ):
            results.append(future.result())

    # Aggregate TP / FP / FN across all repositories
    total_tp = sum(r.tp for r in results)
    total_fp = sum(r.fp for r in results)
    total_fn = sum(r.fn for r in results)

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    fdr = total_fp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0

    # Build Table 6 row
    df = pd.DataFrame(
        [
            {
                "Method": "CoCom-Agent (Ours)",
                "TP": total_tp,
                "FP": total_fp,
                "FN": total_fn,
                "Precision": round(precision, 4),
                "Recall": round(recall, 4),
                "F1": round(f1, 4),
                "FDR": round(fdr, 4),
            }
        ]
    )

    # Persist results
    output_path = Path(output_csv)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)

    print("\n=== Evaluation Complete (Table 6 Results) ===")
    print(df.to_string(index=False))

    return df


if __name__ == "__main__":
    DATASET = "data/primevulctx_sample.json"
    OUTPUT = "results/table_6_metrics.csv"
    run_primevulctx_evaluation(DATASET, OUTPUT, workers=4)
