# File: src/core/orchestrator.py

import asyncio
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from .alignment import CPGAlignmentLayer
from src.graph.aacc_engine import AACCEngine
from src.reasoning.kb_entailment import AssumptionType, EvidenceState, KBEntailmentEngine
from src.reasoning.ledger_dag import AssumptionLedgerDAG
from src.reasoning.llm_oracle import LedgerLLMOracle


@dataclass
class CodeLocation:
    """Represents a source-code position produced by CodeQL."""

    file_path: str
    line_number: int


@dataclass
class VulnerabilityHypothesis:
    """A single taint-flow hypothesis derived from a CodeQL SARIF finding."""

    rule_id: str
    source: CodeLocation
    sink: CodeLocation
    joern_source_ids: Set[int] = field(default_factory=set)
    joern_sink_ids: Set[int] = field(default_factory=set)


@dataclass
class TypedAssumption:
    """An assumption with an explicit AssumptionType, avoiding string-based inference."""

    id: str
    desc: str
    assumption_type: AssumptionType


class CoComOrchestrator:
    """
    Central control plane for a single-repository analysis run.

    Implements the deterministic pipeline:
        Compression → Hypothesis → Ledger → Report

    as defined in Section 4.3 of the paper.
    """

    def __init__(self, repo_path: str, working_dir: str, language: str):
        if language not in ("java", "python"):
            raise ValueError("Supported languages are 'java' and 'python'.")

        self.repo_path = Path(repo_path).resolve()
        self.working_dir = Path(working_dir)
        self.working_dir.mkdir(parents=True, exist_ok=True)
        self.language = language
        self.cpg_path = self.working_dir / f"cpg_{language}.bin"
        self.sarif_path = self.working_dir / f"codeql_{language}.sarif"
        self.initial_hypotheses: List[VulnerabilityHypothesis] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def extract_and_align(self) -> None:
        """
        Runs CodeQL and Joern concurrently, then maps SARIF findings to
        Joern CPG Node IDs via the CPGAlignmentLayer.
        """
        print(f"[CoComOrchestrator] Extracting graphs for {self.repo_path}...")

        # Step 1: Concurrent static-analysis + CPG extraction
        await asyncio.gather(
            self._run_codeql(),
            self._run_joern(),
        )

        # Step 2: Parse SARIF into hypothesis stubs
        self._parse_sarif()

        # Step 3: Align CodeQL findings to Joern CPG nodes
        aligner = CPGAlignmentLayer()
        try:
            for hyp in self.initial_hypotheses:
                hyp.joern_source_ids = aligner.get_joern_nodes(
                    hyp.source.file_path, hyp.source.line_number
                )
                hyp.joern_sink_ids = aligner.get_joern_nodes(
                    hyp.sink.file_path, hyp.sink.line_number
                )
        finally:
            aligner.close()

    def execute_reasoning_pipeline(self) -> List[str]:
        """
        Executes AACC graph compression and the Assumption Ledger
        verification loop for every aligned hypothesis.

        Returns the list of rule IDs whose hypotheses survived
        full VALIDATED verification.
        """
        kb_path = Path(__file__).parent.parent.parent / "config" / f"{self.language}_kb.json"
        aacc = AACCEngine()
        kb_engine = KBEntailmentEngine(str(kb_path))
        llm_oracle = LedgerLLMOracle()
        ledger = AssumptionLedgerDAG()

        try:
            for hyp in self.initial_hypotheses:
                if not hyp.joern_source_ids or not hyp.joern_sink_ids:
                    print(f"[CoComOrchestrator] Skipping {hyp.rule_id}: alignment produced no nodes.")
                    continue

                # 1. Analysis-Aware Context Compression (AACC): G → G'
                g_prime = aacc.extract_compressed_graph(
                    list(hyp.joern_source_ids), list(hyp.joern_sink_ids)
                )

                # 2. Hypothesis Generation — two assumptions per flow.
                # NOTE: These are CWE-generic scaffolding assumptions valid for most taint flows.
                # A full per-CWE proof obligation model would require CWE-specific assumption sets.
                typed_assumptions = [
                    TypedAssumption(
                        id=f"{hyp.rule_id}_flow",
                        desc="Feasible data flow exists from source to sink.",
                        assumption_type=AssumptionType.REACHES_SINK,
                    ),
                    TypedAssumption(
                        id=f"{hyp.rule_id}_nosan",
                        desc="No valid sanitizer interrupts the data flow.",
                        assumption_type=AssumptionType.MISSING_SANITIZER,
                    ),
                ]
                ledger.register_hypothesis(
                    hyp.rule_id,
                    [{"id": a.id, "desc": a.desc} for a in typed_assumptions],
                )

                # 3. Ledger Verification Loop
                for a in typed_assumptions:
                    # Fast Path: deterministic KB evaluation
                    kb_res = kb_engine.evaluate(a.assumption_type, hyp.rule_id, self.language, g_prime)
                    if kb_res["state"] != EvidenceState.NEUTRAL.value:
                        ledger.update_state(a.id, kb_res["state"])
                    else:
                        # Slow Path: bounded LLM semantic oracle
                        g_prime_txt = aacc.format_for_llm(g_prime)
                        llm_res = llm_oracle.evaluate_assumption(a.id, a.desc, g_prime_txt)
                        ledger.update_state(a.id, llm_res["state"])
        finally:
            aacc.close()

        # 4. Collect surviving hypotheses
        return ledger.collect_non_invalid()

    # ------------------------------------------------------------------
    # Internal subprocess wrappers
    # ------------------------------------------------------------------

    async def _run_joern(self) -> None:
        """
        Invokes `joern-parse` asynchronously to build the CPG binary.
        Raises RuntimeError on non-zero exit.
        """
        cmd = [
            "joern-parse",
            str(self.repo_path),
            "--output", str(self.cpg_path),
        ]
        print(f"[CoComOrchestrator] Running Joern on: {self.repo_path}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"joern-parse failed:\n{stderr.decode()}")
        print(f"[CoComOrchestrator] CPG written to: {self.cpg_path}")

    async def _run_codeql(self) -> None:
        """
        Builds a CodeQL database from source, then runs analysis to produce a SARIF report.
        Raises RuntimeError on non-zero exit from either step.
        """
        db_path = self.working_dir / f"codeql_db_{self.language}"

        # Step 1: Create the database from source
        create_cmd = [
            "codeql", "database", "create",
            str(db_path),
            f"--language={self.language}",
            f"--source-root={self.repo_path}",
            "--overwrite",
        ]
        print(f"[CoComOrchestrator] Building CodeQL database ({self.language}) from: {self.repo_path}")
        proc = await asyncio.create_subprocess_exec(
            *create_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"codeql database create failed:\n{stderr.decode()}")

        # Step 2: Analyze the database
        analyze_cmd = [
            "codeql", "database", "analyze",
            "--format=sarif-latest",
            f"--output={self.sarif_path}",
            str(db_path),
            f"{self.language}-security-extended",
        ]
        print(f"[CoComOrchestrator] Running CodeQL analysis ({self.language})...")
        proc = await asyncio.create_subprocess_exec(
            *analyze_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"codeql analyze failed:\n{stderr.decode()}")
        print(f"[CoComOrchestrator] SARIF written to: {self.sarif_path}")

    def _parse_sarif(self) -> None:
        """
        Parses the SARIF report at ``self.sarif_path`` and populates
        ``self.initial_hypotheses`` with one VulnerabilityHypothesis per result.

        Source/sink coordinates are extracted from
        ``codeFlows[0].threadFlows[0].locations`` (first and last entries).
        Falls back to ``relatedLocations[0]`` as source and ``locations[0]`` as
        sink when ``codeFlows`` is absent.  Results without resolvable
        source+sink coordinates are skipped.
        """
        if not self.sarif_path.exists():
            print(f"[CoComOrchestrator] SARIF not found at {self.sarif_path}; skipping parse.")
            return

        with open(self.sarif_path) as f:
            sarif = json.load(f)

        def _loc(entry: Dict) -> Optional[CodeLocation]:
            phys = entry.get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "")
            line = phys.get("region", {}).get("startLine")
            if uri and line is not None:
                return CodeLocation(file_path=uri, line_number=line)
            return None

        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                src: Optional[CodeLocation] = None
                snk: Optional[CodeLocation] = None

                # Primary: taint-flow path via codeFlows
                code_flows = result.get("codeFlows", [])
                if code_flows:
                    thread_locs = (
                        code_flows[0].get("threadFlows", [{}])[0].get("locations", [])
                    )
                    if len(thread_locs) >= 2:
                        src = _loc(thread_locs[0].get("location", {}))
                        snk = _loc(thread_locs[-1].get("location", {}))

                # Fallback: relatedLocations[0] as source, primary location as sink
                if src is None or snk is None:
                    related = result.get("relatedLocations", [])
                    primary = result.get("locations", [])
                    if related and primary:
                        src = _loc(related[0])
                        snk = _loc(primary[0])

                if src and snk:
                    self.initial_hypotheses.append(
                        VulnerabilityHypothesis(rule_id=rule_id, source=src, sink=snk)
                    )
