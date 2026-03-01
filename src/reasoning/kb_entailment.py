# File: src/reasoning/kb_entailment.py

import json
import re
from enum import Enum
from typing import Any, Dict, List, Tuple

import networkx as nx


class EvidenceState(str, Enum):
    VALIDATED = "validated"
    UNDERMINED = "undermined"
    NEUTRAL = "neutral"
    PENDING = "pending"


class AssumptionType(str, Enum):
    MISSING_SANITIZER = "missing_sanitizer"
    REACHES_SINK = "reaches_sink"


class KBEntailmentEngine:
    """
    Evaluates assumptions against G' deterministically using a static Knowledge Base.
    Prevents unnecessary LLM calls when standard framework sanitizers/sinks are present.
    """

    def __init__(self, kb_json_path: str):
        self.kb_path = kb_json_path
        self.kb = self._load_kb()

    def _load_kb(self) -> Dict[str, Any]:
        try:
            with open(self.kb_path, "r") as f:
                return json.load(f).get("frameworks", {})
        except FileNotFoundError:
            print(
                f"[KBEntailmentEngine] Warning: KB not found at {self.kb_path}. Defaulting to NEUTRAL."
            )
            return {}

    def evaluate(
        self,
        assumption_type: AssumptionType,
        target_cwe: str,
        framework: str,
        g_prime: nx.DiGraph,
    ) -> Dict[str, str]:
        """
        Evaluates a single assumption against G' using deterministic KB rules.

        Returns a dict with keys:
            state         — EvidenceState value string
            justification — human-readable rationale
        """
        if framework not in self.kb:
            return {
                "state": EvidenceState.NEUTRAL.value,
                "justification": f"Framework '{framework}' is not mapped in the KB.",
            }

        rules = self.kb[framework]

        if assumption_type == AssumptionType.MISSING_SANITIZER:
            return self._check_sanitizers(target_cwe, rules, g_prime)
        elif assumption_type == AssumptionType.REACHES_SINK:
            return self._check_sinks(target_cwe, rules, g_prime)

        return {
            "state": EvidenceState.NEUTRAL.value,
            "justification": "Unknown assumption type.",
        }

    def _check_sanitizers(
        self, cwe: str, rules: Dict[str, Any], g_prime: nx.DiGraph
    ) -> Dict[str, str]:
        """
        Searches G' for known sanitizer patterns for the given CWE.
        A matched sanitizer undermines the assumption that NO sanitizer exists.
        """
        sanitizers = rules.get("sanitizers", {}).get(cwe, [])
        if not sanitizers:
            return {
                "state": EvidenceState.NEUTRAL.value,
                "justification": "No deterministic sanitizers found.",
            }
        nodes_by_type: Dict[str, List[Tuple[int, Dict]]] = {}
        for node_id, data in g_prime.nodes(data=True):
            nodes_by_type.setdefault(data.get("type", ""), []).append((node_id, data))
        for sanitizer in sanitizers:
            for node_id, data in nodes_by_type.get(sanitizer["node_type"], []):
                if re.search(sanitizer["pattern"], data.get("code", "")):
                    return {
                        "state": EvidenceState.UNDERMINED.value,
                        "justification": (
                            f"Deterministic Match: {cwe} sanitizer '{sanitizer['pattern']}' "
                            f"found at node {node_id}."
                        ),
                    }
        return {
            "state": EvidenceState.NEUTRAL.value,
            "justification": "No deterministic sanitizers found.",
        }

    def _check_sinks(
        self, cwe: str, rules: Dict[str, Any], g_prime: nx.DiGraph
    ) -> Dict[str, str]:
        """
        Searches G' for known dangerous sink patterns for the given CWE.
        A matched sink validates the assumption that taint reaches a sink.
        """
        sinks = rules.get("sinks", {}).get(cwe, [])
        if not sinks:
            return {
                "state": EvidenceState.NEUTRAL.value,
                "justification": "No deterministic sinks found.",
            }
        nodes_by_type: Dict[str, List[Tuple[int, Dict]]] = {}
        for node_id, data in g_prime.nodes(data=True):
            nodes_by_type.setdefault(data.get("type", ""), []).append((node_id, data))
        for sink in sinks:
            for node_id, data in nodes_by_type.get(sink["node_type"], []):
                if re.search(sink["pattern"], data.get("code", "")):
                    return {
                        "state": EvidenceState.VALIDATED.value,
                        "justification": (
                            f"Deterministic Match: {cwe} sink '{sink['pattern']}' "
                            f"found at node {node_id}."
                        ),
                    }
        return {
            "state": EvidenceState.NEUTRAL.value,
            "justification": "No deterministic sinks found.",
        }
