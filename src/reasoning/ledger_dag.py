# File: src/reasoning/ledger_dag.py

from typing import Dict, List, Set

import networkx as nx

from .kb_entailment import EvidenceState


class AssumptionLedgerDAG:
    """
    Enforces the Monotonic Invalidation Property (Theorem 1).

    Maintains a DAG of vulnerability hypotheses and their dependency assumptions.
    When any assumption transitions to UNDERMINED, all dependent hypotheses are
    irreversibly invalidated — this propagation can never be reversed.

    Theorem 1: For all A_i ∈ A, if state(A_i, t) = UNDERMINED,
               then state(A_i, t') = UNDERMINED for all t' > t.
    """

    def __init__(self):
        self.dag: nx.DiGraph = nx.DiGraph()
        self.invalidated_hypotheses: Set[str] = set()

    def register_hypothesis(
        self, hypothesis_id: str, assumptions: List[Dict[str, str]]
    ) -> None:
        """
        Adds a vulnerability hypothesis and its required assumptions to the ledger.
        No-ops if the hypothesis is already registered.
        """
        if hypothesis_id in self.dag:
            return

        self.dag.add_node(hypothesis_id, type="hypothesis", is_valid=True)

        for a in assumptions:
            a_id = a["id"]
            if a_id not in self.dag:
                self.dag.add_node(
                    a_id,
                    type="assumption",
                    state=EvidenceState.PENDING.value,
                    desc=a["desc"],
                )
            # Edge direction: Hypothesis → Assumption (hypothesis depends on assumption)
            self.dag.add_edge(hypothesis_id, a_id)

    def update_state(self, assumption_id: str, oracle_state: str) -> None:
        """
        Applies a state transition to an assumption monotonically.

        Monotonicity constraints:
        - UNDERMINED is terminal: once set it can never change.
        - NEUTRAL transitions are no-ops (evidence is insufficient to commit).

        Raises:
            KeyError: If ``assumption_id`` is not registered in the ledger.
        """
        if assumption_id not in self.dag:
            raise KeyError(
                f"[AssumptionLedgerDAG] Unknown assumption ID: '{assumption_id}'"
            )

        current_state = self.dag.nodes[assumption_id]["state"]

        # Theorem 1: once undermined, always undermined
        if current_state == EvidenceState.UNDERMINED.value:
            return

        # NEUTRAL carries no information — do not overwrite a richer state
        if oracle_state == EvidenceState.NEUTRAL.value:
            return

        self.dag.nodes[assumption_id]["state"] = oracle_state

        if oracle_state == EvidenceState.UNDERMINED.value:
            self._invalidate_dependents(assumption_id)

    def _invalidate_dependents(self, assumption_id: str) -> None:
        """
        Cascades invalidation upward to all hypothesis nodes that depend on
        the undermined assumption.
        """
        dependent_nodes = nx.ancestors(self.dag, assumption_id)
        for node in dependent_nodes:
            node_data = self.dag.nodes[node]
            if node_data.get("type") == "hypothesis" and node_data["is_valid"]:
                node_data["is_valid"] = False
                self.invalidated_hypotheses.add(node)

    def collect_non_invalid(self) -> List[str]:
        """
        Returns hypothesis IDs that survived verification — i.e. still valid
        and all of whose assumptions are in VALIDATED state.
        """
        valid_h = []
        for node, data in self.dag.nodes(data=True):
            if data.get("type") == "hypothesis" and data.get("is_valid"):
                assumptions = list(self.dag.successors(node))
                if all(
                    self.dag.nodes[a]["state"] == EvidenceState.VALIDATED.value
                    for a in assumptions
                ):
                    valid_h.append(node)
        return valid_h

    def summary(self) -> Dict[str, Dict]:
        """Returns the full state of all nodes in the ledger."""
        return {node: dict(data) for node, data in self.dag.nodes(data=True)}
