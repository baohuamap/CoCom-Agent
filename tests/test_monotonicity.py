# File: tests/test_monotonicity.py

"""
Theorem 1 — Monotonic Invalidation Property.

Formally: For all A_i ∈ A (assumption set) and all t, t' ∈ T (time steps),
if state(A_i, t) = UNDERMINED, then state(A_i, t') = UNDERMINED for all t' > t.

These tests mathematically verify that the AssumptionLedgerDAG enforces this
invariant and that NEUTRAL transitions are no-ops that cannot overwrite richer states.
"""

import pytest

from src.reasoning.kb_entailment import EvidenceState
from src.reasoning.ledger_dag import AssumptionLedgerDAG

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def dag():
    return AssumptionLedgerDAG()


@pytest.fixture
def populated_dag():
    """Ledger with one hypothesis H1 depending on assumptions A1 and A2."""
    d = AssumptionLedgerDAG()
    d.register_hypothesis(
        "H1",
        [
            {"id": "A1", "desc": "No sanitizer present"},
            {"id": "A2", "desc": "Taint reaches sink"},
        ],
    )
    return d


@pytest.fixture
def chain_dag():
    """Ledger with H1 -> A1, H2 -> A2, where H2 also depends on A1."""
    d = AssumptionLedgerDAG()
    d.register_hypothesis("H1", [{"id": "A1", "desc": "Root assumption"}])
    d.register_hypothesis(
        "H2",
        [{"id": "A1", "desc": "Root assumption"}, {"id": "A2", "desc": "Secondary"}],
    )
    return d


# ---------------------------------------------------------------------------
# Theorem 1: Terminal State Irreversibility
# ---------------------------------------------------------------------------


class TestMonotonicityInvariant:

    def test_undermined_state_is_permanent(self, populated_dag):
        """Once UNDERMINED, update_state must never overwrite it."""
        populated_dag.update_state("A1", EvidenceState.UNDERMINED.value)
        populated_dag.update_state(
            "A1", EvidenceState.VALIDATED.value
        )  # Attempt violation
        assert populated_dag.dag.nodes["A1"]["state"] == EvidenceState.UNDERMINED.value

    def test_neutral_does_not_overwrite_validated(self, populated_dag):
        """NEUTRAL is a no-op and must never overwrite a richer state."""
        populated_dag.update_state("A1", EvidenceState.VALIDATED.value)
        populated_dag.update_state("A1", EvidenceState.NEUTRAL.value)
        assert populated_dag.dag.nodes["A1"]["state"] == EvidenceState.VALIDATED.value

    def test_neutral_does_not_overwrite_undermined(self, populated_dag):
        """NEUTRAL is a no-op and must never overwrite UNDERMINED."""
        populated_dag.update_state("A1", EvidenceState.UNDERMINED.value)
        populated_dag.update_state("A1", EvidenceState.NEUTRAL.value)
        assert populated_dag.dag.nodes["A1"]["state"] == EvidenceState.UNDERMINED.value

    def test_validated_state_can_transition(self, populated_dag):
        """VALIDATED is not terminal; it can be superseded by UNDERMINED."""
        populated_dag.update_state("A1", EvidenceState.VALIDATED.value)
        populated_dag.update_state("A1", EvidenceState.UNDERMINED.value)
        assert populated_dag.dag.nodes["A1"]["state"] == EvidenceState.UNDERMINED.value

    def test_pending_is_initial_state(self, populated_dag):
        """All newly registered assumptions must start in PENDING state."""
        assert populated_dag.dag.nodes["A1"]["state"] == EvidenceState.PENDING.value
        assert populated_dag.dag.nodes["A2"]["state"] == EvidenceState.PENDING.value


# ---------------------------------------------------------------------------
# Theorem 1: Hypothesis Invalidation Propagation
# ---------------------------------------------------------------------------


class TestInvalidationPropagation:

    def test_hypothesis_invalidated_when_assumption_undermined(self, populated_dag):
        """Undermining A1 must invalidate H1 (its dependent hypothesis)."""
        populated_dag.update_state("A1", EvidenceState.UNDERMINED.value)
        assert populated_dag.dag.nodes["H1"]["is_valid"] is False
        assert "H1" in populated_dag.invalidated_hypotheses

    def test_hypothesis_not_invalidated_by_validated(self, populated_dag):
        """A VALIDATED assumption does not invalidate the hypothesis."""
        populated_dag.update_state("A1", EvidenceState.VALIDATED.value)
        assert populated_dag.dag.nodes["H1"]["is_valid"] is True
        assert "H1" not in populated_dag.invalidated_hypotheses

    def test_cascade_across_shared_assumption(self, chain_dag):
        """Undermining A1 must invalidate both H1 and H2 (both depend on A1)."""
        chain_dag.update_state("A1", EvidenceState.UNDERMINED.value)
        assert chain_dag.dag.nodes["H1"]["is_valid"] is False
        assert chain_dag.dag.nodes["H2"]["is_valid"] is False

    def test_independent_hypothesis_unaffected(self, chain_dag):
        """Undermining A2 (only used by H2) must not affect H1."""
        chain_dag.update_state("A2", EvidenceState.UNDERMINED.value)
        assert chain_dag.dag.nodes["H2"]["is_valid"] is False
        assert chain_dag.dag.nodes["H1"]["is_valid"] is True


# ---------------------------------------------------------------------------
# collect_non_invalid: Survival Predicate
# ---------------------------------------------------------------------------


class TestCollectNonInvalid:

    def test_hypothesis_not_returned_if_assumptions_pending(self, populated_dag):
        """A hypothesis with PENDING assumptions is not fully verified."""
        result = populated_dag.collect_non_invalid()
        assert "H1" not in result

    def test_hypothesis_returned_when_all_validated(self, populated_dag):
        """A hypothesis is returned only when ALL assumptions are VALIDATED."""
        populated_dag.update_state("A1", EvidenceState.VALIDATED.value)
        populated_dag.update_state("A2", EvidenceState.VALIDATED.value)
        assert "H1" in populated_dag.collect_non_invalid()

    def test_hypothesis_not_returned_after_invalidation(self, populated_dag):
        """An invalidated hypothesis must never appear in collect_non_invalid."""
        populated_dag.update_state("A1", EvidenceState.VALIDATED.value)
        populated_dag.update_state("A2", EvidenceState.VALIDATED.value)
        populated_dag.update_state("A1", EvidenceState.UNDERMINED.value)
        assert "H1" not in populated_dag.collect_non_invalid()


# ---------------------------------------------------------------------------
# Idempotency & Structural Safety
# ---------------------------------------------------------------------------


class TestStructuralSafety:

    def test_register_same_hypothesis_twice_is_idempotent(self, dag):
        """Registering the same hypothesis_id twice must not duplicate nodes."""
        dag.register_hypothesis("H1", [{"id": "A1", "desc": "x"}])
        dag.register_hypothesis(
            "H1", [{"id": "A2", "desc": "y"}]
        )  # second call is no-op
        assert set(dag.dag.nodes) == {"H1", "A1"}  # A2 was not added

    def test_update_state_unknown_id_raises(self, dag):
        """update_state must raise KeyError for an assumption ID not in the ledger."""
        with pytest.raises(KeyError, match="Unknown assumption ID"):
            dag.update_state("nonexistent", "validated")
        with pytest.raises(KeyError, match="unknown_assumption"):
            dag.update_state("unknown_assumption", EvidenceState.VALIDATED.value)

    def test_summary_contains_all_nodes(self, populated_dag):
        """summary() must return entries for the hypothesis and all assumptions."""
        s = populated_dag.summary()
        assert set(s.keys()) == {"H1", "A1", "A2"}
