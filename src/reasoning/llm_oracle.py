# File: src/reasoning/llm_oracle.py

import json
from typing import Any, Dict

from openai import (APITimeoutError, AuthenticationError, OpenAI,
                    PermissionDeniedError, RateLimitError)

from .kb_entailment import EvidenceState


class LedgerLLMOracle:
    """
    Evaluates complex assumptions over G' using bounded LLM reasoning.
    Strictly outputs state transitions compliant with the Formal Hypothesis Ledger.

    Only invoked when KBEntailmentEngine returns NEUTRAL — never called
    when the KB can give a deterministic answer.
    """

    def __init__(self, model: str = "gpt-4-turbo"):
        self.model = model
        self.client = OpenAI()  # Assumes OPENAI_API_KEY is in environment

    def _build_system_prompt(self) -> str:
        return (
            "You are a deterministic Static Analysis Verifier.\n"
            "Evaluate the provided vulnerability assumption (A_i) against the Code Property Graph (G') evidence.\n"
            "Categorize the evidence into exactly ONE of these states:\n"
            '1. "validated": Graph explicitly confirms the assumption.\n'
            '2. "undermined": Graph provides explicit, contradictory evidence.\n'
            '3. "neutral": Graph lacks sufficient evidence to definitively validate or undermine.\n\n'
            'CRITICAL: Rejection must be SOUND. Only output "undermined" if explicit contradicting code exists.\n\n'
            "Respond ONLY in valid JSON:\n"
            "{\n"
            '    "state": "<validated|undermined|neutral>",\n'
            '    "justification": "<Strict, one-sentence academic justification citing the code>"\n'
            "}"
        )

    def evaluate_assumption(
        self, assumption_id: str, desc: str, g_prime_context: str
    ) -> Dict[str, Any]:
        """
        Submits an assumption and its G' evidence to the LLM for semantic verification.

        Returns a dict with keys:
            assumption_id — echoed back for tracking
            state         — EvidenceState value string
            justification — rationale from the model
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": self._build_system_prompt()},
                    {
                        "role": "user",
                        "content": (
                            f"ASSUMPTION:\n{desc}\n\nEVIDENCE (G'):\n{g_prime_context}"
                        ),
                    },
                ],
                temperature=0.0,  # Absolute determinism
                timeout=60,
            )
            parsed = json.loads(response.choices[0].message.content)

            state_val = parsed.get("state", "").lower()
            valid_states = {s.value for s in EvidenceState} - {
                EvidenceState.PENDING.value
            }
            if state_val not in valid_states:
                state_val = EvidenceState.NEUTRAL.value

            return {
                "assumption_id": assumption_id,
                "state": state_val,
                "justification": parsed.get(
                    "justification", "No justification provided."
                ),
            }
        except (AuthenticationError, PermissionDeniedError) as e:
            # Unrecoverable configuration errors — re-raise immediately.
            raise
        except (RateLimitError, APITimeoutError) as e:
            print(f"[LedgerLLMOracle] Transient API error for '{assumption_id}': {e}")
            return {
                "assumption_id": assumption_id,
                "state": EvidenceState.NEUTRAL.value,
                "justification": str(e),
            }
        except Exception as e:
            print(f"[LedgerLLMOracle] Unexpected error for '{assumption_id}': {e}")
            return {
                "assumption_id": assumption_id,
                "state": EvidenceState.NEUTRAL.value,
                "justification": str(e),
            }
