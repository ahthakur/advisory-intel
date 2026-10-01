"""Per-run spend cap for Claude API calls.

Every call is checked before it is sent: if the worst case (estimated input
plus the full max_tokens of output) would push the run past the cap, the call
is skipped. Actual cost is then recorded from response.usage.

Cap defaults to $0.50; override with CLAUDE_RUN_BUDGET_USD.
"""

from __future__ import annotations

import os

# USD per million tokens (Anthropic first-party pricing)
PRICES = {
    "claude-haiku-4-5-20251001": {"input": 1.00, "output": 5.00},
}

DEFAULT_CAP_USD = 0.50


class BudgetExceeded(Exception):
    """Raised when the next call could push the run past its cap."""


class RunBudget:
    def __init__(self, cap_usd: float | None = None):
        if cap_usd is None:
            cap_usd = float(os.environ.get("CLAUDE_RUN_BUDGET_USD", DEFAULT_CAP_USD))
        self.cap_usd = cap_usd
        self.spent_usd = 0.0
        self.calls = 0

    @staticmethod
    def _price(model: str) -> dict:
        if model not in PRICES:
            raise ValueError(f"No price configured for {model}; add it to PRICES in src/ai/budget.py")
        return PRICES[model]

    def would_exceed(self, model: str, input_tokens: float, max_tokens: int) -> bool:
        """True if this call's worst case (full max_tokens of output) would pass the cap."""
        price = self._price(model)
        worst = (input_tokens * price["input"] + max_tokens * price["output"]) / 1_000_000
        return self.spent_usd + worst > self.cap_usd

    def reserve(self, model: str, prompt: str, max_tokens: int):
        """Raise BudgetExceeded if the worst case for this call would exceed the cap."""
        # ~3 chars per token overestimates input tokens for English text
        if self.would_exceed(model, len(prompt) / 3 + 50, max_tokens):
            raise BudgetExceeded(self.stop_message())

    def add(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Add the actual cost of a completed call."""
        price = self._price(model)
        cost = (input_tokens * price["input"] + output_tokens * price["output"]) / 1_000_000
        self.spent_usd += cost
        self.calls += 1
        return cost

    def record(self, model: str, usage) -> float:
        """Add the actual cost of a completed call from response.usage."""
        return self.add(model, usage.input_tokens, usage.output_tokens)

    def stop_message(self) -> str:
        return f"Budget cap ${self.cap_usd:.2f} reached (spent ${self.spent_usd:.4f} over {self.calls} calls)"

    def summary(self) -> str:
        return f"Spent ${self.spent_usd:.4f} of ${self.cap_usd:.2f} cap over {self.calls} calls"


class AgentBudgetHook:
    """Strands hook that enforces a RunBudget across every model call an agent makes.

    One hook per agent, so the cap covers the whole session (or a whole eval run).
    """

    def __init__(self, model: str, max_tokens: int, budget: RunBudget | None = None):
        self.model = model
        self.max_tokens = max_tokens
        self.budget = budget or RunBudget()

    def register_hooks(self, registry, **kwargs):
        from strands.hooks import AfterModelCallEvent, BeforeModelCallEvent

        registry.add_callback(BeforeModelCallEvent, self._before)
        registry.add_callback(AfterModelCallEvent, self._after)

    def _before(self, event):
        input_tokens = event.projected_input_tokens
        if input_tokens is None:
            input_tokens = len(str(event.agent.messages)) / 3 + 2000
        if self.budget.would_exceed(self.model, input_tokens, self.max_tokens):
            event.cancel = self.budget.stop_message()

    def _after(self, event):
        if event.stop_response is None:
            return
        usage = event.stop_response.message.get("metadata", {}).get("usage")
        if usage:
            self.budget.add(self.model, usage.get("inputTokens", 0), usage.get("outputTokens", 0))
