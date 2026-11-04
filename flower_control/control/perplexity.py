"""Perplexity Decisions wire adapter; no images, tools or generated code.

Protocol: https://docs.perplexity.ai/docs/decisions/quickstart (2026-10-23).
Reuses the bounded primitives, validation, privacy and HTTP lifecycle of Jev.
"""
from .jev import JevClient


class PerplexityDecisionClient(JevClient):
    provider = "perplexity"
    base_url = "https://api.perplexity.ai"
    endpoint = "/v1/decisions"
    model_pattern = r"pplx-decider-(?:flash-)?v1\.2"
    model_error = "pinned_perplexity_decision_model_required"
    score_limit = 10
    retry_statuses = frozenset({429, 500, 502, 503, 504})
    invalid_request_statuses = frozenset({400, 422})
