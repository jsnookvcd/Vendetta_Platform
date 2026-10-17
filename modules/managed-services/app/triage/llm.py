"""Optional LLM triage backend.

When a model is configured, it can propose a verdict with a rationale. Its output is
never trusted raw: the engine validates it, grounds it against the deterministic rules
signals, and falls back to rules on any error or malformed response. The model is an
assistant to a human analyst, not an authority; a human and, for high-stakes verdicts,
a second approver still decide, and both the model's proposal and the human decision
are written to the signed evidence chain.

This backend speaks the Anthropic Messages API when ANTHROPIC_API_KEY-style settings
are provided. It is intentionally small and dependency-light (httpx). Any failure
raises, and the engine falls back to the rules backend.
"""
from __future__ import annotations

import json

from .model import VERDICTS, Finding, Proposal, requires_second_approver

_SYSTEM = (
    "You are a security alert triage assistant for a DFIR firm. Given one finding, "
    "recommend exactly one verdict from this set: " + ", ".join(VERDICTS) + ". "
    "Respond ONLY with a compact JSON object: "
    '{"verdict": <one of the set>, "confidence": <0..1>, "rationale": <one paragraph>, '
    '"signals": [<short strings>]}. Base the rationale only on the finding\'s stated '
    "facts. Do not invent details. If the facts are insufficient, use "
    "needs_investigation with low confidence."
)


class LLMBackend:
    def __init__(self, *, api_key: str, model: str, base_url: str = "https://api.anthropic.com",
                 timeout: float = 30.0):
        if not api_key or not model:
            raise ValueError("LLM backend needs api_key and model")
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _prompt(self, f: Finding) -> str:
        facts = {
            "title": f.title, "description": f.description, "severity": f.severity,
            "cvss": f.cvss, "asset": f.asset, "cve": f.cve, "source": f.source,
            "times_seen": f.times_seen, "prior_human_verdict": f.prior_verdict,
            "tags": f.tags,
        }
        return "Finding:\n" + json.dumps(facts, indent=2, default=str)

    def propose(self, f: Finding) -> Proposal:
        import httpx

        payload = {
            "model": self.model,
            "max_tokens": 600,
            "system": _SYSTEM,
            "messages": [{"role": "user", "content": self._prompt(f)}],
        }
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01",
                   "content-type": "application/json"}
        with httpx.Client(timeout=self.timeout) as http:
            r = http.post(f"{self.base_url}/v1/messages", json=payload, headers=headers)
        r.raise_for_status()
        body = r.json()
        text = "".join(block.get("text", "") for block in body.get("content", [])
                       if block.get("type") == "text").strip()
        data = _extract_json(text)
        verdict = data.get("verdict", "")
        if verdict not in VERDICTS:
            raise ValueError(f"model returned an unknown verdict: {verdict!r}")
        confidence = float(data.get("confidence", 0.0))
        confidence = max(0.0, min(1.0, confidence))
        rationale = str(data.get("rationale", "")).strip()
        if not rationale:
            raise ValueError("model returned an empty rationale")
        signals = [str(s) for s in data.get("signals", [])][:12]
        return Proposal(
            verdict=verdict,
            confidence=confidence,
            rationale=rationale,
            signals=signals or ["model did not enumerate signals"],
            model=self.model,
            requires_approval=requires_second_approver(verdict, confidence),
        )


def _extract_json(text: str) -> dict:
    """Pull the JSON object out of a model reply, tolerating code fences or stray text."""
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("model response did not contain a JSON object")
    return json.loads(text[start:end + 1])
