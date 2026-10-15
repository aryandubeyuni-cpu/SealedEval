"""Information-flow contract: fixed release time, padded message size, unified refusal, per-tenant cache salt."""

from dataclasses import asdict, dataclass, field

from .crypto import canonical_json, sha256_hex


@dataclass
class InformationFlowContract:
    """What each party may observe during a run. The broker enforces it; its hash goes in the log."""

    tick_ms: int = 300            # responses are released only on fixed ticks (hides timing)
    pad_bytes: int = 512          # every message is padded to this size (hides length)
    unified_refusal: str = "I can't help with that request."  # same text for every block reason
    red_sees: list[str] = field(default_factory=list)
    blue_sees: list[str] = field(default_factory=list)
    operator_sees: list[str] = field(default_factory=list)
    humans_see_prompts_during_run: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    def contract_hash(self) -> str:
        """SHA-256 of the canonical JSON, so the exact contract can be committed before the run."""
        return sha256_hex(canonical_json(self.to_dict()))


def default_contract() -> InformationFlowContract:
    return InformationFlowContract(
        red_sees=["final_response_text_or_unified_refusal"],
        blue_sees=["single_prompt_at_checkpoint"],
        operator_sees=["health", "alerts"],
    )
