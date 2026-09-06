"""Deterministic reference model for PolicyGuard's safety gates.

This model mirrors the contract's pre-consensus checks.  It intentionally does
not pretend to reproduce LLM judgment; live semantic interpretation is verified
by the Studionet Full Consensus evidence recorded after deployment.
"""

from __future__ import annotations

import hashlib
import json
from urllib.parse import urlparse


ALLOWED_TYPES = {
    "AUDIT", "BUDGET", "LEGAL", "SECURITY_REVIEW", "SPECIFICATION",
    "RISK_ASSESSMENT", "APPROVAL_BUNDLE", "PROCUREMENT_QUOTE", "IDENTITY",
    "DELIVERY_PROOF", "REMEDIATION", "CHALLENGE", "OTHER",
}


def valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def validate_url(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or not parsed.path.strip("/"):
        return False
    if parsed.query or parsed.fragment or "\\" in value:
        return False
    host = (parsed.hostname or "").lower()
    blocked = ("localhost", "127.", "0.", "10.", "192.168.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")
    return not any(host == item or host.startswith(item) for item in blocked)


def canonical_hash(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def evaluate_gate(
    *,
    amount_usd: int,
    threshold_usd: int = 20_000,
    required_approvals: int = 3,
    approval_wallets: list[str] | None = None,
    evidence_types: list[str] | None = None,
    sources_authenticated: bool = True,
    malformed_consensus: bool = False,
) -> dict:
    approvals = approval_wallets or []
    evidence = [item.upper() for item in (evidence_types or [])]
    if not sources_authenticated:
        return {"status": "NEEDS_REVIEW", "reason": "Policy or proposal digest mismatch."}
    if len(set(address.lower() for address in approvals)) != len(approvals):
        raise ValueError("duplicate reviewer approval")
    if amount_usd > threshold_usd and len(approvals) < required_approvals:
        return {"status": "NON_COMPLIANT", "reason": "Insufficient reviewer approvals."}
    if amount_usd > threshold_usd and "AUDIT" not in evidence:
        return {"status": "NON_COMPLIANT", "reason": "Required security audit is missing."}
    if malformed_consensus:
        return {"status": "NEEDS_REVIEW", "reason": "Malformed consensus response; manual review is required."}
    return {"status": "COMPLIANT", "reason": "All applicable policy requirements are satisfied."}


def binding_digest(*, policy_digest: str, proposal_digest: str, evidence_digest: str, approval_digest: str, revision: int) -> str:
    return canonical_hash({
        "policy_digest": policy_digest,
        "proposal_digest": proposal_digest,
        "evidence_digest": evidence_digest,
        "approval_digest": approval_digest,
        "revision": revision,
    })


def can_authorize(*, latest_status: str, evaluated_binding: str, current_binding: str, caller_is_owner: bool) -> bool:
    return caller_is_owner and latest_status == "COMPLIANT" and evaluated_binding == current_binding
