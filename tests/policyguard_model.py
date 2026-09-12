"""Deterministic reference model for PolicyGuard's safety gates.

This model mirrors the contract's pre-consensus checks.  It intentionally does
not pretend to reproduce LLM judgment; live semantic interpretation is verified
by the Studionet Full Consensus evidence recorded after deployment.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
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


@dataclass
class WorkflowModel:
    """Small deterministic lifecycle model used for the mapped workflow test.

    The deployed contract owns persistence and consensus execution.  This model
    deliberately covers only the deterministic state transitions around those
    calls so the repository can prove that a fresh organization, policy, and
    proposal are wired through roster setup, evidence, evaluation,
    authorization, and execution without a live validator network.
    """

    organizations: dict[str, dict] = field(default_factory=dict)
    policies: dict[tuple[str, str, int], dict] = field(default_factory=dict)
    proposals: dict[str, dict] = field(default_factory=dict)
    evaluations: dict[str, dict] = field(default_factory=dict)
    authorizations: dict[str, dict] = field(default_factory=dict)

    def create_organization(self, *, organization_id: str, name: str, owner: str) -> None:
        if organization_id in self.organizations:
            raise ValueError("Organization ID has already been used")
        self.organizations[organization_id] = {
            "organization_id": organization_id,
            "name": name,
            "owner": owner.lower(),
            "reviewers": [],
            "policy_id": "",
            "current_policy_version": 0,
        }

    def add_reviewer(self, *, organization_id: str, reviewer: str, caller: str) -> None:
        organization = self.organizations[organization_id]
        if caller.lower() != organization["owner"]:
            raise ValueError("Only the organization owner can add reviewers")
        reviewer = reviewer.lower()
        if reviewer in organization["reviewers"]:
            raise ValueError("Reviewer is already registered")
        organization["reviewers"].append(reviewer)

    def register_policy_version(
        self,
        *,
        organization_id: str,
        policy_id: str,
        version: int,
        threshold_usd: int,
        required_approvals: int,
        required_document_types: list[str],
        baseline_document_types: list[str],
        caller: str,
    ) -> None:
        organization = self.organizations[organization_id]
        if caller.lower() != organization["owner"]:
            raise ValueError("Only the organization owner can register policy versions")
        expected = int(organization["current_policy_version"]) + 1
        if version != expected:
            raise ValueError("Policy versions must be registered sequentially")
        key = (organization_id, policy_id, version)
        self.policies[key] = {
            "organization_id": organization_id,
            "policy_id": policy_id,
            "version": version,
            "approval_threshold_usd": threshold_usd,
            "required_approvals_above_threshold": required_approvals,
            "required_document_types_above_threshold": [item.upper() for item in required_document_types],
            "baseline_document_types": [item.upper() for item in baseline_document_types],
        }
        organization["policy_id"] = policy_id
        organization["current_policy_version"] = version

    def create_proposal(
        self,
        *,
        proposal_id: str,
        organization_id: str,
        policy_id: str,
        policy_version: int,
        amount_usd: int,
        proposer: str,
        executor: str,
    ) -> None:
        organization = self.organizations[organization_id]
        if proposal_id in self.proposals:
            raise ValueError("Proposal ID has already been used")
        if (organization["policy_id"], int(organization["current_policy_version"])) != (policy_id, policy_version):
            raise ValueError("Proposal must bind to the organization's current policy version")
        proposal = {
            "proposal_id": proposal_id,
            "organization_id": organization_id,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "requested_amount_usd": amount_usd,
            "proposer": proposer.lower(),
            "authorized_executor": executor.lower(),
            "status": "PENDING_EVIDENCE",
            "evidence": [],
            "approval_reviewers": [],
            "evaluation_history": [],
            "latest_evaluation_id": "",
            "latest_verdict": "UNEVALUATED",
            "authorization_id": "",
            "input_revision": 0,
        }
        proposal["proposal_digest"] = canonical_hash({
            "proposal_id": proposal_id,
            "organization_id": organization_id,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "requested_amount_usd": amount_usd,
        })
        self.proposals[proposal_id] = proposal

    def _proposal(self, proposal_id: str) -> dict:
        if proposal_id not in self.proposals:
            raise ValueError("Proposal was not found")
        return self.proposals[proposal_id]

    def _invalidate_after_input_change(self, proposal: dict) -> None:
        proposal["input_revision"] += 1
        proposal["status"] = "PENDING_EVIDENCE"
        proposal["authorization_id"] = ""

    def approve_proposal(self, *, proposal_id: str, reviewer: str) -> None:
        proposal = self._proposal(proposal_id)
        organization = self.organizations[proposal["organization_id"]]
        reviewer = reviewer.lower()
        if reviewer not in organization["reviewers"]:
            raise ValueError("Only a registered reviewer can approve this proposal")
        if reviewer in proposal["approval_reviewers"]:
            raise ValueError("This reviewer has already approved the proposal")
        proposal["approval_reviewers"].append(reviewer)
        self._invalidate_after_input_change(proposal)

    def add_evidence(self, *, proposal_id: str, evidence_id: str, evidence_type: str, caller: str) -> None:
        proposal = self._proposal(proposal_id)
        if caller.lower() not in (
            self.organizations[proposal["organization_id"]]["owner"],
            proposal["proposer"],
        ):
            raise ValueError("Only the organization owner or proposer can add evidence")
        if any(item["evidence_id"] == evidence_id for item in proposal["evidence"]):
            raise ValueError("Evidence ID has already been used for this proposal")
        proposal["evidence"].append({"evidence_id": evidence_id, "type": evidence_type.upper()})
        self._invalidate_after_input_change(proposal)

    def _binding(self, proposal: dict) -> str:
        policy = self.policies[(proposal["organization_id"], proposal["policy_id"], proposal["policy_version"])]
        evidence_digest = canonical_hash(sorted(item["type"] for item in proposal["evidence"]))
        approval_digest = canonical_hash(sorted(proposal["approval_reviewers"]))
        return binding_digest(
            policy_digest=canonical_hash(policy),
            proposal_digest=proposal["proposal_digest"],
            evidence_digest=evidence_digest,
            approval_digest=approval_digest,
            revision=proposal["input_revision"],
        )

    def start_evaluation(self, *, proposal_id: str) -> dict:
        proposal = self._proposal(proposal_id)
        policy = self.policies[(proposal["organization_id"], proposal["policy_id"], proposal["policy_version"])]
        required_types = list(policy["baseline_document_types"])
        if proposal["requested_amount_usd"] > policy["approval_threshold_usd"]:
            required_types.extend(policy["required_document_types_above_threshold"])
        verdict = evaluate_gate(
            amount_usd=proposal["requested_amount_usd"],
            threshold_usd=policy["approval_threshold_usd"],
            required_approvals=policy["required_approvals_above_threshold"],
            approval_wallets=proposal["approval_reviewers"],
            evidence_types=[item["type"] for item in proposal["evidence"]],
        )
        # The gate above models the contract's standard AUDIT requirement.  For
        # a custom policy, retain the same fail-closed behavior for any missing
        # document type before recording the immutable evaluation.
        present_types = {item["type"] for item in proposal["evidence"]}
        missing_types = [item for item in required_types if item not in present_types]
        if missing_types:
            reason = "Required security audit is missing." if "AUDIT" in missing_types else "Required supporting documentation is missing."
            verdict = {"status": "NON_COMPLIANT", "reason": reason}
        sequence = len(proposal["evaluation_history"]) + 1
        evaluation_id = f"{proposal_id}:e{sequence}"
        record = {
            **verdict,
            "evaluation_id": evaluation_id,
            "evaluation_sequence": sequence,
            "previous_evaluation_id": proposal["latest_evaluation_id"],
            "input_revision": proposal["input_revision"],
            "binding_digest": self._binding(proposal),
        }
        self.evaluations[evaluation_id] = record
        proposal["evaluation_history"].append(evaluation_id)
        proposal["latest_evaluation_id"] = evaluation_id
        proposal["latest_verdict"] = record["status"]
        proposal["status"] = record["status"]
        return record

    def authorize_action(self, *, proposal_id: str, caller: str) -> dict:
        proposal = self._proposal(proposal_id)
        organization = self.organizations[proposal["organization_id"]]
        if caller.lower() != organization["owner"]:
            raise ValueError("Only the organization owner can authorize the action")
        latest = self.evaluations[proposal["latest_evaluation_id"]]
        if proposal["status"] != "COMPLIANT" or latest["binding_digest"] != self._binding(proposal):
            raise ValueError("Latest verdict is stale or not compliant")
        authorization_id = f"{proposal_id}:auth:{latest['evaluation_id']}"
        authorization = {
            "authorization_id": authorization_id,
            "proposal_id": proposal_id,
            "evaluation_id": latest["evaluation_id"],
            "binding_digest": latest["binding_digest"],
        }
        self.authorizations[authorization_id] = authorization
        proposal["authorization_id"] = authorization_id
        proposal["status"] = "AUTHORIZED"
        return authorization

    def execute_action(self, *, proposal_id: str, execution_reference: str, caller: str) -> dict:
        proposal = self._proposal(proposal_id)
        if proposal["status"] != "AUTHORIZED":
            raise ValueError("Proposal is not authorized")
        if caller.lower() != proposal["authorized_executor"]:
            raise ValueError("Only the authorized executor can mark execution")
        authorization = self.authorizations[proposal["authorization_id"]]
        if authorization["binding_digest"] != self._binding(proposal):
            raise ValueError("Authorization no longer matches the current proposal inputs")
        proposal["status"] = "EXECUTED"
        proposal["execution_reference"] = execution_reference
        return proposal
