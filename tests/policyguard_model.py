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
SOURCE_SCOPES = ALLOWED_TYPES | {"POLICY", "PROPOSAL", "EVIDENCE", "REVIEWER_APPROVAL"}


def valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def canonical_hostname(value: str) -> str | None:
    clean = value.strip().lower()
    if len(clean) < 4 or len(clean) > 253 or "." not in clean or clean.startswith(".") or clean.endswith(".") or ".." in clean:
        return None
    if any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-." for char in clean):
        return None
    if all(char in "0123456789." for char in clean):
        return None
    if any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-") for part in clean.split(".")):
        return None
    blocked = {"localhost", "local", "internal", "invalid", "test"}
    if clean in blocked or any(clean.endswith("." + suffix) for suffix in blocked):
        return None
    return clean


def url_hostname(value: str) -> str | None:
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return None
    if value != value.strip() or not value.startswith("https://"):
        return None
    if parsed.scheme != "https" or not parsed.netloc or not parsed.path.strip("/"):
        return None
    if parsed.query or parsed.fragment or "\\" in value or parsed.username or parsed.password or port:
        return None
    return canonical_hostname(parsed.hostname or "")


def validate_url(value: str) -> bool:
    return url_hostname(value) is not None


def source_authorized(*, url: str, allowed_hostname: str, caller: str, issuer_wallet: str, scope: str, allowed_scopes: list[str], active: bool = True) -> bool:
    hostname = url_hostname(url)
    return bool(
        active
        and hostname is not None
        and hostname == canonical_hostname(allowed_hostname)
        and caller.lower() == issuer_wallet.lower()
        and (scope.upper() in allowed_scopes or (scope.upper() in ALLOWED_TYPES and "EVIDENCE" in allowed_scopes))
    )


def citations_are_fetched(citations: list[str], fetched_urls: list[str]) -> bool:
    return bool(citations) and all(url in fetched_urls for url in citations)


def adjudication_reliable(*, sources_authenticated: bool, citations: list[str], fetched_urls: list[str], evaluated_at: int, evidence_deadline: int) -> bool:
    return bool(
        sources_authenticated
        and citations_are_fetched(citations, fetched_urls)
        and evaluated_at >= evidence_deadline
    )


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
    """Deterministic reference for the contract's trust and lifecycle gates."""

    now: int = 1_800_000_000
    organizations: dict[str, dict] = field(default_factory=dict)
    source_authorities: dict[tuple[str, str], dict] = field(default_factory=dict)
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
            "source_authority_ids": [],
            "source_authority_revision": 0,
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

    def register_source_authority(
        self,
        *,
        organization_id: str,
        authority_id: str,
        hostname: str,
        issuer_wallet: str,
        scopes: list[str],
        caller: str,
    ) -> None:
        organization = self.organizations[organization_id]
        if caller.lower() != organization["owner"]:
            raise ValueError("Only the organization owner can register source authorities")
        clean_hostname = canonical_hostname(hostname)
        clean_scopes = [scope.upper() for scope in scopes]
        if clean_hostname is None or not clean_scopes or any(scope not in SOURCE_SCOPES for scope in clean_scopes):
            raise ValueError("Invalid source authority")
        key = (organization_id, authority_id)
        if key in self.source_authorities:
            raise ValueError("Source authority ID has already been used")
        self.source_authorities[key] = {
            "authority_id": authority_id,
            "hostname": clean_hostname,
            "issuer_wallet": issuer_wallet.lower(),
            "scopes": clean_scopes,
            "active": True,
        }
        organization["source_authority_ids"].append(authority_id)
        organization["source_authority_revision"] += 1

    def revoke_source_authority(self, *, organization_id: str, authority_id: str, caller: str) -> None:
        organization = self.organizations[organization_id]
        if caller.lower() != organization["owner"]:
            raise ValueError("Only the organization owner can revoke source authorities")
        authority = self.source_authorities[(organization_id, authority_id)]
        authority["active"] = False
        organization["source_authority_revision"] += 1

    def _authenticate(self, *, organization_id: str, url: str, scope: str, caller: str) -> str:
        organization = self.organizations[organization_id]
        for authority_id in organization["source_authority_ids"]:
            authority = self.source_authorities[(organization_id, authority_id)]
            if source_authorized(
                url=url,
                allowed_hostname=authority["hostname"],
                caller=caller,
                issuer_wallet=authority["issuer_wallet"],
                scope=scope,
                allowed_scopes=authority["scopes"],
                active=authority["active"],
            ):
                return authority_id
        raise ValueError("Source URL, issuer wallet, and scope are not authorized by the organization")

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
        policy_url: str,
        caller: str,
    ) -> None:
        organization = self.organizations[organization_id]
        if caller.lower() != organization["owner"]:
            raise ValueError("Only the organization owner can register policy versions")
        expected = int(organization["current_policy_version"]) + 1
        if version != expected:
            raise ValueError("Policy versions must be registered sequentially")
        key = (organization_id, policy_id, version)
        source_authority_id = self._authenticate(
            organization_id=organization_id, url=policy_url, scope="POLICY", caller=caller
        )
        self.policies[key] = {
            "organization_id": organization_id,
            "policy_id": policy_id,
            "version": version,
            "approval_threshold_usd": threshold_usd,
            "required_approvals_above_threshold": required_approvals,
            "required_document_types_above_threshold": [item.upper() for item in required_document_types],
            "baseline_document_types": [item.upper() for item in baseline_document_types],
            "policy_url": policy_url,
            "source_authority_id": source_authority_id,
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
        proposal_url: str,
        evidence_deadline: int,
    ) -> None:
        organization = self.organizations[organization_id]
        if proposal_id in self.proposals:
            raise ValueError("Proposal ID has already been used")
        if (organization["policy_id"], int(organization["current_policy_version"])) != (policy_id, policy_version):
            raise ValueError("Proposal must bind to the organization's current policy version")
        if evidence_deadline <= self.now:
            raise ValueError("Evidence deadline must be in the future")
        source_authority_id = self._authenticate(
            organization_id=organization_id, url=proposal_url, scope="PROPOSAL", caller=proposer
        )
        proposal = {
            "proposal_id": proposal_id,
            "organization_id": organization_id,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "requested_amount_usd": amount_usd,
            "proposer": proposer.lower(),
            "authorized_executor": executor.lower(),
            "proposal_url": proposal_url,
            "proposal_source_authority_id": source_authority_id,
            "status": "PENDING_EVIDENCE",
            "evidence": [],
            "approval_reviewers": [],
            "evaluation_history": [],
            "latest_evaluation_id": "",
            "latest_verdict": "UNEVALUATED",
            "authorization_id": "",
            "input_revision": 0,
            "evidence_deadline": evidence_deadline,
            "deadline_revision": 1,
        }
        proposal["proposal_digest"] = canonical_hash({
            "proposal_id": proposal_id,
            "organization_id": organization_id,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "requested_amount_usd": amount_usd,
            "proposal_url": proposal_url,
            "evidence_deadline": evidence_deadline,
            "deadline_revision": 1,
            "proposal_source_authority_id": source_authority_id,
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

    def approve_proposal(self, *, proposal_id: str, reviewer: str, proof_url: str) -> None:
        proposal = self._proposal(proposal_id)
        organization = self.organizations[proposal["organization_id"]]
        reviewer = reviewer.lower()
        if reviewer not in organization["reviewers"]:
            raise ValueError("Only a registered reviewer can approve this proposal")
        if self.now >= proposal["evidence_deadline"]:
            raise ValueError("The evidence deadline has passed")
        if reviewer in proposal["approval_reviewers"]:
            raise ValueError("This reviewer has already approved the proposal")
        source_authority_id = self._authenticate(
            organization_id=proposal["organization_id"], url=proof_url,
            scope="REVIEWER_APPROVAL", caller=reviewer,
        )
        proposal["approval_reviewers"].append(reviewer)
        proposal.setdefault("approval_sources", []).append(source_authority_id)
        self._invalidate_after_input_change(proposal)

    def add_evidence(self, *, proposal_id: str, evidence_id: str, evidence_type: str, evidence_url: str, caller: str) -> None:
        proposal = self._proposal(proposal_id)
        if self.now >= proposal["evidence_deadline"]:
            raise ValueError("The evidence deadline has passed")
        if any(item["evidence_id"] == evidence_id for item in proposal["evidence"]):
            raise ValueError("Evidence ID has already been used for this proposal")
        source_authority_id = self._authenticate(
            organization_id=proposal["organization_id"], url=evidence_url,
            scope=evidence_type, caller=caller,
        )
        proposal["evidence"].append({
            "evidence_id": evidence_id,
            "type": evidence_type.upper(),
            "url": evidence_url,
            "source_authority_id": source_authority_id,
        })
        self._invalidate_after_input_change(proposal)

    def open_remediation_window(self, *, proposal_id: str, new_deadline: int, caller: str) -> None:
        proposal = self._proposal(proposal_id)
        organization = self.organizations[proposal["organization_id"]]
        if caller.lower() != organization["owner"]:
            raise ValueError("Only the organization owner can open a remediation window")
        if proposal["status"] not in {"NON_COMPLIANT", "NEEDS_REVIEW"}:
            raise ValueError("Remediation requires a finalized evaluation")
        if self.now < proposal["evidence_deadline"] or new_deadline < self.now + 60:
            raise ValueError("Invalid remediation deadline")
        proposal["evidence_deadline"] = new_deadline
        proposal["deadline_revision"] += 1
        proposal["proposal_digest"] = canonical_hash({
            "proposal_id": proposal["proposal_id"],
            "evidence_deadline": new_deadline,
            "deadline_revision": proposal["deadline_revision"],
        })
        self._invalidate_after_input_change(proposal)

    def _binding(self, proposal: dict) -> str:
        policy = self.policies[(proposal["organization_id"], proposal["policy_id"], proposal["policy_version"])]
        evidence_digest = canonical_hash(sorted((item["type"], item["source_authority_id"]) for item in proposal["evidence"]))
        approval_digest = canonical_hash(sorted(zip(proposal["approval_reviewers"], proposal.get("approval_sources", []))))
        return binding_digest(
            policy_digest=canonical_hash({**policy, "source_authority_revision": self.organizations[proposal["organization_id"]]["source_authority_revision"]}),
            proposal_digest=proposal["proposal_digest"],
            evidence_digest=evidence_digest,
            approval_digest=approval_digest,
            revision=proposal["input_revision"],
        )

    def start_evaluation(self, *, proposal_id: str, citations: list[str] | None = None, fetched_urls: list[str] | None = None) -> dict:
        proposal = self._proposal(proposal_id)
        if self.now < proposal["evidence_deadline"]:
            raise ValueError("Reliable adjudication cannot begin before the evidence deadline")
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
        supplied_citations = citations if citations is not None else [policy["policy_url"], proposal["proposal_url"]]
        authenticated_pages = fetched_urls if fetched_urls is not None else [policy["policy_url"], proposal["proposal_url"], *[item["url"] for item in proposal["evidence"]]]
        reliable = adjudication_reliable(
            sources_authenticated=True,
            citations=supplied_citations,
            fetched_urls=authenticated_pages,
            evaluated_at=self.now,
            evidence_deadline=proposal["evidence_deadline"],
        )
        if not reliable:
            verdict = {
                "status": "NEEDS_REVIEW",
                "reason": "Consensus citations were missing or did not match authenticated fetched pages.",
            }
        sequence = len(proposal["evaluation_history"]) + 1
        evaluation_id = f"{proposal_id}:e{sequence}"
        record = {
            **verdict,
            "evaluation_id": evaluation_id,
            "evaluation_sequence": sequence,
            "previous_evaluation_id": proposal["latest_evaluation_id"],
            "input_revision": proposal["input_revision"],
            "binding_digest": self._binding(proposal),
            "citations": [url for url in supplied_citations if url in authenticated_pages],
            "citations_valid": citations_are_fetched(supplied_citations, authenticated_pages),
            "deadline_satisfied": self.now >= proposal["evidence_deadline"],
            "reliable_adjudication": reliable,
            "evaluated_at": self.now,
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
        if (
            proposal["status"] != "COMPLIANT"
            or latest["binding_digest"] != self._binding(proposal)
            or latest.get("reliable_adjudication") is not True
            or latest.get("evaluated_at", 0) < proposal["evidence_deadline"]
        ):
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
