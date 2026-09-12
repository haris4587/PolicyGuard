import pytest

from policyguard_model import (
    WorkflowModel,
    adjudication_reliable,
    binding_digest,
    can_authorize,
    citations_are_fetched,
    evaluate_gate,
    source_authorized,
    valid_sha256,
    validate_url,
)


REVIEWERS = [
    "0x1111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222",
    "0x3333333333333333333333333333333333333333",
]


def test_missing_audit_is_non_compliant_with_exact_reason():
    verdict = evaluate_gate(amount_usd=35_000, approval_wallets=REVIEWERS)
    assert verdict == {"status": "NON_COMPLIANT", "reason": "Required security audit is missing."}


def test_corrected_audit_is_compliant():
    verdict = evaluate_gate(amount_usd=35_000, approval_wallets=REVIEWERS, evidence_types=["AUDIT"])
    assert verdict["status"] == "COMPLIANT"


def test_below_threshold_uses_applicable_requirements():
    verdict = evaluate_gate(amount_usd=15_000, approval_wallets=[], evidence_types=[])
    assert verdict["status"] == "COMPLIANT"


def test_insufficient_approvals_is_non_compliant():
    verdict = evaluate_gate(amount_usd=35_000, approval_wallets=REVIEWERS[:2], evidence_types=["AUDIT"])
    assert verdict["reason"] == "Insufficient reviewer approvals."


def test_duplicate_reviewer_approval_is_rejected():
    with pytest.raises(ValueError, match="duplicate reviewer"):
        evaluate_gate(amount_usd=35_000, approval_wallets=[REVIEWERS[0], REVIEWERS[0]], evidence_types=["AUDIT"])


def test_policy_or_proposal_digest_mismatch_needs_review():
    verdict = evaluate_gate(amount_usd=35_000, approval_wallets=REVIEWERS, evidence_types=["AUDIT"], sources_authenticated=False)
    assert verdict == {"status": "NEEDS_REVIEW", "reason": "Policy or proposal digest mismatch."}


@pytest.mark.parametrize("url", [
    "http://example.com/evidence.md",
    "https://localhost/evidence.md",
    "https://127.0.0.1/evidence.md",
    "https://example.com/evidence.md?mutable=1",
    "https://raw.githubusercontent.com@evil.example/evidence.md",
    "https://raw.githubusercontent.com:443/evidence.md",
    "not-a-url",
])
def test_invalid_or_unsupported_evidence_url(url):
    assert not validate_url(url)


def test_valid_public_https_evidence_url():
    assert validate_url("https://raw.githubusercontent.com/haris4587/PolicyGuard/main/demo/evidence/security-audit.md")


def test_source_authority_uses_exact_hostname_issuer_and_scope():
    base = {
        "allowed_hostname": "raw.githubusercontent.com",
        "caller": REVIEWERS[0],
        "issuer_wallet": REVIEWERS[0],
        "scope": "AUDIT",
        "allowed_scopes": ["EVIDENCE"],
    }
    assert source_authorized(
        url="https://raw.githubusercontent.com/haris4587/PolicyGuard/commit/audit.md",
        **base,
    )
    assert not source_authorized(
        url="https://raw.githubusercontent.com.evil.example/haris4587/PolicyGuard/audit.md",
        **base,
    )
    assert not source_authorized(
        url="https://raw.githubusercontent.com/haris4587/PolicyGuard/commit/audit.md",
        **{**base, "caller": REVIEWERS[1]},
    )


def test_citations_must_be_exact_fetched_pages_and_deadline_must_pass():
    fetched = ["https://evidence.example.org/policy.md", "https://evidence.example.org/proposal.md"]
    assert citations_are_fetched([fetched[0]], fetched)
    assert not citations_are_fetched(["https://claimant.example.org/assertion.md"], fetched)
    assert not adjudication_reliable(
        sources_authenticated=True,
        citations=[fetched[0]],
        fetched_urls=fetched,
        evaluated_at=99,
        evidence_deadline=100,
    )
    assert adjudication_reliable(
        sources_authenticated=True,
        citations=[fetched[0]],
        fetched_urls=fetched,
        evaluated_at=100,
        evidence_deadline=100,
    )


def test_malformed_consensus_response_fails_closed():
    verdict = evaluate_gate(amount_usd=35_000, approval_wallets=REVIEWERS, evidence_types=["AUDIT"], malformed_consensus=True)
    assert verdict["status"] == "NEEDS_REVIEW"


def test_stale_verdict_cannot_authorize():
    evaluated = binding_digest(policy_digest="a" * 64, proposal_digest="b" * 64, evidence_digest="c" * 64, approval_digest="d" * 64, revision=3)
    changed = binding_digest(policy_digest="a" * 64, proposal_digest="b" * 64, evidence_digest="e" * 64, approval_digest="d" * 64, revision=4)
    assert not can_authorize(latest_status="COMPLIANT", evaluated_binding=evaluated, current_binding=changed, caller_is_owner=True)


def test_re_evaluation_preserves_original_result():
    history = []
    history.append(evaluate_gate(amount_usd=35_000, approval_wallets=REVIEWERS))
    history.append(evaluate_gate(amount_usd=35_000, approval_wallets=REVIEWERS, evidence_types=["AUDIT"]))
    assert [item["status"] for item in history] == ["NON_COMPLIANT", "COMPLIANT"]


def test_unauthorized_execution_or_authorization_is_rejected():
    binding = binding_digest(policy_digest="a" * 64, proposal_digest="b" * 64, evidence_digest="c" * 64, approval_digest="d" * 64, revision=3)
    assert not can_authorize(latest_status="COMPLIANT", evaluated_binding=binding, current_binding=binding, caller_is_owner=False)


def test_sha256_validation():
    assert valid_sha256("a" * 64)
    assert not valid_sha256("A" * 64)
    assert not valid_sha256("abc")


def test_new_organization_policy_proposal_completes_full_mapped_workflow():
    """A fresh user-created case can traverse every mapped contract action."""

    owner = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    reviewers = [
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333",
    ]
    workflow = WorkflowModel()

    workflow.create_organization(
        organization_id="new-org",
        name="New Organization",
        owner=owner,
    )
    source_url = "https://evidence.example.org/policyguard/document.md"
    workflow.register_source_authority(
        organization_id="new-org",
        authority_id="owner-source",
        hostname="evidence.example.org",
        issuer_wallet=owner,
        scopes=["POLICY", "PROPOSAL", "EVIDENCE"],
        caller=owner,
    )
    for reviewer in reviewers:
        workflow.add_reviewer(
            organization_id="new-org",
            reviewer=reviewer,
            caller=owner,
        )
        workflow.register_source_authority(
            organization_id="new-org",
            authority_id=f"reviewer-{reviewers.index(reviewer) + 1}",
            hostname="evidence.example.org",
            issuer_wallet=reviewer,
            scopes=["REVIEWER_APPROVAL"],
            caller=owner,
        )
    workflow.register_policy_version(
        organization_id="new-org",
        policy_id="new-policy",
        version=1,
        threshold_usd=20_000,
        required_approvals=3,
        required_document_types=["AUDIT"],
        baseline_document_types=[],
        policy_url=source_url,
        caller=owner,
    )
    workflow.create_proposal(
        proposal_id="new-proposal",
        organization_id="new-org",
        policy_id="new-policy",
        policy_version=1,
        amount_usd=35_000,
        proposer=owner,
        executor=owner,
        proposal_url=source_url,
        evidence_deadline=workflow.now + 120,
    )

    for reviewer in reviewers:
        workflow.approve_proposal(proposal_id="new-proposal", reviewer=reviewer, proof_url=source_url)
    with pytest.raises(ValueError, match="before the evidence deadline"):
        workflow.start_evaluation(proposal_id="new-proposal")
    workflow.now += 120
    first = workflow.start_evaluation(proposal_id="new-proposal")
    assert first["status"] == "NON_COMPLIANT"
    assert first["reason"] == "Required security audit is missing."

    workflow.open_remediation_window(
        proposal_id="new-proposal",
        new_deadline=workflow.now + 60,
        caller=owner,
    )
    workflow.add_evidence(
        proposal_id="new-proposal",
        evidence_id="security-audit",
        evidence_type="AUDIT",
        evidence_url=source_url,
        caller=owner,
    )
    with pytest.raises(ValueError, match="before the evidence deadline"):
        workflow.start_evaluation(proposal_id="new-proposal")
    workflow.now += 60
    second = workflow.start_evaluation(proposal_id="new-proposal")
    assert second["status"] == "COMPLIANT"
    assert second["previous_evaluation_id"] == first["evaluation_id"]

    authorization = workflow.authorize_action(proposal_id="new-proposal", caller=owner)
    assert authorization["evaluation_id"] == second["evaluation_id"]
    executed = workflow.execute_action(
        proposal_id="new-proposal",
        execution_reference="new-org-execution-001",
        caller=owner,
    )
    assert executed["status"] == "EXECUTED"
    assert workflow.proposals["new-proposal"]["evaluation_history"] == [
        first["evaluation_id"],
        second["evaluation_id"],
    ]


def test_public_claimant_cannot_add_evidence_without_source_issuer_authority():
    owner = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    claimant = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    source_url = "https://evidence.example.org/document.md"
    workflow = WorkflowModel()
    workflow.create_organization(organization_id="secure-org", name="Secure Org", owner=owner)
    workflow.register_source_authority(
        organization_id="secure-org", authority_id="owner-source",
        hostname="evidence.example.org", issuer_wallet=owner,
        scopes=["POLICY", "PROPOSAL", "EVIDENCE"], caller=owner,
    )
    workflow.register_policy_version(
        organization_id="secure-org", policy_id="secure-policy", version=1,
        threshold_usd=20_000, required_approvals=0, required_document_types=[],
        baseline_document_types=[], policy_url=source_url, caller=owner,
    )
    workflow.create_proposal(
        proposal_id="secure-proposal", organization_id="secure-org",
        policy_id="secure-policy", policy_version=1, amount_usd=1,
        proposer=owner, executor=owner, proposal_url=source_url,
        evidence_deadline=workflow.now + 120,
    )
    with pytest.raises(ValueError, match="not authorized"):
        workflow.add_evidence(
            proposal_id="secure-proposal", evidence_id="claimant-page",
            evidence_type="OTHER", evidence_url=source_url, caller=claimant,
        )


def test_unfetched_model_citation_forces_needs_review():
    owner = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    source_url = "https://evidence.example.org/document.md"
    workflow = WorkflowModel()
    workflow.create_organization(organization_id="cited-org", name="Cited Org", owner=owner)
    workflow.register_source_authority(
        organization_id="cited-org", authority_id="owner-source",
        hostname="evidence.example.org", issuer_wallet=owner,
        scopes=["POLICY", "PROPOSAL"], caller=owner,
    )
    workflow.register_policy_version(
        organization_id="cited-org", policy_id="cited-policy", version=1,
        threshold_usd=20_000, required_approvals=0, required_document_types=[],
        baseline_document_types=[], policy_url=source_url, caller=owner,
    )
    workflow.create_proposal(
        proposal_id="cited-proposal", organization_id="cited-org",
        policy_id="cited-policy", policy_version=1, amount_usd=1,
        proposer=owner, executor=owner, proposal_url=source_url,
        evidence_deadline=workflow.now + 60,
    )
    workflow.now += 60
    verdict = workflow.start_evaluation(
        proposal_id="cited-proposal",
        citations=["https://claimant.example.org/unfetched.md"],
        fetched_urls=[source_url],
    )
    assert verdict["status"] == "NEEDS_REVIEW"
    assert verdict["citations_valid"] is False
    assert verdict["reliable_adjudication"] is False


def test_revoked_source_authority_invalidates_a_compliant_binding():
    owner = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    source_url = "https://evidence.example.org/document.md"
    workflow = WorkflowModel()
    workflow.create_organization(organization_id="revoked-org", name="Revoked Org", owner=owner)
    workflow.register_source_authority(
        organization_id="revoked-org", authority_id="owner-source",
        hostname="evidence.example.org", issuer_wallet=owner,
        scopes=["POLICY", "PROPOSAL"], caller=owner,
    )
    workflow.register_policy_version(
        organization_id="revoked-org", policy_id="revoked-policy", version=1,
        threshold_usd=20_000, required_approvals=0, required_document_types=[],
        baseline_document_types=[], policy_url=source_url, caller=owner,
    )
    workflow.create_proposal(
        proposal_id="revoked-proposal", organization_id="revoked-org",
        policy_id="revoked-policy", policy_version=1, amount_usd=1,
        proposer=owner, executor=owner, proposal_url=source_url,
        evidence_deadline=workflow.now + 60,
    )
    workflow.now += 60
    assert workflow.start_evaluation(proposal_id="revoked-proposal")["status"] == "COMPLIANT"
    workflow.revoke_source_authority(
        organization_id="revoked-org", authority_id="owner-source", caller=owner,
    )
    with pytest.raises(ValueError, match="stale"):
        workflow.authorize_action(proposal_id="revoked-proposal", caller=owner)
