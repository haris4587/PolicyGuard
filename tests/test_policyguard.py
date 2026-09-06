import pytest

from policyguard_model import (
    binding_digest,
    can_authorize,
    evaluate_gate,
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
    "not-a-url",
])
def test_invalid_or_unsupported_evidence_url(url):
    assert not validate_url(url)


def test_valid_public_https_evidence_url():
    assert validate_url("https://raw.githubusercontent.com/haris4587/PolicyGuard/main/demo/evidence/security-audit.md")


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
