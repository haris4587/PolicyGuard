# Steward hardening response

This change closes the four adjudication-integrity gaps identified in the steward request. The controls are enforced by contract state and are not frontend-only checks.

## Requirement mapping

| Steward concern | Contract control | Verification |
|---|---|---|
| Claimant-selected sources | Organization owners register an immutable source-authority ID that binds one exact DNS hostname, one issuer wallet, and explicit scopes. Policy, proposal, evidence, and approval writes must authenticate against an active authority. | `test_source_authority_uses_exact_hostname_issuer_and_scope`; `test_public_claimant_cannot_add_evidence_without_source_issuer_authority` |
| Public evidence additions | `add_evidence` no longer grants access merely because the caller is the owner or proposer. The caller must be the registered issuer for the exact host and evidence scope, and the evidence window must be open. | `test_public_claimant_cannot_add_evidence_without_source_issuer_authority`; full mapped workflow test |
| Permissive hostname matching | URLs reject userinfo, ports, percent-encoded authority data, queries, fragments, IP literals, and non-canonical hostnames. Source authorization uses normalized exact equality, never substring or suffix matching. | parameterized URL tests; crafted `raw.githubusercontent.com.evil.example` test; contract verifier legacy-pattern denylist |
| Citations outside fetched pages | Model citations are accepted only when every stored citation exactly equals a successfully fetched, digest-verified, authority-authenticated page URL. Missing or foreign citations force `NEEDS_REVIEW`; they are never silently replaced. Validators independently check proposed citations against their own fetched-page set. | `test_citations_must_be_exact_fetched_pages_and_deadline_must_pass`; `test_unfetched_model_citation_forces_needs_review` |
| Resolution before the stated deadline | Every proposal stores `evidence_deadline` and `deadline_revision`. Evidence and approvals close at the deadline; evaluation is rejected before it. Authorization requires a reliable evaluation recorded at or after the bound deadline. A recorded remediation window creates a new future deadline, increments the revision, and invalidates the old binding. | pre-deadline failures and post-deadline completion in `test_new_organization_policy_proposal_completes_full_mapped_workflow` |

## Reliable-adjudication invariant

`COMPLIANT` or `NON_COMPLIANT` is treated as reliable only when all of the following are true:

1. Every source authority is active and still matches the stored exact hostname, issuer wallet, and scope.
2. Every fetched page matches its committed SHA-256 digest.
3. Every citation is an exact member of the independently fetched and verified page set.
4. The evaluation timestamp is at or after the proposal's current evidence deadline.
5. The current policy, proposal, evidence, approval, deadline, and source-authority binding matches the immutable evaluation.

Any failure is rejected or normalized to `NEEDS_REVIEW`. Authorization and execution recheck the reliability and binding gates from contract state.

## Reviewer reproduction

```bash
npm ci
python3 -m pip install -r requirements-dev.txt
npm run typecheck
npm test
```

The full mapped workflow test creates a fresh organization, source authorities, reviewer roster, policy, and proposal; proves that pre-deadline evaluation fails; reaches a reliable missing-audit verdict after the deadline; opens a recorded remediation window; adds issuer-authenticated audit evidence; proves early re-evaluation fails again; and completes authorization and execution only after the second deadline.
