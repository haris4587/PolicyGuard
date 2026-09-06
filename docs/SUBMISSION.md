# Builder submission package

## Category

**Builder → Projects**

PolicyGuard is a complete wallet-connected application, deployed Intelligent Contract, public website, tests, evidence bundle, and documented lifecycle. It should not be submitted only as an Intelligent Contract.

## Title

**PolicyGuard — Consensus-Enforced Policy Compliance**

## Description

PolicyGuard turns human-written organizational rules into auditable execution gates. Organizations register versioned policies with SHA-256 commitments, create proposals, collect duplicate-protected reviewer approvals, and append real-world evidence. GenLayer validators independently fetch the committed bytes and interpret whether the action complies, returning a normalized COMPLIANT, NON_COMPLIANT, or NEEDS_REVIEW verdict with reasons, requirements, citations, evidence digests, and quality scoring. Every recheck preserves earlier results. Authorization is impossible unless the latest finalized compliant verdict still matches the current policy version, proposal, evidence set, approval set, and input revision. The live demo blocks a USD 35,000 DAO grant when its required security audit is missing, then supports audit remediation and a new Full Consensus evaluation.

Character count: 879 including spaces (recheck if edited).

## Tags

- Primary: **Governance**
- Supporting: **AI**
- Supporting: **Security**

## Link fields

Use one URL per platform link field:

| Field | URL |
|---|---|
| Website | https://policyguard.ansaf1st33.chatgpt.site |
| GitHub | https://github.com/haris4587/PolicyGuard |
| Contract | Pending verified address URL |
| Deployment evidence | https://github.com/haris4587/PolicyGuard/blob/main/EVIDENCE.md |
| Full Consensus transaction | Pending verified transaction URL |
| Policy | Pending commit-pinned raw URL |
| Proposal | Pending commit-pinned raw URL |
| Reviewer approvals | Pending commit-pinned raw URL |
| Security audit | Pending commit-pinned raw URL |

## Evidence summary

- Stable Studionet contract address and deployment transaction.
- Full Consensus transaction for three approvals plus missing audit.
- Contract read showing `NON_COMPLIANT` and exact missing-audit reason.
- Commit-pinned source URLs with exact SHA-256 hashes.
- Re-evaluation history preserving the original result.
- Wallet-connected public application and reproducible build/tests.

## Screenshot checklist

- [ ] Connected MetaMask address and Studionet badge.
- [ ] Missing-audit `NON_COMPLIANT` verdict with exact reason.
- [ ] Full Consensus transaction shown as finalized and successful.
- [ ] Evaluation timeline showing immutable revisions.
- [ ] Corrected audit and compliant re-evaluation, if completed.
- [ ] Authorization binding / authorized state.
- [ ] GenLayer Studio contract source and address.
- [ ] GitHub repository root and passing CI.
- [ ] Mobile responsive website view.

## Honest disclosure

This is an open-source prototype. The on-chain execution method records authorization/execution state but does not transfer DAO treasury assets in Studio. Production use requires an audited execution adapter and organization-specific source-authority rules.
