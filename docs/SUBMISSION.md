# Builder submission package

## Category

**Builder → Projects**

PolicyGuard is a complete wallet-connected application, deployed Intelligent Contract, public website, tests, evidence bundle, and documented lifecycle. It should not be submitted only as an Intelligent Contract.

## Title

**PolicyGuard — Consensus-Enforced Policy Compliance**

## Description

PolicyGuard turns human-written organizational rules into auditable execution gates. Organization owners register source authorities that bind an exact hostname, issuer wallet, and allowed scopes. Proposals carry an on-chain evidence deadline; policy, proposal, evidence, and approval records must authenticate against an active authority. After the deadline, GenLayer validators independently fetch digest-bound pages and accept only citations that exactly match those fetched pages. Every recheck preserves earlier results. Authorization is impossible unless the latest compliant verdict is marked reliable and still matches the current policy, proposal, evidence, approvals, deadline, source authorities, and input revision. The live demo blocks a USD 35,000 DAO grant when its required security audit is missing, then uses a recorded remediation window before a new Full Consensus evaluation.

Character count: 896 including spaces.

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
| Contract | https://explorer-studio.genlayer.com/address/0xd1ff82eeF6F8bcB7FAD0c96b9787A16Edf7ebDa4 |
| Deployment evidence | https://github.com/haris4587/PolicyGuard/blob/main/EVIDENCE.md |
| Missing-audit Full Consensus | https://explorer-studio.genlayer.com/tx/0x860e7fc4b0e38dd4d79825d21979cb3fda70e901a45c645fa000103e83277788 |
| Remediation deadline | https://explorer-studio.genlayer.com/tx/0xf3d7c3be0a907a73316ca8f75b7ced59e4ad507e53e934e17190beb7a87f6e86 |
| Authenticated audit | https://explorer-studio.genlayer.com/tx/0x0a7fb5542c641cf56ebd3ae380344a9dda85bf953692bffc0dc32674882ae21f |
| Corrected Full Consensus | https://explorer-studio.genlayer.com/tx/0x3d44dcf550ea491961a270709856ce29c7924640f5ba78a8eb78c3432812e45a |
| Authorization | https://explorer-studio.genlayer.com/tx/0x70a77d02cdccde755be04f2dfb166bea4a3c263863badcc17b614e9f6e63fc00 |
| Execution | https://explorer-studio.genlayer.com/tx/0x6e9979db81acd8e97d1cb83315879df7a8cf2e10f5885adee40eefdd86c75b8a |
| Policy | https://raw.githubusercontent.com/haris4587/PolicyGuard/d37632e7584e1980578c2886b2e1264ba1a61648/demo/policy/dao-grant-policy-v1.md |
| Proposal | https://raw.githubusercontent.com/haris4587/PolicyGuard/d37632e7584e1980578c2886b2e1264ba1a61648/demo/proposals/grant-35000.md |
| Reviewer approvals | https://raw.githubusercontent.com/haris4587/PolicyGuard/d37632e7584e1980578c2886b2e1264ba1a61648/demo/evidence/reviewer-approvals.md |
| Security audit | https://raw.githubusercontent.com/haris4587/PolicyGuard/d37632e7584e1980578c2886b2e1264ba1a61648/demo/evidence/security-audit.md |

## Evidence summary

- Stable Studionet contract and finalized deployment transaction.
- Finalized Full Consensus transaction for three approvals plus missing audit.
- Finalized contract read showing `NON_COMPLIANT` and exact missing-audit reason.
- Commit-pinned source URLs with exact SHA-256 hashes.
- Exact-host source authorities with issuer-wallet and scope authentication.
- Contract-state evidence deadlines and rejection of premature adjudication.
- Citation membership checked against independently fetched authenticated pages.
- Corrected Full Consensus result `COMPLIANT`, with re-evaluation history preserving the original result.
- Authorization bound to evaluation #2 and a completed `EXECUTED` lifecycle record.
- Wallet-connected public application and reproducible build/tests.

## Screenshot checklist

- [ ] Connected MetaMask address and Studionet badge on the public app.
- [ ] Missing-audit `NON_COMPLIANT` verdict with exact reason in timeline evaluation #1.
- [ ] Missing-audit transaction `0x860e…7788` shown as `FINALIZED`.
- [ ] Evaluation timeline showing immutable `e1` and `e2` revisions.
- [ ] Published audit and corrected `COMPLIANT` evaluation #2.
- [ ] Authorization binding and final `EXECUTED` proposal state.
- [ ] GenLayer Studio contract source and `0xd1ff…bDa4` address.
- [ ] GitHub repository root and passing CI.
- [ ] Mobile responsive website view at 390 px width.

## Honest disclosure

This is an open-source prototype. The on-chain execution method records authorization/execution state but does not transfer DAO treasury assets in Studio. Production use requires an audited execution adapter and organization-specific source-authority rules.
