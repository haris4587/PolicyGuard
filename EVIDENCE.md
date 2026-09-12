# PolicyGuard deployment evidence

This is the verified evidence index for the steward-hardened PolicyGuard v1.1.0 deployment. Every transaction listed below was submitted in GenLayer Studio with **Normal (Full Consensus)** selected and Simulation Mode disabled, reached `FINALIZED`, and was checked through finalized contract reads.

## Project surfaces

| Item | Verified value |
|---|---|
| GitHub | https://github.com/haris4587/PolicyGuard |
| Website | https://policyguard.ansaf1st33.chatgpt.site |
| Network | GenLayer Studionet · chain 61999 |
| Deployment wallet | [`0x4a98BfEaD6323252dE454CA5A6E708980d5775aa`](https://explorer-studio.genlayer.com/address/0x4a98BfEaD6323252dE454CA5A6E708980d5775aa) |
| Contract address | [`0xd1ff82eeF6F8bcB7FAD0c96b9787A16Edf7ebDa4`](https://explorer-studio.genlayer.com/address/0xd1ff82eeF6F8bcB7FAD0c96b9787A16Edf7ebDa4) |
| Deployment transaction | [`0xc19d…9596`](https://explorer-studio.genlayer.com/tx/0xc19db98f79d63829701b98168257f48fcf3bb562036891f173f1129861699596) |
| Demo bootstrap | [`0x2a57…38a0`](https://explorer-studio.genlayer.com/tx/0x2a571da7c5edeb01c4fa9d73a6a112548b5457522d93b735b23cd81b0f4f38a0) |
| Missing-audit evaluation | [`0x860e…7788`](https://explorer-studio.genlayer.com/tx/0x860e7fc4b0e38dd4d79825d21979cb3fda70e901a45c645fa000103e83277788) |
| Remediation window | [`0xf3d7…6e86`](https://explorer-studio.genlayer.com/tx/0xf3d7c3be0a907a73316ca8f75b7ced59e4ad507e53e934e17190beb7a87f6e86) |
| Audit evidence | [`0x0a7f…e21f`](https://explorer-studio.genlayer.com/tx/0x0a7fb5542c641cf56ebd3ae380344a9dda85bf953692bffc0dc32674882ae21f) |
| Corrected evaluation | [`0x3d44…e45a`](https://explorer-studio.genlayer.com/tx/0x3d44dcf550ea491961a270709856ce29c7924640f5ba78a8eb78c3432812e45a) |
| Authorization | [`0x70a7…fc00`](https://explorer-studio.genlayer.com/tx/0x70a77d02cdccde755be04f2dfb166bea4a3c263863badcc17b614e9f6e63fc00) |
| Execution | [`0x6e99…5b8a`](https://explorer-studio.genlayer.com/tx/0x6e9979db81acd8e97d1cb83315879df7a8cf2e10f5885adee40eefdd86c75b8a) |

## Contract source commitment

| Commitment | Value |
|---|---|
| Source path | `contracts/policy_guard.py` |
| Deployed source commit | [`b751247b32269dad7c3f3f82484e35c6871e9cb5`](https://github.com/haris4587/PolicyGuard/commit/b751247b32269dad7c3f3f82484e35c6871e9cb5) |
| Contract source SHA-256 | `eafe9714fc3ea5fab9b2016bf17ade13d433281071cd77bd5122e38177cf5bfc` |
| Deployment result | `FINALIZED`; constructor state was readable and reported owner `0x4a98…75aa` with all counters at zero |

The demo documents remain pinned to immutable evidence commit `d37632e7584e1980578c2886b2e1264ba1a61648` and are checked against the SHA-256 values in `demo/manifest.json`.

## Steward-control evidence

The bootstrap registered four exact-host source authorities: one owner authority for policy, proposal, evidence, and audit scopes, plus three reviewer-wallet authorities for reviewer approvals. The finalized evaluation records identify the authority ID and issuer wallet for every fetched document.

Every stored citation in both evaluations is an exact member of that evaluation's `evidence_digests[].url` set. Each cited member returned `authenticated: true`, `status: VERIFIED`, and an actual SHA-256 equal to its committed SHA-256.

### Evaluation #1 — missing audit

| Field | Finalized value |
|---|---|
| Proposal / evaluation | `policyguard-demo-35000` / `policyguard-demo-35000:e1` |
| Status | `NON_COMPLIANT` |
| Reason | `Required security audit is missing.` |
| Missing requirement | `Published security audit` |
| Deadline | `2026-09-12T23:36:32Z` · revision 1 |
| Evaluated | `2026-09-12T23:37:40Z` · after deadline |
| Deadline satisfied | `true` |
| Citations valid | `true` |
| Reliable adjudication | `true` |
| Source status | `VERIFIED` |
| Source-authority digest | `b096b560f3f10199b721c33c2703f31aedfbf1f93104fde668538fd534ed05a6` |
| Binding digest | `67197e986dca93e248b39f02f9eaee6121075c62c0edd4d2caf1867d6e220567` |
| Evidence-set digest | `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` |
| Confidence | `HIGH` |
| Transaction | [`0x860e7fc4b0e38dd4d79825d21979cb3fda70e901a45c645fa000103e83277788`](https://explorer-studio.genlayer.com/tx/0x860e7fc4b0e38dd4d79825d21979cb3fda70e901a45c645fa000103e83277788) |

The first verdict cited only the fetched policy and proposal pages. It did not invent or substitute an audit citation, and authorization remained unavailable because the status was not compliant.

### Remediation and evaluation #2

The owner opened deadline revision 2, then added the commit-pinned security audit before that deadline through the active owner authority. Re-evaluation was performed only after the recorded deadline.

| Field | Finalized value |
|---|---|
| Previous evaluation | `policyguard-demo-35000:e1` |
| Evaluation | `policyguard-demo-35000:e2` |
| Audit SHA-256 | `5bb64218abd8cb5896184328be586722a1d62e46ec363be40c803ba36e528f71` |
| Deadline | `2026-09-12T23:43:19Z` · revision 2 |
| Evaluated | `2026-09-12T23:44:52Z` · after deadline |
| Status | `COMPLIANT` |
| Missing requirements | None |
| Deadline satisfied | `true` |
| Citations valid | `true` |
| Reliable adjudication | `true` |
| Source status | `VERIFIED` |
| Source-authority digest | `6b8655cc2dc71623febb38db81b5432e54ee5d8b0d9e7ae6cc97221a3602737c` |
| Binding digest | `880130496f2146c654b7f9151e72190972147299088c532a3593d119c36ab195` |
| Evidence-set digest | `8abe512f0ef25814055cc2e765e5957c4895126cae49d7cdc155199232c1aaa9` |
| Confidence | `HIGH` |
| Transaction | [`0x3d44dcf550ea491961a270709856ce29c7924640f5ba78a8eb78c3432812e45a`](https://explorer-studio.genlayer.com/tx/0x3d44dcf550ea491961a270709856ce29c7924640f5ba78a8eb78c3432812e45a) |

Evaluation #2 cited exactly four fetched, authenticated pages: the policy, proposal, security audit, and reviewer-approval bundle. Evaluation #1 remained readable through finalized state.

## Authorization and execution

| Field | Finalized value |
|---|---|
| Authorization ID | `policyguard-demo-35000:auth:policyguard-demo-35000:e2` |
| Bound evaluation | `policyguard-demo-35000:e2` |
| Binding digest | `880130496f2146c654b7f9151e72190972147299088c532a3593d119c36ab195` |
| Authorized at | `2026-09-12T23:46:43Z` |
| Executed at | `2026-09-12T23:48:35Z` |
| Execution reference | `policyguard-steward-live-2026-09-12` |
| Final proposal state | `EXECUTED` |

Finalized `get_protocol_stats()` returned:

```json
{"approvals":3,"audit_events":8,"authorizations":1,"demo_seeded":true,"evaluations":2,"evidence_items":1,"executions":1,"organizations":1,"policy_versions":1,"proposals":1,"source_authorities":4}
```

The execution is an auditable PolicyGuard lifecycle record; it does not transfer real treasury assets.

## Reproducible verification

```bash
npm ci
python3 -m pip install -r requirements-dev.txt
npm run typecheck
npm test
```

The machine-readable deployment record is `config/deployment.json`. GitHub Actions repeats repository verification on every `main` update.
