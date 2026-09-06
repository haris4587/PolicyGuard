# PolicyGuard deployment evidence

This file is the append-only project evidence index for the verified Studionet demonstration. Every transaction below was observed through GenLayer Studio in Normal (Full Consensus) mode with Simulation Mode disabled, allowed to reach `FINALIZED`, and then cross-checked through finalized contract reads.

## Project surfaces

| Item | Verified value |
|---|---|
| GitHub | https://github.com/haris4587/PolicyGuard |
| Website | https://policyguard.ansaf1st33.chatgpt.site |
| Network | GenLayer Studionet · chain 61999 |
| Deployment wallet | [`0x278ad4Ef3419415eA4B41947beD5C69B5195a1FE`](https://explorer-studio.genlayer.com/address/0x278ad4Ef3419415eA4B41947beD5C69B5195a1FE) |
| Contract address | [`0xdD7D1EaC2A2F09602734BC7D6Bb1897ED4487964`](https://explorer-studio.genlayer.com/address/0xdD7D1EaC2A2F09602734BC7D6Bb1897ED4487964) |
| Deployment transaction | [`0x0bb9…b6e3`](https://explorer-studio.genlayer.com/tx/0x0bb9dbcd8741512b277c1b83f87eaf9fda07ead0c9231802884dd7480d40b6e3) |
| Demo bootstrap transaction | [`0xf52d…8c9f`](https://explorer-studio.genlayer.com/tx/0xf52d55432d5d975f3b48aee9969903f3b94508520c730ce226b6e76557638c9f) |
| Missing-audit Full Consensus transaction | [`0xbf95…39d2`](https://explorer-studio.genlayer.com/tx/0xbf95352e985cb1a454baaf44c52e260aefecbffc3fc1ca0186496cddd4e439d2) |
| Audit remediation transaction | [`0x129b…f542`](https://explorer-studio.genlayer.com/tx/0x129b1db674a6bedb4e2c0f28acf5cce8cf3732f86a27b8a8d7f5015196d1f542) |
| Corrected-audit Full Consensus transaction | [`0xeb42…b778`](https://explorer-studio.genlayer.com/tx/0xeb42736834489e3402f50ae945e0e6ca1a6972c892e0544d9080082b49f8b778) |
| Authorization transaction | [`0x55e7…bd30`](https://explorer-studio.genlayer.com/tx/0x55e7adb24cdfab0d386f1431771c47665297e8d8d60efc44cdad541535d1bd30) |
| Execution transaction | [`0x847a…3a61`](https://explorer-studio.genlayer.com/tx/0x847aae7f902edba949f5ec4d23647d2a238f2b7984cc0a7118c74f6b6d353a61) |

## Contract source

| Commitment | Value |
|---|---|
| Source path | `contracts/policy_guard.py` |
| Evidence source commit | [`d37632e7584e1980578c2886b2e1264ba1a61648`](https://github.com/haris4587/PolicyGuard/commit/d37632e7584e1980578c2886b2e1264ba1a61648) |
| Contract source SHA-256 at evidence commit | `317a0e70ac3ad51d1960f7a4d3ffb255292d34ea171374fe8363767c2b07ce8e` |
| Deployment status | `FINALIZED` and contract state readable |

## Stable demo inputs

| Input | SHA-256 |
|---|---|
| DAO grant policy v1 | `62957ed2e2de08939500b3b5a19f2d95102ce458d6a4bd10535a90b9fa38190c` |
| USD 35,000 proposal | `7bd84b46f443e2317bff343d544843309a88d5818f8ffe83979ed438f2c0b5bc` |
| USD 15,000 proposal | `d2d7cb9445fe412c139dc7880569e98033bc6419b1ccd77fe768174f76e1597a` |
| Three-reviewer bundle | `22d8480e63c683e358a7e2add341206fd487f2592b337b76654ce2a697e2276f` |
| Published security audit | `5bb64218abd8cb5896184328be586722a1d62e46ec363be40c803ba36e528f71` |
| Budget evidence | `c4883467e7b54ce45422ce277c9037fafe505c65ffedcf8c0d2ac45501aa0697` |

The immutable evidence commit is recorded in `demo/manifest.json`. Exact validator inputs:

- [DAO grant policy v1](https://raw.githubusercontent.com/haris4587/PolicyGuard/d37632e7584e1980578c2886b2e1264ba1a61648/demo/policy/dao-grant-policy-v1.md)
- [USD 35,000 grant proposal](https://raw.githubusercontent.com/haris4587/PolicyGuard/d37632e7584e1980578c2886b2e1264ba1a61648/demo/proposals/grant-35000.md)
- [USD 15,000 grant proposal](https://raw.githubusercontent.com/haris4587/PolicyGuard/d37632e7584e1980578c2886b2e1264ba1a61648/demo/proposals/grant-15000.md)
- [Three-reviewer approval bundle](https://raw.githubusercontent.com/haris4587/PolicyGuard/d37632e7584e1980578c2886b2e1264ba1a61648/demo/evidence/reviewer-approvals.md)
- [Published security audit](https://raw.githubusercontent.com/haris4587/PolicyGuard/d37632e7584e1980578c2886b2e1264ba1a61648/demo/evidence/security-audit.md)
- [Budget evidence](https://raw.githubusercontent.com/haris4587/PolicyGuard/d37632e7584e1980578c2886b2e1264ba1a61648/demo/evidence/budget-evidence.md)

## Required verdict record

### Evaluation #1 — missing audit

| Field | Verified value |
|---|---|
| Proposal | `policyguard-demo-35000` |
| Evaluation ID | `policyguard-demo-35000:e1` |
| Status | `NON_COMPLIANT` |
| Reason | `Required security audit is missing.` |
| Approval count | 3 |
| Missing requirement | `Published security audit` |
| Evidence quality | 60 / 100 · `HIGH` confidence |
| Evidence-set digest | `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` |
| Recorded at | `2026-09-06T06:14:20Z` · sequence 1 |
| Authorization | Blocked by contract |
| Transaction | [`0xbf95352e985cb1a454baaf44c52e260aefecbffc3fc1ca0186496cddd4e439d2`](https://explorer-studio.genlayer.com/tx/0xbf95352e985cb1a454baaf44c52e260aefecbffc3fc1ca0186496cddd4e439d2) |

### Evaluation #2 — remediated

| Field | Verified value |
|---|---|
| Previous evaluation | `policyguard-demo-35000:e1` |
| Audit digest | `5bb64218abd8cb5896184328be586722a1d62e46ec363be40c803ba36e528f71` |
| Evaluation ID | `policyguard-demo-35000:e2` |
| Status | `COMPLIANT` |
| Missing requirements | None |
| Evidence quality | 88 / 100 · `HIGH` confidence |
| Evidence-set digest | `19517df0ad531fa92cc8c4dba830adec3350a18a3c4ea8fc761b0199dc21c538` |
| Binding digest | `c1a29aacb6c169869a2f4290d1f7ab6362afead74b43dafcc25677e9d6e47b85` |
| Recorded at | `2026-09-06T06:17:09Z` · sequence 2 |
| Transaction | [`0xeb42736834489e3402f50ae945e0e6ca1a6972c892e0544d9080082b49f8b778`](https://explorer-studio.genlayer.com/tx/0xeb42736834489e3402f50ae945e0e6ca1a6972c892e0544d9080082b49f8b778) |

Finalized `get_evaluation_history("policyguard-demo-35000")` returned both `e1` and `e2`; remediation did not replace the original non-compliant result.

## Authorization and execution record

| Field | Verified value |
|---|---|
| Authorization ID | `policyguard-demo-35000:auth:policyguard-demo-35000:e2` |
| Bound evaluation | `policyguard-demo-35000:e2` |
| Binding digest | `c1a29aacb6c169869a2f4290d1f7ab6362afead74b43dafcc25677e9d6e47b85` |
| Authorized at | `2026-09-06T06:20:00Z` |
| Executed at | `2026-09-06T06:21:03Z` |
| Execution reference | `PolicyGuard Studionet demo execution authorization` |
| Final proposal state | `EXECUTED` |

The execution is an auditable PolicyGuard lifecycle record; it does not transfer real treasury assets.

## Local verification evidence

The repository's clean verification command is:

```bash
npm ci
python3 -m pip install -r requirements-dev.txt
npm run typecheck
npm test
```

The exact verified deployment configuration is machine-readable in `config/deployment.json`. GitHub Actions repeats the repository verification command on every `main` update.
