# PolicyGuard deployment evidence

This file is an append-only project evidence index. Placeholder values are not claims of deployment. They are replaced only after an independently checked Studio or explorer record confirms the transaction and execution result.

## Project surfaces

| Item | Verified value |
|---|---|
| GitHub | https://github.com/haris4587/PolicyGuard |
| Website | https://policyguard.ansaf1st33.chatgpt.site |
| Network | GenLayer Studionet · chain 61999 |
| Contract address | Pending |
| Deployment transaction | Pending |
| Missing-audit Full Consensus transaction | Pending |
| Corrected-audit Full Consensus transaction | Pending |
| Authorization transaction | Pending |

## Contract source

| Commitment | Value |
|---|---|
| Source path | `contracts/policy_guard.py` |
| Source commit | Pending final deployed source commit |
| Source SHA-256 | Pending final deployed source digest |
| Deployment status | Pending |

## Stable demo inputs

| Input | SHA-256 |
|---|---|
| DAO grant policy v1 | `62957ed2e2de08939500b3b5a19f2d95102ce458d6a4bd10535a90b9fa38190c` |
| USD 35,000 proposal | `7bd84b46f443e2317bff343d544843309a88d5818f8ffe83979ed438f2c0b5bc` |
| USD 15,000 proposal | `d2d7cb9445fe412c139dc7880569e98033bc6419b1ccd77fe768174f76e1597a` |
| Three-reviewer bundle | `22d8480e63c683e358a7e2add341206fd487f2592b337b76654ce2a697e2276f` |
| Published security audit | `5bb64218abd8cb5896184328be586722a1d62e46ec363be40c803ba36e528f71` |
| Budget evidence | `c4883467e7b54ce45422ce277c9037fafe505c65ffedcf8c0d2ac45501aa0697` |

The immutable evidence commit and exact raw links are recorded after the first GitHub source publication in `demo/manifest.json`.

## Required verdict record

### Evaluation #1 — missing audit

| Field | Verified value |
|---|---|
| Proposal | `policyguard-demo-35000` |
| Status | Pending Full Consensus |
| Reason | Must finalize as `Required security audit is missing.` |
| Approval count | 3 |
| Authorization | Blocked |
| Transaction | Pending |

### Evaluation #2 — remediated

| Field | Verified value |
|---|---|
| Previous evaluation | `policyguard-demo-35000:e1` |
| Audit digest | `5bb64218abd8cb5896184328be586722a1d62e46ec363be40c803ba36e528f71` |
| Status | Pending Full Consensus |
| Transaction | Pending |

## Local verification evidence

The repository's clean verification command is:

```bash
npm ci
python3 -m pip install -r requirements-dev.txt
npm run typecheck
npm test
```

The final tested commit and CI run are linked here after GitHub publication.
