# Testing guide

## One-command verification

```bash
npm ci
python3 -m pip install -r requirements-dev.txt
npm run typecheck
npm test
```

## What runs

| Layer | Command | Coverage |
|---|---|---|
| Contract syntax | `python3 -m py_compile contracts/policy_guard.py` | valid Python source |
| Deterministic lifecycle model | `pytest -q tests/test_policyguard.py` | policy gates, exact-host/issuer/scope authorities, deadline closure, citation membership, fresh workflow, duplicates, stale authorization, fallback, history |
| Contract controls | `node scripts/verify-contract.mjs` | required lifecycle methods and GenLayer primitives |
| Evidence integrity | `node scripts/verify-evidence.mjs` | manifest matches exact SHA-256 bytes |
| Type safety | `npm run typecheck` | React/TypeScript client |
| Static analysis | `npm run lint` | application and repository source |
| Production build | `npm run build` | Cloudflare Worker-compatible output |
| Production rendering | `node --test tests/*.test.mjs` | metadata, product copy, wallet/GenLayer methods, network config |

## Required scenario matrix

| Scenario | Expected result | Automated |
|---|---|---|
| USD 35,000 + 3 approvals + missing audit | `NON_COMPLIANT` / exact missing-audit reason | yes |
| Same grant after valid audit | `COMPLIANT` | yes; plus live consensus after deployment |
| USD 15,000 below threshold | applicable baseline requirements only | yes |
| Fewer than 3 approvals | `NON_COMPLIANT` | yes |
| Duplicate reviewer | revert/reject | yes |
| Policy or proposal digest mismatch | `NEEDS_REVIEW` | yes |
| Invalid/unsupported evidence URL | reject | yes, parameterized |
| Exact allowed host vs crafted suffix/userinfo/port | only exact canonical host accepted | yes |
| Public claimant evidence without issuer authority | reject | yes |
| Citation absent from fetched pages | `NEEDS_REVIEW`, unreliable | yes |
| Evaluation before evidence deadline | reject | yes |
| Authorization without post-deadline reliable verdict | reject | yes |
| Malformed consensus output | `NEEDS_REVIEW` | yes |
| Stale verdict authorization | reject | yes |
| Re-evaluation history | original result preserved | yes |
| Unauthorized authorization/execution | reject | yes |
| Fresh organization → source authorities → policy → proposal/deadline → roster → post-deadline evaluation → recorded remediation window → post-deadline re-evaluation → authorization → execution | `EXECUTED`, with both evaluations retained | yes |

## Studionet verification

Automated tests intentionally do not claim to reproduce a live validator committee. Final deployment evidence must additionally record:

1. A finalized deployment transaction.
2. A finalized `bootstrap_demo` transaction.
3. A Normal / Full Consensus `start_evaluation` transaction for the missing-audit case.
4. The stored evaluation read from `get_latest_evaluation`.
5. If completed, the audit remediation and second Full Consensus evaluation.
6. Finalized reads showing exact source-authority records, the evidence deadline, fetched-page citations, and `reliable_adjudication = true`.

For every write, check both consensus status (`FINALIZED`) and execution result (`SUCCESS` / finished with return). A finalized transaction with an execution error is not a successful test.

## Evidence regeneration

```bash
npm run evidence:hash
```

If any demo document changes, update `demo/HASHES.sha256` and `demo/manifest.json`, create a new Git commit, and use the new full commit SHA in later evidence URLs. Never edit a document while continuing to cite an old digest.
