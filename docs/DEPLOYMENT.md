# Deployment and verification

PolicyGuard targets **stable GenLayer Studionet**, not the release-candidate Studio-dev environment.

| Setting | Value |
|---|---|
| Studio | `https://studio.genlayer.com` |
| RPC | `https://studio.genlayer.com/api` |
| Chain ID | `61999` (`0xf22f`) |
| Explorer | `https://explorer-studio.genlayer.com` |
| SDK | `genlayer-js@1.1.8` |
| Contract | `contracts/policy_guard.py` |

## Verified live deployment

| Item | Value |
|---|---|
| Contract | [`0xdD7D1EaC2A2F09602734BC7D6Bb1897ED4487964`](https://explorer-studio.genlayer.com/address/0xdD7D1EaC2A2F09602734BC7D6Bb1897ED4487964) |
| Deployment | [`0x0bb9dbcd8741512b277c1b83f87eaf9fda07ead0c9231802884dd7480d40b6e3`](https://explorer-studio.genlayer.com/tx/0x0bb9dbcd8741512b277c1b83f87eaf9fda07ead0c9231802884dd7480d40b6e3) |
| Missing-audit evaluation | [`0xbf95352e985cb1a454baaf44c52e260aefecbffc3fc1ca0186496cddd4e439d2`](https://explorer-studio.genlayer.com/tx/0xbf95352e985cb1a454baaf44c52e260aefecbffc3fc1ca0186496cddd4e439d2) · `NON_COMPLIANT` |
| Corrected evaluation | [`0xeb42736834489e3402f50ae945e0e6ca1a6972c892e0544d9080082b49f8b778`](https://explorer-studio.genlayer.com/tx/0xeb42736834489e3402f50ae945e0e6ca1a6972c892e0544d9080082b49f8b778) · `COMPLIANT` |
| Final state | `EXECUTED` |

## Pre-deployment checks

```bash
npm ci
python3 -m pip install -r requirements-dev.txt
npm run typecheck
npm test
```

Verify that `demo/manifest.json` contains a full, immutable evidence Git commit before deploying. All URLs used by `bootstrap_demo` are constructed from that commit rather than `main`.

## Studio deployment

1. Open stable GenLayer Studio.
2. Connect MetaMask on chain `61999`.
3. Keep **Simulation Mode off**.
4. Select **Normal / Full Consensus**.
5. Load the complete contents of `contracts/policy_guard.py`.
6. Deploy `PolicyGuard`. Its constructor takes no arguments.
7. Wait for `FINALIZED`, confirm the execution result succeeded, and record both the contract address and deployment transaction hash.

Do not record an address from a reverted or erroring deployment. A transaction can be finalized while its contract execution failed.

## Primary live run

The exact commit and file hashes come from `demo/manifest.json`.

### 1. Bootstrap the missing-audit case

Call `bootstrap_demo`:

| Field | Value |
|---|---|
| `evidence_commit` | full 40-character value from `demo/manifest.json` |
| `policy_sha256` | `62957ed2e2de08939500b3b5a19f2d95102ce458d6a4bd10535a90b9fa38190c` |
| `proposal_sha256` | `7bd84b46f443e2317bff343d544843309a88d5818f8ffe83979ed438f2c0b5bc` |
| `approvals_sha256` | `22d8480e63c683e358a7e2add341206fd487f2592b337b76654ce2a697e2276f` |

Transaction value: `0`. Wait for successful finalization.

### 2. Run Full Consensus

Call `start_evaluation`:

| Field | Value |
|---|---|
| `proposal_id` | `policyguard-demo-35000` |

Transaction value: `0`. Simulation remains off; Normal / Full Consensus remains selected.

Required stored result:

```text
status: NON_COMPLIANT
reason: Required security audit is missing.
approval_count: 3
```

### 3. Append remediation

Call `add_evidence`:

| Field | Value |
|---|---|
| `proposal_id` | `policyguard-demo-35000` |
| `evidence_id` | `security-audit-v1` |
| `evidence_type` | `AUDIT` |
| `evidence_url` | commit-pinned `demo/evidence/security-audit.md` raw URL |
| `evidence_sha256` | `5bb64218abd8cb5896184328be586722a1d62e46ec363be40c803ba36e528f71` |

### 4. Re-evaluate

Call `start_evaluation("policyguard-demo-35000")` again. Confirm evaluation sequence `2`, `previous_evaluation_id = policyguard-demo-35000:e1`, and that evaluation #1 remains readable.

If the second result is `COMPLIANT`, `authorize_action` may be called. The contract recomputes the complete current binding before recording authorization.

## Update deployment evidence

Only after verification, update:

- `config/deployment.json`
- `EVIDENCE.md`
- `docs/SUBMISSION.md`
- README deployment table

Record full hashes, not screenshots alone. Re-run the entire test/build suite after configuration changes and redeploy the website from the exact tested source commit.

## Frontend behavior

- Reads use finalized state.
- Every live write requires the connected MetaMask provider.
- Wrong-network handling requests chain `61999` and can add the stable network if missing.
- The site does not generate a private key.
- The transaction rail separates wallet request, submission, acceptance, and finalization.
- A transaction ID is retained after submission; timeouts must not trigger blind duplicate writes.
