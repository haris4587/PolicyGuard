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
| Contract | [`0xd1ff82eeF6F8bcB7FAD0c96b9787A16Edf7ebDa4`](https://explorer-studio.genlayer.com/address/0xd1ff82eeF6F8bcB7FAD0c96b9787A16Edf7ebDa4) |
| Deployment | [`0xc19db98f79d63829701b98168257f48fcf3bb562036891f173f1129861699596`](https://explorer-studio.genlayer.com/tx/0xc19db98f79d63829701b98168257f48fcf3bb562036891f173f1129861699596) |
| Missing-audit evaluation | [`0x860e7fc4b0e38dd4d79825d21979cb3fda70e901a45c645fa000103e83277788`](https://explorer-studio.genlayer.com/tx/0x860e7fc4b0e38dd4d79825d21979cb3fda70e901a45c645fa000103e83277788) · reliable `NON_COMPLIANT` |
| Remediation deadline | [`0xf3d7c3be0a907a73316ca8f75b7ced59e4ad507e53e934e17190beb7a87f6e86`](https://explorer-studio.genlayer.com/tx/0xf3d7c3be0a907a73316ca8f75b7ced59e4ad507e53e934e17190beb7a87f6e86) |
| Authenticated audit | [`0x0a7fb5542c641cf56ebd3ae380344a9dda85bf953692bffc0dc32674882ae21f`](https://explorer-studio.genlayer.com/tx/0x0a7fb5542c641cf56ebd3ae380344a9dda85bf953692bffc0dc32674882ae21f) |
| Corrected evaluation | [`0x3d44dcf550ea491961a270709856ce29c7924640f5ba78a8eb78c3432812e45a`](https://explorer-studio.genlayer.com/tx/0x3d44dcf550ea491961a270709856ce29c7924640f5ba78a8eb78c3432812e45a) · reliable `COMPLIANT` |
| Authorization | [`0x70a77d02cdccde755be04f2dfb166bea4a3c263863badcc17b614e9f6e63fc00`](https://explorer-studio.genlayer.com/tx/0x70a77d02cdccde755be04f2dfb166bea4a3c263863badcc17b614e9f6e63fc00) |
| Execution | [`0x6e9979db81acd8e97d1cb83315879df7a8cf2e10f5885adee40eefdd86c75b8a`](https://explorer-studio.genlayer.com/tx/0x6e9979db81acd8e97d1cb83315879df7a8cf2e10f5885adee40eefdd86c75b8a) |
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

The bootstrap records exact-host source authorities and a closed initial evidence deadline. Read `get_organization`, `get_source_authority`, and `get_proposal` to verify those fields before evaluation.

### 2. Run Full Consensus after the deadline

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
deadline_satisfied: true
citations_valid: true
reliable_adjudication: true
```

Every citation must exactly match a URL in the returned `evidence_digests` with `status = VERIFIED` and `authenticated = true`.

### 3. Open a remediation window

Call `open_remediation_window("policyguard-demo-35000", new_evidence_deadline)` with a Unix timestamp at least 60 seconds and no more than 30 days in the future. Confirm that the proposal returns to `PENDING_EVIDENCE`, `deadline_revision` increments, and the old evaluation remains readable.

### 4. Append remediation before the new deadline

Call `add_evidence`:

| Field | Value |
|---|---|
| `proposal_id` | `policyguard-demo-35000` |
| `evidence_id` | `security-audit-v1` |
| `evidence_type` | `AUDIT` |
| `evidence_url` | commit-pinned `demo/evidence/security-audit.md` raw URL |
| `evidence_sha256` | `5bb64218abd8cb5896184328be586722a1d62e46ec363be40c803ba36e528f71` |

The caller must match the active demo owner source authority for `raw.githubusercontent.com` and `EVIDENCE`; the exact-host check is enforced on-chain.

### 5. Re-evaluate after the new deadline

Call `start_evaluation("policyguard-demo-35000")` again. Confirm evaluation sequence `2`, `previous_evaluation_id = policyguard-demo-35000:e1`, and that evaluation #1 remains readable.

Attempting this call before the new deadline must revert. After the deadline, confirm evaluation sequence `2`, `previous_evaluation_id = policyguard-demo-35000:e1`, `citations_valid = true`, and `reliable_adjudication = true`; evaluation #1 must remain readable.

Only then may `authorize_action` be called. The contract recomputes the complete current binding, including deadline and source-authority state, before recording authorization.

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
