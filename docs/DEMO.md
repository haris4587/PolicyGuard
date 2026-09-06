# PolicyGuard demo runbook

## Story in one sentence

A DAO's written policy blocks a USD 35,000 grant because a required audit is missing, then permits authorization only after the audit is appended and a new consensus evaluation becomes compliant.

## Public walkthrough

1. Open the PolicyGuard website and show **Studionet · 61999**.
2. Connect MetaMask and show the connected account.
3. Open the commit-pinned policy, proposal, and three-reviewer approval bundle.
4. Load proposal `policyguard-demo-35000`.
5. Show evaluation #1:
   - `NON_COMPLIANT`
   - `Required security audit is missing.`
   - approval count `3`
   - no authorization record
6. Open the published audit and show its SHA-256 digest.
7. Append the audit evidence through the wallet-signed action.
8. Start Full Consensus again.
9. Show both evaluations in the immutable timeline.
10. If #2 is `COMPLIANT`, authorize the action and show the binding digest.

## Expected lifecycle evidence

```text
PENDING_EVIDENCE
  → NON_COMPLIANT (evaluation #1; missing audit)
  → PENDING_EVIDENCE (audit appended; input revision increments)
  → COMPLIANT (evaluation #2; previous evaluation linked)
  → AUTHORIZED (latest binding rechecked)
```

## What the demo proves

- The contract stores a human-policy reference and exact bytes commitment.
- Reviewer identities cannot be duplicated.
- Validator consensus interprets documents, while deterministic controls fail closed for explicit missing inputs.
- Remediation does not overwrite the negative verdict.
- A prior compliant verdict cannot survive changed policy, proposal, evidence, approval, or revision state.
- The frontend uses real reads and wallet-signed writes and does not present static output as live state.

## Screenshots to capture

1. Website header with MetaMask account and Studionet badge.
2. Missing-audit evaluation card with exact reason.
3. Transaction lifecycle or explorer view showing the Full Consensus hash.
4. Re-evaluation timeline with #1 and #2 visible together.
5. Authorization lock or authorized state after the compliant result.
6. GitHub repository root showing contract, frontend, tests, demo, and documentation.
7. Contract source open in GenLayer Studio.
8. Studio transaction details showing `FINALIZED` and successful execution.
