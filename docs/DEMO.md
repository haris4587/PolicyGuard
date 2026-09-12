# PolicyGuard demo runbook

## Story in one sentence

A DAO's written policy blocks a USD 35,000 grant because a required audit is missing. The result becomes reliable only after its recorded evidence deadline, and authorization remains blocked until an authenticated audit is added during a new remediation window and a second post-deadline evaluation becomes compliant.

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
7. Open a recorded remediation window and show the new on-chain deadline revision.
8. Append the audit through its source-authorized wallet before the new deadline.
9. Show that early re-evaluation is rejected; after the deadline, start Full Consensus again.
10. Show both evaluations, exact fetched-page citations, and reliable-adjudication flags in the immutable timeline.
11. Show evaluation #2 as `COMPLIANT`, authorize the action, and show the binding digest.
12. Show the final `EXECUTED` state and immutable execution reference.

## Expected lifecycle evidence

```text
PENDING_EVIDENCE
  → NON_COMPLIANT (evaluation #1; missing audit)
  → PENDING_EVIDENCE (remediation deadline recorded; audit appended; revisions increment)
  → COMPLIANT (evaluation #2; previous evaluation linked)
  → AUTHORIZED (latest binding rechecked)
  → EXECUTED (authorized executor records completion)
```

This exact lifecycle is live on Studionet at contract [`0xd1ff82eeF6F8bcB7FAD0c96b9787A16Edf7ebDa4`](https://explorer-studio.genlayer.com/address/0xd1ff82eeF6F8bcB7FAD0c96b9787A16Edf7ebDa4). The reliable missing-audit evaluation is transaction [`0x860e…7788`](https://explorer-studio.genlayer.com/tx/0x860e7fc4b0e38dd4d79825d21979cb3fda70e901a45c645fa000103e83277788); the post-remediation reliable evaluation is [`0x3d44…e45a`](https://explorer-studio.genlayer.com/tx/0x3d44dcf550ea491961a270709856ce29c7924640f5ba78a8eb78c3432812e45a). Both finalized records report `deadline_satisfied: true`, `citations_valid: true`, and `reliable_adjudication: true`.

## What the demo proves

- The contract stores a human-policy reference and exact bytes commitment.
- Exact-host source authorities bind issuer wallets and scopes before documents enter adjudication.
- Evaluation and authorization enforce the active evidence deadline from contract state.
- Every stored citation is an exact authenticated fetched-page URL.
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
