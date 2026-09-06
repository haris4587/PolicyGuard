# Reviewer Approval Bundle — Sentinel Grant

Proposal: `policyguard-demo-35000`  
Decision: Approve subject to PolicyGuard's independent policy-compliance evaluation.

| Reviewer | Registered wallet | Decision | Reference |
|---|---|---|---|
| Reviewer Alpha | `0x1111111111111111111111111111111111111111` | APPROVE | `PG-APPROVAL-001` |
| Reviewer Beta | `0x2222222222222222222222222222222222222222` | APPROVE | `PG-APPROVAL-002` |
| Reviewer Gamma | `0x3333333333333333333333333333333333333333` | APPROVE | `PG-APPROVAL-003` |

The demo bootstrap stores these three distinct identities as clearly labeled `DEMO_ATTESTED` approvals bound to this document's SHA-256 digest. Normal production approvals use `approve_proposal`, where each registered reviewer must sign their own GenLayer transaction and duplicate approvals are rejected by wallet address.
