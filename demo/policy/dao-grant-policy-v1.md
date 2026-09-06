# PolicyGuard Demo DAO — Treasury Grant Policy v1

Policy ID: `grant-policy`  
Effective version: `1`  
Governing organization: `policyguard-dao`

## Rule

Grants above USD 20,000 require all of the following before treasury execution:

1. Approval from at least three distinct registered reviewers.
2. A published security audit covering the work, scope, or system being funded.
3. A proposal that identifies the recipient, amount, purpose, milestones, and requested treasury action.

The security audit must be reachable through a public document link and must describe its scope, findings, and publication status. A plan to publish an audit later does not satisfy this rule.

Grants of USD 20,000 or less do not require the three-reviewer threshold or a security audit under this policy, but they must still be consistent with the proposal's stated purpose and must not contain unresolved contradictions.

If required evidence is missing, changed after commitment, unreachable, contradictory, or ambiguous, the action must not be authorized. The appropriate outcome is `NON_COMPLIANT` for a clear unmet rule and `NEEDS_REVIEW` when the available material cannot support a safe determination.

## Execution safeguard

Only the latest finalized `COMPLIANT` evaluation may authorize execution. It must remain bound to this exact policy version and digest, the proposal digest, the complete evidence digest set, and the complete approval set. Any input change requires a new evaluation.
