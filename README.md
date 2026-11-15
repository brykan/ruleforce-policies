# ruleforce-policies

Rego policies for the RuleForce proof of concept: an AI agent's money-moving action
calls OPA before it does anything, so business rules are enforced by the system,
not the prompt.

| Path | Package | Queried at |
| --- | --- | --- |
| `policies/ruleforce/transfers/` | `ruleforce.transfers` | `POST /v1/data/ruleforce/transfers/decision?provenance=true` |

On merge to `main`, [the workflow](.github/workflows/bundle.yml) runs `opa test`,
builds a bundle with the commit SHA as its revision, and publishes it to the
`policy-bundle` release. OPA polls it every 20–30 s. Every decision ODC records
carries that revision, which ties it back to a commit here.

**Rolling back** is a `git revert` on `main`.

```bash
opa test policies -v
```

The policies here are demo rules for a sample treasury, not real controls.
