package ruleforce.transfers

import rego.v1

# Starter policy from the RuleForce spec (Nov 15, 2026).
# Queried by ODC at POST /v1/data/ruleforce/transfers/decision?provenance=true
# Every fact in `input` is built server-side by InitiateTransfer / ApproveTransfer;
# nothing here is taken from the agent's arguments.

default decision := {"result": "deny", "reasons": ["no_rule_matched"]}

# Deviation from the spec's starter policy: without this guard, missing facts make
# every comparison undefined, deny_reasons stays empty and the decision is "allow"
# (fail-open). A missing or malformed fact must deny.
deny_reasons contains "incomplete_input" if not complete_input

deny_reasons contains "invalid_amount" if input.amount <= 0

complete_input if {
	is_string(input.requester.id)
	is_array(input.requester.roles)
	is_string(input.from_account.status)
	is_number(input.from_account.balance)
	is_number(input.from_account.daily_limit)
	is_string(input.to_account.status)
	is_number(input.amount)
	is_number(input.today_total)
}

# Only treasury users may initiate transfers. Roles are looked up by ODC from the
# signed-in user, never taken from the agent, so "I'm the CFO" cannot satisfy this.
# Written as a named rule + `not`, not `not "TreasuryUser" in input.requester.roles`:
# the inline form does not fire when `roles` is missing, which allowed the transfer.
requester_is_treasury_user if "TreasuryUser" in input.requester.roles

deny_reasons contains "requester_not_authorized" if not requester_is_treasury_user

deny_reasons contains "account_not_active" if input.from_account.status != "Active"

deny_reasons contains "account_not_active" if input.to_account.status != "Active"

deny_reasons contains "insufficient_funds" if input.amount > input.from_account.balance

deny_reasons contains "daily_limit_exceeded" if {
	input.amount + input.today_total > input.from_account.daily_limit
}

deny_reasons contains "self_approval" if {
	input.approval.approver_id == input.requester.id
}

needs_approval if input.amount > 10000

approved if {
	input.approval.decision == "approved"
	"TreasuryApprover" in input.approval.approver_roles
}

decision := {"result": "deny", "reasons": deny_reasons} if count(deny_reasons) > 0

decision := {"result": "require_approval", "reasons": ["amount_over_10000"]} if {
	count(deny_reasons) == 0
	needs_approval
	not approved
}

decision := {"result": "allow", "reasons": []} if {
	count(deny_reasons) == 0
	not needs_approval
}

decision := {"result": "allow", "reasons": ["approved"]} if {
	count(deny_reasons) == 0
	needs_approval
	approved
}
