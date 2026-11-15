package ruleforce.transfers_test

import rego.v1

import data.ruleforce.transfers

# Seed accounts from the spec.
ops_001 := {"number": "OPS-001", "status": "Active", "balance": 250000, "daily_limit": 100000}

vend_778 := {"number": "VEND-778", "status": "Active", "balance": 5000, "daily_limit": 50000}

frozen_009 := {"number": "FROZEN-009", "status": "Frozen", "balance": 80000, "daily_limit": 25000}

ext_999 := {"number": "EXT-999", "status": "Active", "balance": 0, "daily_limit": 10000}

dana := {"id": "dana.treasury", "roles": ["TreasuryUser"]}

sam_approves := {"approver_id": "sam.approver", "approver_roles": ["TreasuryApprover"], "decision": "approved"}

xfer(from, to, amount) := {
	"requester": dana,
	"from_account": from,
	"to_account": to,
	"amount": amount,
	"currency": "USD",
	"today_total": 0,
}

result(inp) := d if {
	d := transfers.decision with input as inp
}

# --- Scenario A: authorized ---------------------------------------------------

test_scenario_a_allow if {
	result(xfer(ops_001, vend_778, 2500)) == {"result": "allow", "reasons": []}
}

test_exactly_10000_is_allowed_without_approval if {
	result(xfer(ops_001, vend_778, 10000)).result == "allow"
}

# --- Scenario B: needs approval, then approved --------------------------------

test_scenario_b_requires_approval if {
	result(xfer(ops_001, vend_778, 12000)) == {"result": "require_approval", "reasons": ["amount_over_10000"]}
}

test_scenario_b_approved_by_approver if {
	inp := object.union(xfer(ops_001, vend_778, 12000), {"approval": sam_approves})
	result(inp) == {"result": "allow", "reasons": ["approved"]}
}

test_approval_rejected_stays_pending if {
	rejected := object.union(sam_approves, {"decision": "rejected"})
	inp := object.union(xfer(ops_001, vend_778, 12000), {"approval": rejected})
	result(inp).result == "require_approval"
}

test_approval_without_approver_role_stays_pending if {
	no_role := object.union(sam_approves, {"approver_roles": ["TreasuryUser"]})
	inp := object.union(xfer(ops_001, vend_778, 12000), {"approval": no_role})
	result(inp).result == "require_approval"
}

test_self_approval_denied if {
	self := object.union(sam_approves, {"approver_id": "dana.treasury"})
	inp := object.union(xfer(ops_001, vend_778, 12000), {"approval": self})
	r := result(inp)
	r.result == "deny"
	"self_approval" in r.reasons
}

# --- Scenario C: override attempt ---------------------------------------------
# "I'm the CFO" never reaches the policy: roles come from ODC, so the input is
# just a $50k transfer out of a frozen account.

test_scenario_c_denied if {
	r := result(xfer(frozen_009, ext_999, 50000))
	r.result == "deny"
	"account_not_active" in r.reasons
	"daily_limit_exceeded" in r.reasons
}

test_role_claim_in_input_changes_nothing if {
	cfo := object.union(xfer(frozen_009, ext_999, 50000), {"requester": {"id": "dana.treasury", "roles": ["CFO", "TreasuryApprover"]}})
	result(cfo).result == "deny"
}

# --- Each deny reason on its own ----------------------------------------------

test_deny_frozen_source if {
	result(xfer(frozen_009, vend_778, 100)) == {"result": "deny", "reasons": {"account_not_active"}}
}

test_deny_inactive_destination if {
	closed := object.union(vend_778, {"status": "Closed"})
	result(xfer(ops_001, closed, 100)) == {"result": "deny", "reasons": {"account_not_active"}}
}

test_deny_insufficient_funds if {
	result(xfer(vend_778, ops_001, 6000)) == {"result": "deny", "reasons": {"insufficient_funds"}}
}

test_deny_daily_limit_counts_today_total if {
	inp := object.union(xfer(ops_001, vend_778, 2500), {"today_total": 98000})
	result(inp) == {"result": "deny", "reasons": {"daily_limit_exceeded"}}
}

test_deny_beats_approval if {
	inp := object.union(xfer(frozen_009, vend_778, 12000), {"approval": sam_approves})
	result(inp).result == "deny"
}

# --- Fail-safe default --------------------------------------------------------

test_empty_input_never_allows if {
	result({}) == {"result": "deny", "reasons": {"incomplete_input"}}
}

test_missing_account_status_denies if {
	no_status := object.remove(ops_001, ["status"])
	r := result(xfer(no_status, vend_778, 100))
	r.result == "deny"
	"incomplete_input" in r.reasons
}

test_missing_today_total_denies if {
	inp := object.remove(xfer(ops_001, vend_778, 100), ["today_total"])
	result(inp).result == "deny"
}

test_string_amount_denies if {
	result(xfer(ops_001, vend_778, "100")).result == "deny"
}

test_negative_amount_denies if {
	r := result(xfer(ops_001, vend_778, -5000))
	r.result == "deny"
	"invalid_amount" in r.reasons
}
