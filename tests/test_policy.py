import pytest

from frappe_guard.policy import (
	CLOSED,
	DEFAULTS,
	ENFORCE,
	MONITOR,
	OFF,
	OPEN,
	Outcome,
	Verdict,
	decide,
	parse_overrides,
	resolve,
)


def test_the_defaults_fail_closed_for_forms_and_open_for_login_reset_and_the_link():
	assert DEFAULTS["contact"].fail == CLOSED
	assert DEFAULTS["sign_up"].fail == CLOSED
	assert all(DEFAULTS[name].fail == OPEN for name in ("login", "reset_password", "send_login_link"))
	assert all(policy.mode == MONITOR for policy in DEFAULTS.values())


def test_an_unknown_action_gets_a_closed_monitor_policy_with_its_own_name():
	policy = resolve("something_else")
	assert (policy.provider_action, policy.mode, policy.fail) == ("something_else", MONITOR, CLOSED)


def test_the_layers_apply_in_order_and_the_site_config_wins():
	policy = resolve(
		"contact",
		default_mode=ENFORCE,
		settings_overrides='{"contact": {"threshold": 0.3, "mode": "off"}}',
		site_overrides={"contact": {"mode": "monitor"}, "*": {"threshold": 0.9}},
	)
	assert policy.mode == MONITOR
	assert (
		policy.threshold == 0.9
	)  # a later source wins, also with its "*" layer, over an earlier source's action layer


def test_the_wildcard_applies_to_every_action_and_the_action_beats_it():
	site = {"*": {"mode": "enforce", "threshold": 0.7}, "login": {"threshold": 0.2}}
	assert resolve("contact", site_overrides=site).threshold == 0.7
	assert resolve("login", site_overrides=site).threshold == 0.2
	assert resolve("login", site_overrides=site).mode == ENFORCE


@pytest.mark.parametrize(
	"layer",
	[
		{"mode": "block"},
		{"threshold": 2},
		{"threshold": -0.1},
		{"threshold": True},
		{"threshold": "0.5"},
		{"fail": "maybe"},
		{"provider_action": ""},
		{"unknown": 1},
		"not a dict",
	],
)
def test_an_invalid_override_is_ignored(layer):
	assert resolve("contact", site_overrides={"contact": layer}) == resolve("contact")


def test_an_invalid_default_mode_is_ignored():
	assert resolve("contact", default_mode="loud").mode == MONITOR


@pytest.mark.parametrize(
	("raw", "expected"),
	[('{"a": 1}', {"a": 1}), ({"a": 1}, {"a": 1}), ("", {}), (None, {}), ("{", {}), ("[1]", {}), (5, {})],
)
def test_parse_overrides(raw, expected):
	assert parse_overrides(raw) == expected


def test_off_never_refuses_and_a_pass_is_allowed_in_every_mode():
	for mode in (OFF, MONITOR, ENFORCE):
		policy = resolve("contact", default_mode=mode)
		assert decide(policy, Verdict(Outcome.PASS, 0.9)).allow
	assert decide(resolve("contact", default_mode=OFF), Verdict(Outcome.LOW_SCORE)).outcome == Outcome.OFF


def test_monitor_lets_a_failed_request_pass_and_says_enforce_would_refuse_it():
	decision = decide(resolve("contact", default_mode=MONITOR), Verdict(Outcome.LOW_SCORE, 0.1))
	assert decision.allow and decision.would_refuse and decision.outcome == Outcome.LOW_SCORE


@pytest.mark.parametrize(
	"outcome",
	[
		Outcome.LOW_SCORE,
		Outcome.MISSING,
		Outcome.HOST_MISMATCH,
		Outcome.ACTION_MISMATCH,
		Outcome.NOT_CONFIGURED,
	],
)
def test_enforce_refuses_every_failure_whatever_the_fail_policy(outcome):
	for action in ("contact", "login"):
		assert not decide(resolve(action, default_mode=ENFORCE), Verdict(outcome)).allow


def test_an_outage_follows_the_fail_policy_in_enforce():
	assert not decide(resolve("contact", default_mode=ENFORCE), Verdict(Outcome.PROVIDER_ERROR)).allow
	opened = decide(resolve("login", default_mode=ENFORCE), Verdict(Outcome.PROVIDER_ERROR))
	assert opened.allow and not opened.would_refuse
