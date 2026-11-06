import pytest

from frappe_guard import check
from frappe_guard.policy import Outcome
from frappe_guard.providers.stub import StubProvider


@pytest.fixture
def configured(frappe_stub):
	frappe_stub.conf.update(guard_recaptcha_secret="s", guard_hosts=["www.example.com"], guard_mode="enforce")
	return frappe_stub


def test_off_checks_nothing(frappe_stub):
	frappe_stub.conf["guard_mode"] = "off"
	provider = StubProvider(Outcome.LOW_SCORE)
	decision = check.evaluate("contact", "tok", provider)
	assert decision.allow and decision.outcome == Outcome.OFF and not provider.calls


def test_a_good_token_passes_with_the_threshold_and_the_action_of_the_policy(configured):
	provider = StubProvider(Outcome.PASS, 0.8)
	configured.conf["guard_actions"] = {"contact": {"threshold": 0.7, "provider_action": "contact_form"}}
	assert check.evaluate("contact", "tok", provider).allow
	assert provider.calls == [("tok", "contact_form", 0.7)]
	assert configured.log.lines == []  # a pass is not logged


def test_a_missing_token_is_refused_in_enforce_and_logged_without_the_token(configured):
	decision = check.evaluate("contact", None, StubProvider())
	assert not decision.allow and decision.outcome == Outcome.MISSING
	assert configured.log.lines == ["action=contact outcome=missing mode=enforce allow=False score=None"]


def test_monitor_lets_the_request_pass_but_logs_it(configured):
	configured.conf["guard_mode"] = "monitor"
	decision = check.evaluate("contact", "tok", StubProvider(Outcome.LOW_SCORE, 0.1))
	assert decision.allow and decision.would_refuse
	assert "outcome=low_score" in configured.log.lines[0] and "tok" not in configured.log.lines[0]


def test_a_site_without_a_secret_or_hosts_is_refused_but_a_dev_or_test_run_passes(frappe_stub):
	frappe_stub.conf["guard_mode"] = "enforce"
	assert not check.evaluate("contact", "tok").allow
	frappe_stub.conf.update(
		guard_recaptcha_secret="s"
	)  # a secret without a host list is still not configured
	assert check.evaluate("contact", "tok").outcome == Outcome.NOT_CONFIGURED
	frappe_stub.flags.in_test = True
	assert check.evaluate("contact", "tok").allow
	frappe_stub.flags.in_test = False
	frappe_stub.conf["developer_mode"] = 1
	assert check.evaluate("contact", "tok").allow


def test_the_real_provider_is_used_when_none_is_given(configured, monkeypatch):
	seen = []

	class Real:
		def __init__(self, secret, hosts):
			seen.append((secret, hosts))

		def verify(self, token, action, threshold):
			return StubProvider().verify(token, action, threshold)

	monkeypatch.setattr(check, "RecaptchaV3", Real)
	assert check.evaluate("sign_up", "tok").allow
	assert seen == [("s", ["www.example.com"])]


def test_the_messages_ask_for_a_retry_and_say_nothing_about_the_score():
	assert "not configured" in check.message(Outcome.NOT_CONFIGURED)
	assert "Try again later" in check.message(Outcome.PROVIDER_ERROR)
	assert "Reload the page" in check.message(Outcome.LOW_SCORE)
	assert check.message(Outcome.PASS) == check.message(Outcome.MISSING)


def test_monitor_passes_a_site_that_is_not_configured_and_enforce_refuses_it_even_for_an_open_action(
	frappe_stub,
):
	frappe_stub.conf["guard_mode"] = "monitor"
	decision = check.evaluate("login", "tok")
	assert decision.allow and decision.would_refuse and decision.outcome == Outcome.NOT_CONFIGURED
	frappe_stub.conf["guard_mode"] = "enforce"
	assert not check.evaluate("login", "tok").allow


@pytest.mark.parametrize("token", [["a"], {"a": 1}, 5, "", "x" * 4097])
def test_a_token_that_is_not_a_sane_string_never_reaches_the_provider(configured, token):
	provider = StubProvider()
	decision = check.evaluate("contact", token, provider)
	assert decision.outcome == Outcome.MISSING and not decision.allow and not provider.calls


def test_a_token_of_the_largest_size_goes_to_the_provider(configured):
	provider = StubProvider()
	assert check.evaluate("contact", "x" * 4096, provider).allow and len(provider.calls) == 1


def test_monitor_login_with_an_outage_passes_and_is_not_marked_for_refusal(configured):
	configured.conf["guard_mode"] = "monitor"
	decision = check.evaluate("login", "tok", StubProvider(Outcome.PROVIDER_ERROR))
	assert decision.allow and not decision.would_refuse


class Broken:
	def verify(self, token, action, threshold):
		raise RuntimeError("secret-token-value")


def test_an_unexpected_error_is_an_outage_decided_by_the_fail_policy_and_leaks_nothing(configured):
	assert not check.evaluate("contact", "tok-123", Broken()).allow  # a form fails closed
	assert check.evaluate("login", "tok-123", Broken()).allow  # login fails open (under the rate limiter)
	assert check.evaluate("whatever", "tok-123", Broken()).outcome == Outcome.PROVIDER_ERROR
	assert not any("tok-123" in line or "secret-token-value" in line for line in configured.log.lines)
	assert any("failed unexpectedly" in line for line in configured.log.lines)


def test_a_broken_database_read_does_not_crash_the_check(configured):
	def boom(doctype, field):
		raise RuntimeError("DocType not found")

	configured.db.get_single_value = boom
	assert check.evaluate("contact", "tok", StubProvider()).allow


def test_when_the_configuration_itself_fails_the_check_is_enforced_with_the_code_defaults(
	frappe_stub, monkeypatch
):
	def boom(action):
		raise RuntimeError("config")

	monkeypatch.setattr(check.config, "policy_for", boom)
	assert not check.evaluate("contact", "tok", StubProvider()).allow  # a form fails closed
	assert check.evaluate("login", "tok", StubProvider()).allow  # login fails open
	assert check.evaluate("unknown_action", "tok", StubProvider()).outcome == Outcome.PROVIDER_ERROR
