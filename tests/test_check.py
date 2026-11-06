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
	assert "Try again later" in check.message(Outcome.PROVIDER_ERROR)
	assert "Reload the page" in check.message(Outcome.LOW_SCORE)
	assert check.message(Outcome.PASS) == check.message(Outcome.MISSING)
