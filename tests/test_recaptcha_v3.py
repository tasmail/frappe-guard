import pytest
import requests

from frappe_guard.policy import Outcome
from frappe_guard.providers.recaptcha_v3 import RecaptchaV3

HOSTS = ["www.example.com", " Staging.Example.com "]


class Reply:
	def __init__(self, data=None, error=None):
		self.data, self.error = data, error

	def json(self):
		if self.error:
			raise self.error
		return self.data


def provider(reply=None, error=None, calls=None, hosts=HOSTS):
	def post(url, data=None, timeout=None, **kw):
		if calls is not None:
			calls.append((url, dict(data), timeout))
		if isinstance(error, requests.RequestException):
			raise error
		return Reply(reply, error)

	return RecaptchaV3("secret", hosts, post=post)


GOOD = {"success": True, "action": "contact", "score": 0.9, "hostname": "www.example.com"}


def test_a_good_token_passes_and_no_remoteip_is_sent():
	calls = []
	verdict = provider(GOOD, calls=calls).verify("tok", "contact", 0.5)
	assert (verdict.outcome, verdict.score) == (Outcome.PASS, 0.9)
	assert calls[0][1] == {"secret": "secret", "response": "tok"}
	assert "remoteip" not in calls[0][1]


def test_the_host_list_is_normalised_and_compared_case_insensitively():
	reply = dict(GOOD, hostname="STAGING.example.com")
	assert provider(reply).verify("t", "contact", 0.5).outcome == Outcome.PASS


@pytest.mark.parametrize(
	("change", "outcome"),
	[
		({"success": False}, Outcome.INVALID_TOKEN),
		({"action": "other"}, Outcome.ACTION_MISMATCH),
		({"hostname": "evil.example"}, Outcome.HOST_MISMATCH),
		({"hostname": None}, Outcome.HOST_MISMATCH),
		({"score": 0.1}, Outcome.LOW_SCORE),
		({"score": 0}, Outcome.LOW_SCORE),
	],
)
def test_a_failed_token_gets_its_outcome(change, outcome):
	assert provider(dict(GOOD, **change)).verify("t", "contact", 0.5).outcome == outcome


def test_a_zero_score_is_honoured_even_when_the_threshold_is_zero():
	assert provider(dict(GOOD, score=0)).verify("t", "contact", 0).outcome == Outcome.PASS


def test_a_missing_or_odd_score_counts_as_zero():
	for score in (None, "0.9", True):
		reply = dict(GOOD, score=score)
		assert provider(reply).verify("t", "contact", 0.5).outcome == Outcome.LOW_SCORE


def test_an_unreachable_provider_or_an_unreadable_reply_is_a_provider_error():
	assert (
		provider(error=requests.ConnectionError()).verify("t", "contact", 0.5).outcome
		== Outcome.PROVIDER_ERROR
	)
	assert provider(error=ValueError()).verify("t", "contact", 0.5).outcome == Outcome.PROVIDER_ERROR
	assert provider(["not", "a", "dict"]).verify("t", "contact", 0.5).outcome == Outcome.PROVIDER_ERROR


def test_a_truthy_success_that_is_not_true_is_not_a_pass():
	assert provider(dict(GOOD, success="yes")).verify("t", "contact", 0.5).outcome == Outcome.INVALID_TOKEN


@pytest.mark.parametrize("code", ["invalid-input-secret", "missing-input-secret"])
def test_a_wrong_secret_is_a_fault_of_the_configuration_not_of_the_token(code):
	reply = {"success": False, "error-codes": [code]}
	assert provider(reply).verify("t", "contact", 0.5).outcome == Outcome.NOT_CONFIGURED


@pytest.mark.parametrize("codes", [["timeout-or-duplicate"], "invalid-input-secret", None, [1, {}]])
def test_other_error_codes_are_a_token_failure(codes):
	reply = {"success": False, "error-codes": codes}
	assert provider(reply).verify("t", "contact", 0.5).outcome == Outcome.INVALID_TOKEN


def test_the_trailing_dot_of_a_host_is_ignored_and_a_port_is_not_a_host():
	assert (
		provider(dict(GOOD, hostname="www.example.com.")).verify("t", "contact", 0.5).outcome == Outcome.PASS
	)
	assert (
		provider(dict(GOOD, hostname="www.example.com:443")).verify("t", "contact", 0.5).outcome
		== Outcome.HOST_MISMATCH
	)


@pytest.mark.parametrize("hostname", [["www.example.com"], 5, {"a": 1}])
def test_a_hostname_that_is_not_a_string_is_a_mismatch_not_a_crash(hostname):
	assert (
		provider(dict(GOOD, hostname=hostname)).verify("t", "contact", 0.5).outcome == Outcome.HOST_MISMATCH
	)


def test_the_host_list_ignores_items_that_are_not_strings_and_an_empty_list_passes_nothing():
	assert (
		provider(GOOD, hosts=[5, None, "www.example.com"]).verify("t", "contact", 0.5).outcome == Outcome.PASS
	)
	assert provider(GOOD, hosts=[]).verify("t", "contact", 0.5).outcome == Outcome.HOST_MISMATCH
