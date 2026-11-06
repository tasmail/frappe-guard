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


def provider(data=None, error=None, calls=None):
	def post(url, data=None, timeout=None, **kw):
		if calls is not None:
			calls.append((url, dict(data), timeout))
		if isinstance(error, requests.RequestException):
			raise error
		return Reply(REPLY if data is not None and error is None else None, error)

	REPLY = data
	return RecaptchaV3("secret", HOSTS, post=post)


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
		({"success": False}, Outcome.MISSING),
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
