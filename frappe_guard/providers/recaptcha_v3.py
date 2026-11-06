"""Google reCAPTCHA v3: the verification of a token (the stricter checks of `fossdoc_shop/captcha.py`)."""

import requests

from frappe_guard.policy import Outcome, Verdict

VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
TIMEOUT = 5


# A wrong or revoked secret is a fault of the configuration, not of the token.
SECRET_ERRORS = {"invalid-input-secret", "missing-input-secret"}


def _host(name) -> str:
	return name.strip().lower().rstrip(".") if isinstance(name, str) else ""


class RecaptchaV3:
	def __init__(self, secret: str, hosts, post=requests.post, timeout: float = TIMEOUT):
		self.secret = secret
		self.hosts = {_host(host) for host in hosts if isinstance(host, str) and _host(host)}
		self.post = post
		self.timeout = timeout

	def verify(self, token: str, expected_action: str, threshold: float) -> Verdict:
		"""`success`, the action the token was made for, the score (0 is honoured) and the host of the reply."""
		try:
			# no `remoteip`: behind the proxy it is the proxy
			reply = self.post(
				VERIFY_URL, data={"secret": self.secret, "response": token}, timeout=self.timeout
			).json()
		except (requests.RequestException, ValueError):
			return Verdict(Outcome.PROVIDER_ERROR)
		if not isinstance(reply, dict):
			return Verdict(Outcome.PROVIDER_ERROR)
		score = reply.get("score")
		score = score if isinstance(score, (int, float)) and not isinstance(score, bool) else 0
		if reply.get("success") is not True:
			codes = reply.get("error-codes")
			if isinstance(codes, list) and SECRET_ERRORS & set(map(str, codes)):
				return Verdict(Outcome.NOT_CONFIGURED)
			return Verdict(Outcome.INVALID_TOKEN, score)  # invalid, expired or already used token
		if reply.get("action") != expected_action:
			return Verdict(Outcome.ACTION_MISMATCH, score)
		if _host(reply.get("hostname")) not in self.hosts:
			return Verdict(Outcome.HOST_MISMATCH, score)
		if score < threshold:
			return Verdict(Outcome.LOW_SCORE, score)
		return Verdict(Outcome.PASS, score)
