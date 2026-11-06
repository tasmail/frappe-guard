"""Google reCAPTCHA v3: the verification of a token (the stricter checks of `fossdoc_shop/captcha.py`)."""

import requests

from frappe_guard.policy import Outcome, Verdict

VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
TIMEOUT = 5


class RecaptchaV3:
	def __init__(self, secret: str, hosts, post=requests.post, timeout: float = TIMEOUT):
		self.secret = secret
		self.hosts = {host.strip().lower() for host in hosts if host and host.strip()}
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
		if not reply.get("success"):
			return Verdict(Outcome.MISSING, score)  # invalid, expired or already used token
		if reply.get("action") != expected_action:
			return Verdict(Outcome.ACTION_MISMATCH, score)
		if (reply.get("hostname") or "").lower() not in self.hosts:
			return Verdict(Outcome.HOST_MISMATCH, score)
		if score < threshold:
			return Verdict(Outcome.LOW_SCORE, score)
		return Verdict(Outcome.PASS, score)
