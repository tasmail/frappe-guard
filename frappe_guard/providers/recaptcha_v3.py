"""Google reCAPTCHA v3: the verification of a token (the stricter checks of `fossdoc_shop/captcha.py`)."""

import math
import threading
import time

import requests

from frappe_guard.policy import Outcome, Verdict

VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
# The call blocks a worker of the site: connect and read each have a short limit (the worst case is their sum, about 4 s).
TIMEOUT = (1.5, 2.5)
MAX_IN_FLIGHT = (
	20  # calls to the provider at the same time in one process; more are not made (`provider_error`)
)
BREAKER_FAILURES = 5  # consecutive failures of the provider that open the breaker
BREAKER_PAUSE = 15  # seconds the provider is not called after that: the fail policy answers at once
SESSION = requests.Session()  # keep-alive: a new TCP and TLS connection per check costs 100 to 300 ms


# A wrong or revoked secret is a fault of the configuration, not of the token.
SECRET_ERRORS = {"invalid-input-secret", "missing-input-secret"}


class Breaker:
	"""Stops calling a provider that keeps failing (the browser script does the same): the workers are not held by it."""

	def __init__(self, failures: int = BREAKER_FAILURES, pause: float = BREAKER_PAUSE, clock=time.monotonic):
		self.failures, self.pause, self.clock = failures, pause, clock
		self.count, self.open_until = 0, 0.0

	def allows(self) -> bool:
		return self.clock() >= self.open_until

	def failed(self) -> None:
		self.count += 1
		if self.count >= self.failures:
			self.open_until, self.count = self.clock() + self.pause, 0

	def succeeded(self) -> None:
		self.count = 0


BREAKER = Breaker()
IN_FLIGHT = threading.BoundedSemaphore(MAX_IN_FLIGHT)


def _host(name) -> str:
	return name.strip().lower().rstrip(".") if isinstance(name, str) else ""


class RecaptchaV3:
	def __init__(self, secret: str, hosts, post=None, timeout=TIMEOUT):
		self.secret = secret
		self.hosts = {_host(host) for host in hosts if isinstance(host, str) and _host(host)}
		self.post = post or SESSION.post
		self.timeout = timeout

	def verify(self, token: str, expected_action: str, threshold: float) -> Verdict:
		"""`success`, the action the token was made for, the score (0 is honoured) and the host of the reply."""
		if not BREAKER.allows() or not IN_FLIGHT.acquire(blocking=False):
			return Verdict(
				Outcome.PROVIDER_ERROR
			)  # no call: the provider keeps failing, or too many calls are in flight
		try:
			# no `remoteip`: behind the proxy it is the proxy
			reply = self.post(
				VERIFY_URL, data={"secret": self.secret, "response": token}, timeout=self.timeout
			).json()
		except (requests.RequestException, ValueError):
			BREAKER.failed()
			return Verdict(Outcome.PROVIDER_ERROR)
		finally:
			IN_FLIGHT.release()
		if not isinstance(reply, dict):
			BREAKER.failed()
			return Verdict(Outcome.PROVIDER_ERROR)
		BREAKER.succeeded()
		score = reply.get("score")
		numeric = isinstance(score, (int, float)) and not isinstance(score, bool)
		score = score if numeric and math.isfinite(score) else 0  # NaN is valid JSON for Python: not a score
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
