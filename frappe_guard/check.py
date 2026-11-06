"""The check of one request: the policy of the action, the provider, the decision, the log line.

A site without a secret or host list is `not_configured`: refused in `enforce`, but passed in `monitor` (the default mode; the
log line says so) and in developer mode and tests.
"""

from dataclasses import replace

import frappe
from frappe import _

from frappe_guard import config
from frappe_guard.policy import DEFAULTS, MONITOR, OFF, Decision, Outcome, Verdict, decide
from frappe_guard.providers.recaptcha_v3 import RecaptchaV3

MAX_TOKEN = 4096


def message(outcome: Outcome) -> str:
	if outcome == Outcome.PROVIDER_ERROR:
		return _("The check of the form is not available now. Try again later.")
	if outcome == Outcome.RATE_LIMITED:
		return _("Too many requests. Try again later.")
	if outcome == Outcome.NOT_CONFIGURED:
		return _("The check of the form is not configured")
	return _("The check of the form failed. Reload the page and try again.")


def _usable(token) -> bool:
	"""Only a string of a sane length goes to the provider (a JSON body can carry a list or a dict)."""
	return isinstance(token, str) and 0 < len(token) <= MAX_TOKEN


def evaluate(action: str, token, provider=None, threshold_bonus: float = 0, policy=None) -> Decision:
	"""Decide whether a request of `action` with `token` passes. Never raises; the caller throws on `allow` False.

	An unexpected error is an outage of the check: the fail policy of the action decides, in the configured mode (in `monitor`
	when the configuration itself cannot be read), so a broken check neither crashes the request nor opens a closed action.
	"""
	try:
		return _evaluate(action, token, provider, threshold_bonus, policy)
	except Exception:  # noqa: BLE001  by design: a broken check must not break the request
		_log("the check failed unexpectedly: action=%s", action)
		return decide(policy_of(action), Verdict(Outcome.PROVIDER_ERROR))


def _log(message: str, *args) -> None:
	try:
		frappe.logger("frappe_guard").info(message, *args)
	except Exception:  # noqa: BLE001, S110  logging must not break the request either
		pass


def policy_of(action: str):
	"""The policy of the action as configured; when even that fails, the code defaults in `monitor`.

	The mode is unknown then, and every site starts in `monitor` for a week: a bug of the guard must not refuse the forms of a
	site that never asked for `enforce` (the honeypot and the rate limit stay). A site in `enforce` is not protected for
	the length of such a failure; the log line is the signal.
	"""
	try:
		return config.policy_for(action)
	except Exception:  # noqa: BLE001  see above
		return replace(DEFAULTS.get(action) or config.policy.resolve(action), mode=MONITOR)


def _evaluate(action: str, token, provider, threshold_bonus: float = 0, policy=None) -> Decision:
	policy = policy or config.policy_for(action)
	if policy.mode == OFF:
		return decide(policy, Verdict(Outcome.OFF))
	secret, hosts = config.secret(), config.hosts()
	if provider is None and not (secret and hosts):
		if config.unconfigured_is_allowed():
			return Decision(True, Outcome.NOT_CONFIGURED, None, policy.mode)
		verdict = Verdict(Outcome.NOT_CONFIGURED)
	elif not _usable(token):
		verdict = Verdict(Outcome.MISSING)
	else:
		provider = provider or RecaptchaV3(secret, hosts)
		threshold = min(
			1.0, policy.threshold + max(0, threshold_bonus)
		)  # above a soft limit the score demanded rises
		verdict = provider.verify(token, policy.provider_action, threshold)
	decision = decide(policy, verdict)
	record(action, decision)
	return decision


def record(action: str, decision: Decision) -> None:
	"""One log line for a request that did not pass (and for a request that `enforce` would refuse); never a token."""
	if decision.outcome == Outcome.PASS:
		return
	_log(
		"action=%s outcome=%s mode=%s allow=%s score=%s",
		action,
		decision.outcome.value,
		decision.mode,
		decision.allow,
		decision.score,
	)
