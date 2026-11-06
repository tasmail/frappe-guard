"""The check of one request: the policy of the action, the provider, the decision, the log line."""

import frappe
from frappe import _

from frappe_guard import config
from frappe_guard.policy import OFF, Decision, Outcome, Verdict, decide
from frappe_guard.providers.recaptcha_v3 import RecaptchaV3

MESSAGES = {
	Outcome.MISSING: "The check of the form failed. Reload the page and try again.",
	Outcome.LOW_SCORE: "The check of the form failed. Reload the page and try again.",
	Outcome.ACTION_MISMATCH: "The check of the form failed. Reload the page and try again.",
	Outcome.HOST_MISMATCH: "The check of the form failed. Reload the page and try again.",
	Outcome.PROVIDER_ERROR: "The check of the form is not available now. Try again later.",
	Outcome.NOT_CONFIGURED: "The check of the form is not configured",
}


def message(outcome: Outcome) -> str:
	return _(MESSAGES.get(outcome, MESSAGES[Outcome.MISSING]))


def evaluate(action: str, token: str | None, provider=None) -> Decision:
	"""Decide whether a request of `action` with `token` passes. Never raises; the caller throws on `allow` False."""
	policy = config.policy_for(action)
	if policy.mode == OFF:
		return decide(policy, Verdict(Outcome.OFF))
	secret, hosts = config.secret(), config.hosts()
	if provider is None and not (secret and hosts):
		if config.unconfigured_is_allowed():
			return Decision(True, Outcome.NOT_CONFIGURED, None, policy.mode)
		verdict = Verdict(Outcome.NOT_CONFIGURED)
	elif not token:
		verdict = Verdict(Outcome.MISSING)
	else:
		provider = provider or RecaptchaV3(secret, hosts)
		verdict = provider.verify(token, policy.provider_action, policy.threshold)
	decision = decide(policy, verdict)
	record(action, decision)
	return decision


def record(action: str, decision: Decision) -> None:
	"""One log line for a request that did not pass (and for a request that `enforce` would refuse); never a token."""
	if decision.outcome == Outcome.PASS:
		return
	frappe.logger("frappe_guard").info(
		"action=%s outcome=%s mode=%s allow=%s score=%s",
		action,
		decision.outcome.value,
		decision.mode,
		decision.allow,
		decision.score,
	)
