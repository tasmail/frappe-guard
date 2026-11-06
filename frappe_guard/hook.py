"""The choke point: one `auth_hooks` hook that checks every guarded request before Frappe dispatches it.

`auth_hooks` runs after the API key and bearer check, before the dispatch, and also for `OPTIONS`. The password `login` is
not decided here: `LoginManager` logs in inside `HTTPRequest()`, before any hook (see P7).
"""

import frappe

from frappe_guard import actions, check, clientip, ratelimit
from frappe_guard.policy import CLOSED, ENFORCE, MONITOR, OFF, Decision, Outcome

TOKEN_HEADER = "X-Guard-Token"
TOKEN_FIELD = "guard_token"


def take_token(form_dict):
	"""The token of the request: the header, else the field; the field is removed so no endpoint ever receives it."""
	field = form_dict.pop(TOKEN_FIELD, None) if isinstance(form_dict, dict) else None
	return frappe.get_request_header(TOKEN_HEADER) or field


def guard_request() -> None:
	"""Refuse a guarded request that fails the check. Registered in `auth_hooks`; never lets an error through as a 500."""
	request = getattr(frappe.local, "request", None)
	if (
		request is None or request.method == "OPTIONS"
	):  # a CORS preflight has no session and no client address
		return
	token = take_token(frappe.form_dict)  # the token never reaches an endpoint, guarded or not
	try:
		action = actions.action_of(request, frappe.form_dict)
	except Exception:  # noqa: BLE001  every request of the site passes here: a bug of the map must not become a 500
		# fail open on purpose (Frappe answers), but loud: a systematic bug would otherwise disable the guard silently
		frappe.logger("frappe_guard").error("the action of the request could not be told", exc_info=True)
		return
	if action is None:
		return
	policy = check.policy_of(action)
	if policy.mode == OFF:
		return
	signed_in = frappe.session.user not in ("Guest", "", None)
	# First the counters that need no token (address, site; for a signed-in session also account and recipient): they run
	# before the provider is asked, so a flood cannot burn the quota of the provider.
	identities = _identities(action, request, signed_in)
	first = ratelimit.KIND_ORDER if signed_in else ("ip", "site")
	result = _rate(action, identities, policy.fail, first)
	_refuse_if_hard(action, policy, result)
	if signed_in:
		return  # a signed-in user (also an API key or bearer) skips the captcha; the counters above applied
	bonus = ratelimit.SOFT_BONUS if result.level == ratelimit.Level.SOFT else 0
	decision = check.evaluate(action, token, threshold_bonus=bonus, policy=policy)
	if not decision.allow:
		frappe.throw(check.message(decision.outcome), frappe.ValidationError)
	if decision.outcome == Outcome.PASS or not decision.would_refuse:
		# Then the counters of an account and of a recipient, only after the token was verified: a request without a valid
		# token must not burn the counter of a victim's address (the victim would be refused his own password reset).
		_refuse_if_hard(action, policy, _rate(action, identities, policy.fail, ("account", "recipient")))


def _refuse_if_hard(action: str, policy, result: ratelimit.RateResult) -> None:
	if result.level != ratelimit.Level.HARD:
		return
	# an outage of the counters is "not available", a limit that was exceeded is "too many requests"
	outcome = Outcome.PROVIDER_ERROR if result.error else Outcome.RATE_LIMITED
	decision = Decision(policy.mode != ENFORCE, outcome, None, policy.mode, policy.mode == MONITOR)
	check.record(action, decision)
	if not decision.allow:
		frappe.throw(check.message(outcome), frappe.ValidationError)


def _rate(action: str, identities, fail: str, kinds) -> ratelimit.RateResult:
	"""The counters of the request; an error of ours is an outage of the counters: the fail policy of the action decides."""
	try:
		if callable(identities):
			identities = identities()
		return ratelimit.check(action, identities, fail, kinds)
	except Exception:  # noqa: BLE001  every guarded request passes here: a bug must not become a 500
		frappe.logger("frappe_guard").error("the counters of the request failed", exc_info=True)
		return ratelimit.RateResult(
			ratelimit.Level.HARD if fail == CLOSED else ratelimit.Level.OK, error=True
		)


def _identities(action: str, request, signed_in: bool):
	"""What the counters identify the request by: the address, the session user, the recipient of the mail, the site.

	Returned as a function, so that an error while it is made is an outage of the counters (see `_rate`), not a 500.
	"""

	def identities() -> dict:
		found = {"ip": clientip.client_ip(request), "site": ratelimit.SITE_IDENT}
		if signed_in:
			found["account"] = frappe.session.user
		recipient = ratelimit.recipient(action, frappe.form_dict)
		if recipient:
			found["recipient"] = recipient
		return found

	return identities
