"""The choke point: one `auth_hooks` hook that checks every guarded request before Frappe dispatches it.

`auth_hooks` runs after the API key and bearer check, before the dispatch, and also for `OPTIONS`. The password `login` is
not decided here: `LoginManager` logs in inside `HTTPRequest()`, before any hook (see P7).
"""

import frappe

from frappe_guard import actions, check, clientip, config, ratelimit
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
	policy = config.policy_for(action)
	if policy.mode == OFF:
		return
	signed_in = frappe.session.user not in ("Guest", "", None)
	result = _rate(action, request, signed_in, policy.fail)
	if result.level == ratelimit.Level.HARD:
		decision = Decision(
			policy.mode != ENFORCE, Outcome.RATE_LIMITED, None, policy.mode, policy.mode == MONITOR
		)
		check.record(action, decision)
		if not decision.allow:
			frappe.throw(check.message(Outcome.RATE_LIMITED), frappe.ValidationError)
	if signed_in:
		return  # a signed-in user (also an API key or bearer) skips the captcha; the counters above still applied
	bonus = ratelimit.SOFT_BONUS if result.level == ratelimit.Level.SOFT else 0
	decision = check.evaluate(action, token, threshold_bonus=bonus)
	if not decision.allow:
		frappe.throw(check.message(decision.outcome), frappe.ValidationError)


def _rate(action: str, request, signed_in: bool, fail: str) -> ratelimit.RateResult:
	"""The counters of the request; an error of ours is an outage of the counters: the fail policy of the action decides."""
	try:
		return ratelimit.check(action, _identities(action, request, signed_in), fail)
	except Exception:  # noqa: BLE001  every guarded request passes here: a bug must not become a 500
		frappe.logger("frappe_guard").error("the counters of the request failed", exc_info=True)
		return ratelimit.RateResult(
			ratelimit.Level.HARD if fail == CLOSED else ratelimit.Level.OK, error=True
		)


def _identities(action: str, request, signed_in: bool) -> dict:
	"""What the counters identify the request by: the address, the session user, the recipient of the mail, the site."""
	identities = {"ip": clientip.client_ip(request), "site": ratelimit.SITE_IDENT}
	if signed_in:
		identities["account"] = frappe.session.user
	recipient = ratelimit.recipient(action, frappe.form_dict)
	if recipient:
		identities["recipient"] = recipient
	return identities
