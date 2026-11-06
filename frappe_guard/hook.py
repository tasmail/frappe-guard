"""The choke point: one `auth_hooks` hook that checks every guarded request before Frappe dispatches it.

`auth_hooks` runs after the API key and bearer check, before the dispatch, and also for `OPTIONS`. The password `login` is
not decided here: `LoginManager` logs in inside `HTTPRequest()`, before any hook (see P7).
"""

import frappe

from frappe_guard import actions, check

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
	if frappe.session.user not in ("Guest", "", None):
		return  # a signed-in user (also an API key or bearer) skips the captcha; the counters of P8 still apply
	decision = check.evaluate(action, token)
	if not decision.allow:
		frappe.throw(check.message(decision.outcome), frappe.ValidationError)
