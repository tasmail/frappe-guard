"""The configuration of a site: the keys and the host list live in the site config, the tunables in `Guard Settings`.

Nothing here raises on a malformed value: a bad site config must never turn into a 500 or open a closed action, so a value of
the wrong type is ignored (and reported by name) and the defaults of the code apply.
"""

import frappe

from frappe_guard import policy

SETTINGS = "Guard Settings"


def secret() -> str:
	value = frappe.conf.get("guard_recaptcha_secret")
	return value if isinstance(value, str) else ""


def site_key() -> str:
	value = frappe.conf.get("guard_recaptcha_site_key")
	return value if isinstance(value, str) else ""


def hosts() -> list[str]:
	"""The host names the tokens of this site are accepted from (public, internal and staging names), one list per key."""
	value = frappe.conf.get("guard_hosts")
	if isinstance(value, str):
		value = [value]
	return [host for host in value if isinstance(host, str)] if isinstance(value, (list, tuple)) else []


def warn_ignored(action: str, field: str) -> None:
	frappe.logger("frappe_guard").info("ignored an invalid override: action=%s field=%s", action, field)


def _single(field: str):
	"""A value of `Guard Settings`; None when the DocType is not installed yet or the database fails."""
	try:
		return frappe.db.get_single_value(SETTINGS, field)
	except Exception:  # noqa: BLE001 by design, see the docstring
		return None


def _site_layer() -> dict:
	"""`guard_actions` of the site config as a fresh dict; `guard_mode` is the default mode of `*` that `guard_actions` can override."""
	actions = frappe.conf.get("guard_actions")
	layer = {key: value for key, value in actions.items()} if isinstance(actions, dict) else {}
	star = dict(layer.get("*")) if isinstance(layer.get("*"), dict) else {}
	if frappe.conf.get("guard_mode") in policy.MODES:
		star.setdefault("mode", frappe.conf.get("guard_mode"))
	if star:
		layer["*"] = star
	return layer


def policy_for(action: str) -> policy.ActionPolicy:
	"""The policy of an action: the code, `Guard Settings`, the site config (the last wins)."""
	return policy.resolve(
		action, _single("default_mode") or None, _single("action_overrides"), _site_layer(), warn_ignored
	)


def unconfigured_is_allowed() -> bool:
	"""A site without a secret refuses the actions it guards, except in developer mode and in tests."""
	return bool(frappe.conf.get("developer_mode") or frappe.flags.in_test)
