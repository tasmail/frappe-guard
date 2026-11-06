"""The configuration of a site: the keys and the host list live in the site config, the tunables in `Guard Settings`."""

import frappe

from frappe_guard import policy

SETTINGS = "Guard Settings"


def secret() -> str:
	return frappe.conf.get("guard_recaptcha_secret") or ""


def site_key() -> str:
	return frappe.conf.get("guard_recaptcha_site_key") or ""


def hosts() -> list[str]:
	"""The host names the tokens of this site are accepted from (public, internal and staging names), one list per key."""
	value = frappe.conf.get("guard_hosts") or []
	return [value] if isinstance(value, str) else list(value)


def policy_for(action: str) -> policy.ActionPolicy:
	"""The policy of an action: the code, `Guard Settings`, the site config (the last wins)."""
	default_mode = frappe.db.get_single_value(SETTINGS, "default_mode") or None
	overrides = frappe.db.get_single_value(SETTINGS, "action_overrides")
	site_overrides = dict(frappe.conf.get("guard_actions") or {})
	if frappe.conf.get("guard_mode") in policy.MODES:
		site_overrides.setdefault("*", {})["mode"] = frappe.conf.get("guard_mode")
	return policy.resolve(action, default_mode, overrides, site_overrides)


def unconfigured_is_allowed() -> bool:
	"""A site without a secret refuses the actions it guards, except in developer mode and in tests."""
	return bool(frappe.conf.get("developer_mode") or frappe.flags.in_test)
