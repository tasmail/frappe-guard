"""The configuration of a site: the keys and the host list live in the site config, the tunables in `Guard Settings`.

Nothing here raises on a malformed value: a bad site config must never turn into a 500 or open a closed action, so a value of
the wrong type is ignored (and reported by name) and the defaults of the code apply.
"""

import time

import frappe

from frappe_guard import policy

SETTINGS = "Guard Settings"
# `Guard Settings` is read from the database (two queries; Frappe's value cache lives for one request only), so a process keeps
# the values for a short time: the hook of every guarded request would otherwise run two SQL queries. A change of the settings
# reaches a process within this many seconds.
SETTINGS_TTL = 30
FAILURE_TTL = 3  # a failed read is retried soon, and the last good value keeps being served meanwhile
_memo: dict[str, tuple[float, tuple]] = {}
_good: dict[str, tuple] = {}  # the last values that were read successfully, per site


def reset() -> None:
	"""Forget the remembered settings (tests, and after a change that must show at once)."""
	_memo.clear()
	_good.clear()


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
	"""A value of `Guard Settings`; raises when the DocType is not installed yet or the database fails."""
	return frappe.db.get_single_value(SETTINGS, field)


def _settings() -> tuple:
	"""(default_mode, action_overrides) of `Guard Settings`, remembered per site for `SETTINGS_TTL` seconds."""
	site = str(getattr(frappe.local, "site", "") or "")
	remembered = _memo.get(site)
	now = time.monotonic()
	if remembered and remembered[0] > now:
		return remembered[1]
	try:
		values = (_single("default_mode"), _single("action_overrides"))
	except Exception:  # noqa: BLE001  the DocType is not there yet, or the database fails
		# One transient error must not turn a site that is in `enforce` in `Guard Settings` into `monitor` for a while: the last
		# good values keep being served (the code defaults if there are none) and the read is retried in a few seconds.
		values = _good.get(site, (None, None))
		_memo[site] = (now + FAILURE_TTL, values)
		return values
	_good[site] = values
	_memo[site] = (now + SETTINGS_TTL, values)
	return values


def _site_layer() -> dict:
	"""`guard_actions` of the site config as a fresh dict; `guard_mode` is the default mode of `*` that `guard_actions` can override."""
	actions = frappe.conf.get("guard_actions")
	layer = {key: value for key, value in actions.items()} if isinstance(actions, dict) else {}
	star = dict(layer.get("*")) if isinstance(layer.get("*"), dict) else {}
	mode = frappe.conf.get("guard_mode")
	if mode is not None and mode not in policy.MODES:
		warn_ignored("*", "guard_mode")
	elif mode is not None and star.get("mode") not in policy.MODES:
		if "mode" in star:
			warn_ignored("*", "mode")
		star["mode"] = mode  # an invalid `guard_actions["*"]["mode"]` must not shadow it
	if star:
		layer["*"] = star
	return layer


def policy_for(action: str) -> policy.ActionPolicy:
	"""The policy of an action: the code, `Guard Settings`, the site config (the last wins)."""
	default_mode, overrides = _settings()
	return policy.resolve(action, default_mode or None, overrides, _site_layer(), warn_ignored)


def unconfigured_is_allowed() -> bool:
	"""A site without a secret refuses the actions it guards, except in developer mode and in tests."""
	return bool(frappe.conf.get("developer_mode") or frappe.flags.in_test)
