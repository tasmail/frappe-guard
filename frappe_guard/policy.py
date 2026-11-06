"""What to do with a CAPTCHA verdict: the policy of an action and the decision, with no Frappe and no network.

An action (`sign_up`, `contact`, ...) has a mode (`off`: nothing is checked; `monitor`: checked and logged, never refused;
`enforce`: a failed check is refused), a threshold of the score and a fail policy for an outage of the provider (`closed`:
refuse, `open`: let the request pass). The defaults are here; a site tunes them in the Single DocType `Guard Settings` and in
the site config (the site config wins: Press writes it).
"""

import json
from dataclasses import dataclass, replace
from enum import Enum

OFF, MONITOR, ENFORCE = "off", "monitor", "enforce"
MODES = (OFF, MONITOR, ENFORCE)
CLOSED, OPEN = "closed", "open"
FAIL_POLICIES = (CLOSED, OPEN)
DEFAULT_THRESHOLD = 0.5


class Outcome(str, Enum):
	PASS = "pass"
	LOW_SCORE = "low_score"
	MISSING = "missing"
	PROVIDER_ERROR = "provider_error"
	HOST_MISMATCH = "host_mismatch"
	ACTION_MISMATCH = "action_mismatch"
	NOT_CONFIGURED = "not_configured"
	OFF = "off"


@dataclass(frozen=True)
class Verdict:
	"""The answer of a provider about one token."""

	outcome: Outcome
	score: float | None = None


@dataclass(frozen=True)
class ActionPolicy:
	name: str
	provider_action: str
	mode: str = MONITOR
	threshold: float = DEFAULT_THRESHOLD
	fail: str = CLOSED


@dataclass(frozen=True)
class Decision:
	allow: bool
	outcome: Outcome
	score: float | None = None
	mode: str = MONITOR
	would_refuse: bool = False  # in `monitor`: the request passes, but `enforce` would have refused it


def _action(name: str, fail: str = CLOSED) -> ActionPolicy:
	return ActionPolicy(name=name, provider_action=name, fail=fail)


# The forms fail closed; login, reset and the e-mail link fail open under the counters of the rate limiter (plan G5).
DEFAULTS = {
	policy.name: policy
	for policy in (
		_action("sign_up"),
		_action("reset_password", OPEN),
		_action("send_login_link", OPEN),
		_action("login", OPEN),
		_action("contact"),
		_action("download"),
		_action("calculation"),
	)
}


def _valid(field: str, value) -> bool:
	if field == "mode":
		return value in MODES
	if field == "fail":
		return value in FAIL_POLICIES
	if field == "threshold":
		return isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1
	if field == "provider_action":
		return isinstance(value, str) and bool(value)
	return False


def _apply(policy: ActionPolicy, layer) -> ActionPolicy:
	"""A layer is a dict of the fields to change; an invalid value is ignored, never trusted."""
	if not isinstance(layer, dict):
		return policy
	changes = {field: value for field, value in layer.items() if _valid(field, value)}
	return replace(policy, **changes)


def parse_overrides(raw) -> dict:
	"""The JSON of `Guard Settings.action_overrides` (or an already parsed dict); anything else is nothing."""
	if isinstance(raw, dict):
		return raw
	try:
		parsed = json.loads(raw or "{}")
	except (TypeError, ValueError):
		return {}
	return parsed if isinstance(parsed, dict) else {}


def resolve(
	action: str, default_mode: str | None = None, settings_overrides=None, site_overrides=None
) -> ActionPolicy:
	"""The policy of an action: the defaults, then `Guard Settings`, then the site config (the last wins)."""
	policy = DEFAULTS.get(action) or _action(action)
	if default_mode in MODES:
		policy = replace(policy, mode=default_mode)
	for layer in (parse_overrides(settings_overrides), parse_overrides(site_overrides)):
		policy = _apply(policy, layer.get("*"))
		policy = _apply(policy, layer.get(action))
	return policy


def decide(policy: ActionPolicy, verdict: Verdict) -> Decision:
	"""Allow or refuse by the mode, the fail policy and the verdict."""
	if policy.mode == OFF:
		return Decision(True, Outcome.OFF, None, OFF)
	if verdict.outcome == Outcome.PASS:
		return Decision(True, Outcome.PASS, verdict.score, policy.mode)
	refuse = not (verdict.outcome == Outcome.PROVIDER_ERROR and policy.fail == OPEN)
	allow = policy.mode == MONITOR or not refuse
	return Decision(allow, verdict.outcome, verdict.score, policy.mode, would_refuse=refuse and allow)
