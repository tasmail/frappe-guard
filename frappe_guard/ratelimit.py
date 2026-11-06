"""Rate limit of the guarded actions: atomic Redis counters per action, kind and window.

A counter is `SET key 0 EX window NX` plus `INCR` in one transaction (MULTI/EXEC): the first hit creates the key with its TTL,
every hit increments it, nothing races (Frappe's own `rate_limit` does). The key is made with `frappe.cache.make_key` (the db
name prefix: sites that share Redis do not share counters) and holds a hash, never an address or an e-mail.

Kinds: `ip` (the client address, see `clientip`), `account` (the session user, for a signed-in session), `recipient` (the
address a mail is sent to: `sign_up`, `reset_password`, `send_login_link` mail a caller-chosen address) and `site` (every
request of the action: a flood guard that does not depend on any spoofable value). A `soft` limit only raises the score the
CAPTCHA demands (a shared NAT is not locked out), a `hard` limit refuses. Redis down: the fail policy of the action decides, a
closed action is never passed silently.
"""

from dataclasses import dataclass
from enum import IntEnum

import frappe

from frappe_guard.clientip import identifier
from frappe_guard.policy import CLOSED

SOFT_BONUS = 0.2  # the score demanded on top of the threshold above a soft limit
SITE_IDENT = "*"
RECIPIENT_FIELDS = {"sign_up": "email", "send_login_link": "email", "reset_password": "user"}


@dataclass(frozen=True)
class Limit:
	kind: str
	window: int  # seconds
	soft: int
	hard: int


class Level(IntEnum):
	OK = 0
	SOFT = 1
	HARD = 2


@dataclass(frozen=True)
class RateResult:
	level: Level = Level.OK
	kind: str | None = None
	error: bool = False  # the counters could not be read


_BURST = Limit("ip", 60, 3, 10)
_MAIL = (
	Limit("ip", 3600, 5, 20),
	Limit("recipient", 3600, 2, 5),
	Limit("account", 3600, 5, 20),
	Limit("site", 3600, 200, 600),
)
_FORM = (Limit("ip", 3600, 10, 40), Limit("site", 3600, 300, 1000))
DEFAULT_LIMITS = {
	"sign_up": (_BURST, *_MAIL),
	"reset_password": (_BURST, *_MAIL),
	"send_login_link": (_BURST, *_MAIL),
	"contact": (_BURST, *_FORM),
	"download": (_BURST, *_FORM),
	"calculation": (_BURST, *_FORM),
}
FALLBACK_LIMITS = (_BURST, *_FORM)


def _limit(raw) -> Limit | None:
	"""A limit of the site config, `{"kind": "ip", "window": 3600, "soft": 5, "hard": 20}`; anything else is ignored."""
	if not isinstance(raw, dict):
		return None
	kind, window, soft, hard = (raw.get(key) for key in ("kind", "window", "soft", "hard"))
	ints = all(isinstance(value, int) and not isinstance(value, bool) for value in (window, soft, hard))
	if kind in ("ip", "account", "recipient", "site") and ints and 0 < window and 0 < soft <= hard:
		return Limit(kind, window, soft, hard)
	return None


def limits_for(action: str) -> tuple[Limit, ...]:
	"""The limits of an action: the site config (`guard_limits`: {action: [limit, ...]}) replaces the defaults, if valid."""
	site = frappe.conf.get("guard_limits")
	raw = site.get(action) if isinstance(site, dict) else None
	if isinstance(raw, list):
		valid = tuple(limit for limit in map(_limit, raw) if limit)
		if valid:
			return valid
	return DEFAULT_LIMITS.get(action, FALLBACK_LIMITS)


def hit(action: str, kind: str, ident: str, window: int) -> int:
	"""Count one request and return the count of its window. Raises when Redis fails."""
	key = frappe.cache.make_key(f"guard:{action}:{kind}:{window}:{identifier(ident)}")
	pipe = frappe.cache.pipeline(transaction=True)
	pipe.set(key, 0, ex=window, nx=True)
	pipe.incr(key)
	return int(pipe.execute()[-1])


def check(action: str, identities: dict[str, str], fail: str = CLOSED) -> RateResult:
	"""Count the request against every limit of the action that has an identity and return the worst level."""
	worst = RateResult()
	try:
		for limit in limits_for(action):
			ident = identities.get(limit.kind)
			if not ident:
				continue
			count = hit(action, limit.kind, ident, limit.window)
			level = Level.HARD if count > limit.hard else Level.SOFT if count > limit.soft else Level.OK
			if level > worst.level:
				worst = RateResult(level, limit.kind)
	except Exception:  # noqa: BLE001  Redis down: the fail policy of the action decides
		return RateResult(Level.HARD if fail == CLOSED else Level.OK, error=True)
	return worst


def recipient(action: str, form_dict) -> str | None:
	"""The normalised address that a mail of this action goes to, if the action has such a field."""
	field = RECIPIENT_FIELDS.get(action)
	value = form_dict.get(field) if field and isinstance(form_dict, dict) else None
	return value.strip().lower() if isinstance(value, str) and value.strip() else None
