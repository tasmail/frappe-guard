"""Rate limit of the guarded actions: atomic Redis counters per action, kind and window.

A counter is `SET key 0 EX window NX` plus `INCR` in one transaction (MULTI/EXEC): the first hit creates the key with its TTL,
every hit increments it, nothing races (Frappe's own `rate_limit` does). The key is made with `frappe.cache.make_key` (the db
name prefix: sites that share Redis do not share counters) and holds a hash, never an address or an e-mail.

Kinds: `ip` (the client address, see `clientip`), `account` (the session user, for a signed-in session), `recipient` (the
address a mail is sent to: `sign_up`, `reset_password`, `send_login_link` mail a caller-chosen address) and `site` (every
request of the action: a flood guard that does not depend on any spoofable value). A `soft` limit only raises the score the
CAPTCHA demands (a shared NAT is not locked out), a `hard` limit refuses. A guest's `account` and `recipient` counters are
counted only after the CAPTCHA passed (`hook`): a request without a valid token cannot burn the counter of a victim's address. Redis down: the fail policy of the action decides, a
closed action is never passed silently.
"""

from dataclasses import dataclass
from enum import IntEnum

import frappe

from frappe_guard.clientip import UNKNOWN, identifier
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


_BURST = Limit("ip", 60, 5, 20)
_MAIL = (
	Limit("ip", 3600, 10, 60),
	# Only the hard limit of `account` and `recipient` is active (soft = hard): they are counted after the CAPTCHA passed (or for
	# a signed-in session, which has no CAPTCHA), so there is no score left to raise. A mail-bomb cap, not a quota of the owner
	# of the address. Known residual risk: an attacker with valid tokens can use the cap up for a victim's address (an hour).
	Limit("account", 3600, 20, 20),
	Limit("recipient", 3600, 20, 20),
	Limit("site", 3600, 200, 600),
)
_FORM = (Limit("ip", 3600, 20, 100), Limit("site", 3600, 300, 1000))
DEFAULT_LIMITS = {
	"sign_up": (_BURST, *_MAIL),
	"reset_password": (_BURST, *_MAIL),
	"send_login_link": (_BURST, *_MAIL),
	"contact": (_BURST, *_FORM),
	"download": (_BURST, *_FORM),
	"calculation": (_BURST, *_FORM),
}
FALLBACK_LIMITS = (_BURST, *_FORM)
# The per-identity counters come first, the site counter last: a request that a per-identity limit already refused is not
# counted against the shared counters (one address must not exhaust the site counter for everyone).
KIND_ORDER = ("ip", "account", "recipient", "site")


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
	"""The limits of an action: the defaults, with the kinds that `guard_limits` of the site config names replaced.

	`guard_limits` is {action: [limit, ...]}; a kind that it names replaces every default limit of that kind (a config with only
	`ip` keeps the default `site` counter); an invalid limit is ignored.
	"""
	defaults = DEFAULT_LIMITS.get(action, FALLBACK_LIMITS)
	site = frappe.conf.get("guard_limits")
	raw = site.get(action) if isinstance(site, dict) else None
	if not isinstance(raw, list):
		return defaults
	by_window = {
		(limit.kind, limit.window): limit for limit in map(_limit, raw) if limit
	}  # a repeated (kind, window): the last
	valid = tuple(by_window.values())
	named = {limit.kind for limit in valid}
	return tuple(limit for limit in defaults if limit.kind not in named) + valid


def hit(action: str, kind: str, ident: str, window: int) -> int:
	"""Count one request and return the count of its window. Raises when Redis fails."""
	key = frappe.cache.make_key(f"guard:{action}:{kind}:{window}:{identifier(ident)}")
	pipe = frappe.cache.pipeline(transaction=True)
	pipe.set(key, 0, ex=window, nx=True)
	pipe.incr(key)
	return int(pipe.execute()[-1])


def check(action: str, identities: dict[str, str], fail: str = CLOSED, kinds=KIND_ORDER) -> RateResult:
	"""Count the request against the limits of the given kinds and return the worst level.

	The kinds are counted in the order of `KIND_ORDER`; after the first hard limit nothing more is counted, so a refused request
	does not feed the shared counters. A missing identity is not counted; an unknown client address (see `clientip`) is counted
	per action and window under the kind `unknown` (never refused), and then the site limit can only raise the score, not
	refuse (one client with no address of its own must not be able to lock everyone out).
	"""
	worst = RateResult()
	limits = sorted(limits_for(action), key=lambda limit: KIND_ORDER.index(limit.kind))
	try:
		for limit in limits:
			ident = identities.get(limit.kind)
			if limit.kind not in kinds or not ident:
				continue
			if ident == UNKNOWN:
				# no per-client counter is possible; count the requests of unknown clients (never refused) so that the
				# loud log line of `clientip` is not the only signal that the proxy chain is not what is configured
				hit(action, "unknown", SITE_IDENT, limit.window)
				continue
			count = hit(action, limit.kind, ident, limit.window)
			level = Level.HARD if count > limit.hard else Level.SOFT if count > limit.soft else Level.OK
			if limit.kind == "site" and identities.get("ip") == UNKNOWN:
				# with no per-client counter one client could use the site limit up and refuse everyone: it only raises the score
				level = min(level, Level.SOFT)
			if level > worst.level:
				worst = RateResult(level, limit.kind)
			if worst.level == Level.HARD:
				break
	except Exception:  # noqa: BLE001  Redis down: the fail policy of the action decides
		return RateResult(Level.HARD if fail == CLOSED else Level.OK, error=True)
	return worst


def recipient(action: str, form_dict) -> str | None:
	"""The normalised address that a mail of this action goes to, if the action has such a field.

	For counting only, a `+tag` of the local part is dropped (plus-aliases of one mailbox share a counter).
	"""
	field = RECIPIENT_FIELDS.get(action)
	value = form_dict.get(field) if field and isinstance(form_dict, dict) else None
	if not (isinstance(value, str) and value.strip()):
		return None
	local, at, domain = value.strip().lower().partition("@")
	return f"{local.split('+', 1)[0]}{at}{domain}"
