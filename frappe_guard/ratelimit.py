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


def _key(action: str, kind: str, ident: str, window: int) -> bytes:
	return frappe.cache.make_key(f"guard:{action}:{kind}:{window}:{identifier(ident)}")


def hit_many(entries: list[tuple[str, str, str, int]]) -> list[int]:
	"""Count one request in every entry (action, kind, identity, window) in ONE round trip to Redis and return the counts.

	One MULTI/EXEC transaction of `SET key 0 EX window NX` and `INCR key` per entry: atomic, and the cost of a guarded request
	is one round trip however many counters it has. Raises when Redis fails.
	"""
	pipe = frappe.cache.pipeline(transaction=True)
	keys = [_key(*entry) for entry in entries]
	for key, entry in zip(keys, entries, strict=True):
		pipe.set(key, 0, ex=entry[3], nx=True)
		pipe.incr(key)
	return [int(count) for count in pipe.execute()[1::2]]


def hit(action: str, kind: str, ident: str, window: int) -> int:
	"""Count one request in one counter and return the count of its window. Raises when Redis fails."""
	return hit_many([(action, kind, ident, window)])[0]


def _refund(entries: list[tuple[str, str, str, int]]) -> None:
	"""Take back the counts of the counters that a refused request must not feed (best effort, never raises).

	Not atomic with the count: for the milliseconds in between, other requests see the counters a little too high (by the
	number of requests in flight that are being refused).
	"""
	if not entries:
		return
	try:
		pipe = frappe.cache.pipeline(transaction=True)
		for entry in entries:
			key = _key(*entry)
			# `SET NX EX` first: a key that expired or was evicted since the count must not come back as `-1` without a TTL (a
			# counter that never resets); with the TTL a missing key is a harmless -1 that expires with its window
			pipe.set(key, 0, ex=entry[3], nx=True)
			pipe.decr(key)
		pipe.execute()
	except Exception:  # noqa: BLE001, S110  a counter that was not refunded only errs on the side of refusing
		pass


def check(action: str, identities: dict[str, str], fail: str = CLOSED, kinds=KIND_ORDER) -> RateResult:
	"""Count the request against the limits of the given kinds and return the worst level.

	One round trip to Redis for all the counters (a second one only when the request is refused). The kinds are ordered as
	`KIND_ORDER`; the counters after the first hard limit are given back, so a refused request does not feed the shared
	counters. A missing identity is not counted; an unknown client address (see `clientip`) is counted per action and window
	under the kind `unknown` (never refused), and then the site limit can only raise the score, not refuse (one client with no
	address of its own must not be able to lock everyone out).
	"""
	unknown_client = identities.get("ip") == UNKNOWN
	plan = []  # (limit, the entry that is counted)
	for limit in sorted(limits_for(action), key=lambda limit: KIND_ORDER.index(limit.kind)):
		ident = identities.get(limit.kind)
		if limit.kind not in kinds or not ident:
			continue
		# an unknown address has no counter of its own: the requests of unknown clients are counted (never refused), so that
		# the loud log line of `clientip` is not the only signal that the proxy chain is not what is configured
		plan.append(
			(
				limit,
				(action, "unknown", SITE_IDENT, limit.window)
				if limit.kind == "ip"
				and ident == UNKNOWN  # only an address can be unknown, not a recipient named "unknown"
				else (action, limit.kind, ident, limit.window),
			)
		)
	if not plan:
		return RateResult()
	try:
		counts = hit_many([entry for _, entry in plan])
	except Exception:  # noqa: BLE001  Redis down: the fail policy of the action decides
		return RateResult(Level.HARD if fail == CLOSED else Level.OK, error=True)
	worst = RateResult()
	for position, ((limit, entry), count) in enumerate(zip(plan, counts, strict=True)):
		if entry[1] == "unknown":
			continue
		level = Level.HARD if count > limit.hard else Level.SOFT if count > limit.soft else Level.OK
		if limit.kind == "site" and unknown_client:
			level = min(
				level, Level.SOFT
			)  # one client must not be able to use the site limit up and refuse everyone
		if level > worst.level:
			worst = RateResult(level, limit.kind)
		if level == Level.HARD:
			_refund([later for _, later in plan[position + 1 :] if later[1] != "unknown"])
			break
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
