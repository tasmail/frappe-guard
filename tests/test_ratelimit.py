import pytest

from frappe_guard import ratelimit
from frappe_guard.policy import CLOSED, OPEN
from frappe_guard.ratelimit import Level, Limit


def ids(**kw):
	return {"ip": "1.2.3.4", "site": "*", **kw}


def test_a_hit_counts_per_window_and_the_first_hit_sets_the_ttl(frappe_stub):
	assert [ratelimit.hit("contact", "ip", "1.2.3.4", 60) for _ in range(3)] == [1, 2, 3]
	assert list(frappe_stub.cache.ttls.values()) == [60]
	assert ratelimit.hit("contact", "ip", "5.6.7.8", 60) == 1  # another identity
	assert ratelimit.hit("contact", "ip", "1.2.3.4", 3600) == 1  # another window


def test_the_key_has_the_db_prefix_and_holds_no_address_or_mail(frappe_stub):
	ratelimit.hit("sign_up", "recipient", "victim@example.com", 3600)
	(key,) = frappe_stub.cache.values
	assert key.startswith(b"db|guard:sign_up:recipient:3600:")
	assert b"victim" not in key and b"example.com" not in key


def test_below_the_soft_limit_is_ok_then_soft_then_hard(frappe_stub):
	frappe_stub.conf["guard_limits"] = {"contact": [{"kind": "ip", "window": 3600, "soft": 2, "hard": 4}]}
	levels = [ratelimit.check("contact", ids()).level for _ in range(5)]
	assert levels == [Level.OK, Level.OK, Level.SOFT, Level.SOFT, Level.HARD]
	assert ratelimit.check("contact", ids()).kind == "ip"


def test_a_kind_without_an_identity_is_not_counted(frappe_stub):
	ratelimit.check("sign_up", {"site": "*"})
	assert len(frappe_stub.cache.values) == 1  # only the site counter
	ratelimit.check("sign_up", {})
	assert len(frappe_stub.cache.values) == 1


def test_the_worst_level_and_its_kind_are_reported(frappe_stub):
	frappe_stub.conf["guard_limits"] = {
		"sign_up": [
			{"kind": "ip", "window": 3600, "soft": 100, "hard": 200},
			{"kind": "recipient", "window": 3600, "soft": 1, "hard": 2},
		]
	}
	identities = ids(recipient="a@example.com")
	results = [ratelimit.check("sign_up", identities) for _ in range(3)]
	assert [(r.level, r.kind) for r in results] == [
		(Level.OK, None),
		(Level.SOFT, "recipient"),
		(Level.HARD, "recipient"),
	]


def test_a_distinct_recipient_is_counted_on_its_own(frappe_stub):
	frappe_stub.conf["guard_limits"] = {
		"sign_up": [{"kind": "recipient", "window": 3600, "soft": 1, "hard": 1}]
	}
	assert ratelimit.check("sign_up", ids(recipient="a@example.com")).level == Level.OK
	assert ratelimit.check("sign_up", ids(recipient="b@example.com")).level == Level.OK
	assert ratelimit.check("sign_up", ids(recipient="a@example.com")).level == Level.HARD


def test_redis_down_follows_the_fail_policy_of_the_action(frappe_stub):
	frappe_stub.cache.down = True
	closed = ratelimit.check("contact", ids(), CLOSED)
	assert (closed.level, closed.error) == (Level.HARD, True)  # a closed action is never passed silently
	opened = ratelimit.check("login", ids(), OPEN)
	assert (opened.level, opened.error) == (Level.OK, True)


@pytest.mark.parametrize(
	"raw",
	[
		"x",
		{"kind": "bogus", "window": 60, "soft": 1, "hard": 2},
		{"kind": "ip", "window": 0, "soft": 1, "hard": 2},
		{"kind": "ip", "window": 60, "soft": 3, "hard": 2},
		{"kind": "ip", "window": 60, "soft": 0, "hard": 2},
		{"kind": "ip", "window": True, "soft": 1, "hard": 2},
		{"kind": "ip", "window": "60", "soft": 1, "hard": 2},
	],
)
def test_an_invalid_limit_of_the_site_config_leaves_the_defaults(frappe_stub, raw):
	frappe_stub.conf["guard_limits"] = {"contact": [raw]}
	assert ratelimit.limits_for("contact") == ratelimit.DEFAULT_LIMITS["contact"]


def test_the_site_limits_replace_the_defaults_and_an_unknown_action_gets_the_fallback(frappe_stub):
	frappe_stub.conf["guard_limits"] = {"contact": [{"kind": "site", "window": 60, "soft": 1, "hard": 2}]}
	assert ratelimit.limits_for("contact") == (Limit("site", 60, 1, 2),)
	frappe_stub.conf["guard_limits"] = "not a dict"
	assert ratelimit.limits_for("whatever") == ratelimit.FALLBACK_LIMITS


def test_the_defaults_have_a_site_counter_for_every_guarded_action_and_a_recipient_counter_for_the_mail_actions():
	for action, limits in ratelimit.DEFAULT_LIMITS.items():
		assert any(limit.kind == "site" for limit in limits), action
	for action in ratelimit.RECIPIENT_FIELDS:
		assert any(limit.kind == "recipient" for limit in ratelimit.DEFAULT_LIMITS[action]), action


def test_the_recipient_is_normalised_and_comes_from_the_field_of_the_action():
	assert ratelimit.recipient("sign_up", {"email": " A@Example.COM "}) == "a@example.com"
	assert ratelimit.recipient("send_login_link", {"email": "a@example.com"}) == "a@example.com"
	assert (
		ratelimit.recipient("reset_password", {"user": "u@example.com", "email": "x@y.z"}) == "u@example.com"
	)
	assert (
		ratelimit.recipient("contact", {"email": "a@example.com"}) is None
	)  # no recipient field for this action
	for bad in ({}, {"email": ""}, {"email": "  "}, {"email": ["a"]}, {"email": 5}):
		assert ratelimit.recipient("sign_up", bad) is None
	assert ratelimit.recipient("sign_up", None) is None
