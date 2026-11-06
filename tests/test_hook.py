import types

import pytest
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from frappe_guard import check, hook
from frappe_guard.policy import Decision, Outcome

SIGN_UP = "frappe.core.doctype.user.user.sign_up"


@pytest.fixture
def send(frappe_stub):
	def go(path="/", method="POST", form=None, headers=None, user="Guest"):
		frappe_stub.local.request = Request(EnvironBuilder(path=path, method=method).get_environ())
		frappe_stub.form_dict = {} if form is None else form
		frappe_stub.headers = headers or {}
		frappe_stub.session = types.SimpleNamespace(user=user)
		hook.guard_request()

	return go


class Calls(list):
	allow: dict
	bonus: list


@pytest.fixture
def evaluated(monkeypatch):
	calls = Calls()
	calls.bonus = []

	def evaluate(action, token, threshold_bonus=0):
		calls.bonus.append(threshold_bonus)
		calls.append((action, token))
		return Decision(calls_allow["allow"], Outcome.PASS if calls_allow["allow"] else Outcome.LOW_SCORE)

	calls_allow = {"allow": True}
	monkeypatch.setattr(check, "evaluate", evaluate)
	calls.allow = calls_allow
	return calls


def test_an_unmapped_request_is_not_checked(send, evaluated):
	send("/", form={"cmd": "frappe.ping"})
	send("/api/resource/User", "GET")
	assert evaluated == []


def test_options_and_a_request_object_that_is_missing_are_skipped(send, evaluated, frappe_stub):
	send("/", "OPTIONS", form={"cmd": SIGN_UP})
	frappe_stub.local.request = None
	hook.guard_request()
	assert evaluated == []


def test_a_guest_request_is_checked_with_its_action_and_header_token(send, evaluated):
	send("/", form={"cmd": SIGN_UP}, headers={"X-Guard-Token": "from-header"})
	assert evaluated == [("sign_up", "from-header")]


def test_the_form_field_is_the_token_when_there_is_no_header_and_is_removed(send, evaluated, frappe_stub):
	send("/api/method/frappe.www.contact.send_message", form={"guard_token": "from-field", "subject": "x"})
	assert evaluated == [("contact", "from-field")]
	assert frappe_stub.form_dict == {"subject": "x"}  # the endpoint never receives the token


def test_the_header_beats_the_field_and_both_are_removed(send, evaluated, frappe_stub):
	send("/", form={"cmd": SIGN_UP, "guard_token": "field"}, headers={"X-Guard-Token": "header"})
	assert evaluated == [("sign_up", "header")] and "guard_token" not in frappe_stub.form_dict


def test_a_refused_request_throws_a_validation_error_with_the_message(send, evaluated):
	evaluated.allow["allow"] = False
	with pytest.raises(Exception) as error:
		send("/", form={"cmd": SIGN_UP})
	assert type(error.value).__name__ == "ValidationError" and "Reload the page" in str(error.value)


def test_a_signed_in_user_skips_the_captcha_but_the_token_is_still_removed(send, evaluated, frappe_stub):
	for user in ("Administrator", "a@example.com"):
		send("/", form={"cmd": SIGN_UP, "guard_token": "t"}, user=user)
		assert frappe_stub.form_dict == {"cmd": SIGN_UP}
	assert evaluated == []


def test_the_token_field_is_removed_from_an_unguarded_request_too(send, evaluated, frappe_stub):
	send("/login", form={"cmd": "login", "guard_token": "t"})
	assert frappe_stub.form_dict == {"cmd": "login"} and evaluated == []


def test_an_error_in_the_map_never_becomes_a_500(send, evaluated, monkeypatch, frappe_stub):
	def boom(request, form_dict):
		raise RuntimeError("map")

	monkeypatch.setattr(hook.actions, "action_of", boom)
	send("/", form={"cmd": SIGN_UP})
	assert evaluated == [] and any("could not be told" in line for line in frappe_stub.log.lines)


def test_the_real_check_refuses_a_guarded_request_of_an_unconfigured_site_in_enforce(send, frappe_stub):
	frappe_stub.conf["guard_mode"] = "enforce"
	with pytest.raises(Exception) as error:
		send(f"/api/v1/method/{SIGN_UP}/")
	assert "not configured" in str(error.value)
	frappe_stub.conf["guard_mode"] = "monitor"
	send(f"/api/v1/method/{SIGN_UP}/")  # monitor: nothing is refused


def test_the_hook_is_registered_in_auth_hooks():
	from frappe_guard import hooks

	assert hooks.auth_hooks == ["frappe_guard.hook.guard_request"]


def limits(frappe_stub, action, *limit_rows):
	frappe_stub.conf["guard_limits"] = {
		action: [{"kind": k, "window": 3600, "soft": s, "hard": h} for k, s, h in limit_rows]
	}


def test_above_a_soft_limit_the_captcha_demands_a_higher_score(send, evaluated, frappe_stub):
	limits(frappe_stub, "sign_up", ("ip", 1, 5))
	send("/", form={"cmd": SIGN_UP})
	send("/", form={"cmd": SIGN_UP})
	assert evaluated.bonus == [0, 0.2]


def test_above_a_hard_limit_enforce_refuses_before_the_provider_is_asked(send, evaluated, frappe_stub):
	frappe_stub.conf["guard_mode"] = "enforce"
	limits(frappe_stub, "sign_up", ("ip", 1, 1))
	send("/", form={"cmd": SIGN_UP})
	with pytest.raises(Exception) as error:
		send("/", form={"cmd": SIGN_UP})
	assert "Too many requests" in str(error.value)
	assert len(evaluated) == 1  # the second request never reached the provider
	assert any("outcome=rate_limited" in line and "allow=False" in line for line in frappe_stub.log.lines)


def test_monitor_counts_and_logs_a_hard_limit_but_never_refuses(send, evaluated, frappe_stub):
	frappe_stub.conf["guard_mode"] = "monitor"
	limits(frappe_stub, "sign_up", ("ip", 1, 1))
	send("/", form={"cmd": SIGN_UP})
	send("/", form={"cmd": SIGN_UP})
	assert len(evaluated) == 2
	assert any("outcome=rate_limited" in line and "allow=True" in line for line in frappe_stub.log.lines)


def test_off_counts_nothing_and_checks_nothing(send, evaluated, frappe_stub):
	frappe_stub.conf["guard_mode"] = "off"
	send("/", form={"cmd": SIGN_UP})
	assert evaluated == [] and frappe_stub.cache.values == {}


def test_a_signed_in_user_skips_the_captcha_but_not_the_counters(send, evaluated, frappe_stub):
	frappe_stub.conf["guard_mode"] = "enforce"
	limits(frappe_stub, "sign_up", ("account", 1, 2), ("recipient", 100, 100))
	for n in range(2):
		send("/", form={"cmd": SIGN_UP, "email": f"v{n}@example.com"}, user="a@example.com")
	with pytest.raises(Exception) as error:  # the third distinct recipient: stopped by the account counter
		send("/", form={"cmd": SIGN_UP, "email": "v3@example.com"}, user="a@example.com")
	assert "Too many requests" in str(error.value)
	assert evaluated == []  # no captcha for a signed-in user


def test_a_recipient_is_counted_across_accounts_and_addresses(send, evaluated, frappe_stub):
	frappe_stub.conf["guard_mode"] = "enforce"
	limits(frappe_stub, "reset_password", ("recipient", 1, 2))
	form = {"cmd": "frappe.core.doctype.user.user.reset_password", "user": "Victim@Example.com"}
	send("/", form=dict(form))
	send("/", form=dict(form), user="other@example.com")
	with pytest.raises(frappe_stub.ValidationError):
		send("/", form=dict(form, user=" victim@example.com "))


def test_the_counters_use_the_forwarded_address_not_the_one_the_client_chose(send, evaluated, frappe_stub):
	frappe_stub.conf["guard_mode"] = "enforce"
	limits(frappe_stub, "sign_up", ("ip", 1, 1))
	send("/", form={"cmd": SIGN_UP}, headers={"X-Forwarded-For": "6.6.6.6, 203.0.113.7"})
	with pytest.raises(frappe_stub.ValidationError):  # a different forged left entry is the same client
		send("/", form={"cmd": SIGN_UP}, headers={"X-Forwarded-For": "7.7.7.7, 203.0.113.7"})


def test_redis_down_refuses_a_closed_action_in_enforce_and_passes_an_open_one(send, evaluated, frappe_stub):
	frappe_stub.conf["guard_mode"] = "enforce"
	frappe_stub.cache.down = True
	with pytest.raises(frappe_stub.ValidationError):
		send("/", form={"cmd": SIGN_UP})  # sign_up fails closed
	send("/", form={"cmd": "frappe.www.login.send_login_link", "email": "a@example.com"})  # fails open
	assert len(evaluated) == 1


def test_an_error_of_ours_in_the_counters_is_an_outage_not_a_500(send, evaluated, frappe_stub, monkeypatch):
	def boom(*args, **kwargs):
		raise RuntimeError("identities")

	monkeypatch.setattr(hook.clientip, "client_ip", boom)
	frappe_stub.conf["guard_mode"] = "enforce"
	with pytest.raises(Exception) as error:
		send("/", form={"cmd": SIGN_UP})
	assert "Too many requests" in str(error.value)  # sign_up fails closed
	assert any("counters of the request failed" in line for line in frappe_stub.log.lines)
	send("/", form={"cmd": "frappe.www.login.send_login_link"})  # open: passes
