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


@pytest.fixture
def evaluated(monkeypatch):
	calls = Calls()

	def evaluate(action, token):
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
