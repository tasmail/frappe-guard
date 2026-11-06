import pytest
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from frappe_guard import actions

SIGN_UP = "frappe.core.doctype.user.user.sign_up"


def request(path, method="POST", query=""):
	return Request(EnvironBuilder(path=path, method=method, query_string=query).get_environ())


def method_of(path, form=None, http="POST"):
	return actions.requested_method(request(path, http), {} if form is None else form)


@pytest.mark.parametrize(
	"path",
	[
		f"/api/method/{SIGN_UP}",
		f"/api/v1/method/{SIGN_UP}",
		f"/api/method/{SIGN_UP}/",
		f"/api/v1/method/{SIGN_UP}/",
		f"/api/method/{SIGN_UP}/anything/else",  # Frappe splits at the first slash
		f"/api/v1/method/{SIGN_UP}/anything",
		f"/api/v2/method/{SIGN_UP}",
		f"/api/v2/method/{SIGN_UP}/",
	],
)
@pytest.mark.parametrize("http", ["POST", "GET"])
def test_every_mount_the_slash_and_the_suffix_give_the_same_method(path, http):
	assert method_of(path, http=http) == SIGN_UP


def test_the_v2_doctype_form_resolves_the_module_of_the_controller(frappe_stub):
	frappe_stub.doctype_modules["User"] = "frappe.core.doctype.user.user"
	assert method_of("/api/v2/method/User/sign_up") == SIGN_UP
	assert method_of("/api/v2/method/Unknown/sign_up") is None  # Frappe fails the same lookup and answers


@pytest.mark.parametrize(
	"path",
	[
		"/",
		"/login",
		"/api/resource/User",
		"/api/v2/method/ping",
		"/api/v2/method/login",
		"/api/v2/document/User",
		"/api/nothing",
		"/api//method/x",  # merge_slashes is off in Frappe: a 404 there too
		"/app/user",
	],
)
def test_a_path_that_is_not_a_method_call_gives_none(path):
	assert method_of(path) is None


@pytest.mark.parametrize(
	"path", ["/", "/x", "/login", "/api/method/ping", "/api/resource/User", "/app/anything"]
)
def test_cmd_wins_on_every_path_and_method(path):
	assert method_of(path, {"cmd": SIGN_UP}, "POST") == SIGN_UP
	assert method_of(path, {"cmd": SIGN_UP}, "GET") == SIGN_UP


@pytest.mark.parametrize("cmd", [["a"], {"a": 1}, 5, True])
def test_a_cmd_that_is_not_a_string_is_not_a_method_call(cmd):
	assert method_of("/x", {"cmd": cmd}) is None
	assert (
		method_of(f"/api/method/{SIGN_UP}", {"cmd": cmd}) is None
	)  # Frappe's handler fails it, nothing is run


def test_a_form_dict_that_is_not_a_dict_falls_back_to_the_path():
	assert actions.requested_method(request(f"/api/method/{SIGN_UP}"), ["a", "list"]) == SIGN_UP
	assert actions.requested_method(request("/x"), None) is None


def test_the_default_map_and_the_site_map(frappe_stub):
	assert actions.action_of(request("/x"), {"cmd": SIGN_UP}) == "sign_up"
	assert actions.action_of(request("/x"), {"cmd": "frappe.www.contact.send_message"}) == "contact"
	assert actions.action_of(request("/x"), {"cmd": "unknown.method"}) is None
	frappe_stub.conf["guard_action_map"] = {"my.app.send": "contact", SIGN_UP: "signup2", 5: "x", "bad": 5}
	assert actions.action_of(request("/x"), {"cmd": "my.app.send"}) == "contact"
	assert actions.action_of(request("/x"), {"cmd": SIGN_UP}) == "signup2"  # the site map wins
	assert "bad" not in actions.action_map()
	frappe_stub.conf["guard_action_map"] = "not a dict"
	assert actions.action_map() == actions.DEFAULT_MAP


def test_the_login_action_is_not_mapped_here():
	assert actions.action_of(request("/api/method/login"), {}) is None
	assert actions.action_of(request("/login"), {"cmd": "login"}) is None


def _fake_map(monkeypatch, endpoint, arguments):
	import sys

	class Bound:
		def match(self):
			return endpoint, arguments

	class Map:
		def bind_to_environ(self, environ):
			return Bound()

	monkeypatch.setattr(sys.modules["frappe.api"], "API_URL_MAP", Map())


def test_a_matched_rpc_rule_without_a_string_method_gives_none(monkeypatch):
	import sys

	_fake_map(monkeypatch, sys.modules["frappe.api"].v1.handle_rpc_call, {"method": None})
	assert method_of("/api/method/x") is None


def test_an_endpoint_that_is_only_named_like_the_rpc_one_does_not_match(monkeypatch):
	def handle_rpc_call():  # same name, not the endpoint of Frappe
		pass

	_fake_map(monkeypatch, handle_rpc_call, {"method": SIGN_UP})
	assert method_of("/api/method/x") is None


@pytest.mark.parametrize(
	"path", ["/api/v1/method/upload_file", "/api/method/upload_file", "/api/v2/method/upload_file"]
)
def test_upload_file_names_the_method_it_calls(path):
	assert method_of(path, {"method": SIGN_UP}) == SIGN_UP
	assert method_of(path, {"method": 5}) == "upload_file"
	assert method_of("/x", {"cmd": "upload_file", "method": SIGN_UP}) == SIGN_UP
	assert method_of("/x", {"cmd": "frappe.handler.upload_file", "method": SIGN_UP}) == SIGN_UP


def test_an_empty_cmd_falls_through_to_the_router_as_in_frappe():
	assert method_of(f"/api/method/{SIGN_UP}", {"cmd": ""}) == SIGN_UP
	assert method_of("/x", {"cmd": ""}) is None


def test_head_and_the_v2_prefix_with_cmd():
	assert method_of(f"/api/method/{SIGN_UP}", http="HEAD") == SIGN_UP
	assert method_of("/api/v2/method/ping", {"cmd": SIGN_UP}) == SIGN_UP  # cmd wins, as in Frappe
