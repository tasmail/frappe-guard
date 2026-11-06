"""The guard runs on EVERY request of a site: these tests pin what it may cost (round trips, queries, calls), not seconds."""

import types

import pytest
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from frappe_guard import actions, check, hook
from frappe_guard.policy import Decision, Outcome

SIGN_UP = "frappe.core.doctype.user.user.sign_up"
CONTACT = "frappe.www.contact.send_message"


@pytest.fixture
def run(frappe_stub, monkeypatch):
	"""Send a request through the hook and count the I/O it caused."""
	provider_calls = []

	def evaluate(action, token, provider=None, threshold_bonus=0, policy=None):
		provider_calls.append(action)
		return Decision(True, Outcome.PASS, 0.9, "enforce")

	monkeypatch.setattr(check, "evaluate", evaluate)
	frappe_stub.conf.update(guard_mode="enforce", guard_trusted_hops=1)
	reads = []
	real = frappe_stub.db.get_single_value
	frappe_stub.db.get_single_value = lambda doctype, field: reads.append(field) or real(doctype, field)

	def go(path="/", method="POST", form=None, user="Guest", forwarded="203.0.113.7"):
		frappe_stub.local.request = Request(
			EnvironBuilder(path=path, method=method, headers={"X-Forwarded-For": forwarded}).get_environ()
		)
		frappe_stub.form_dict = {} if form is None else form
		frappe_stub.session = types.SimpleNamespace(user=user)
		before = frappe_stub.cache.round_trips
		hook.guard_request()
		return frappe_stub.cache.round_trips - before

	go.reads, go.provider_calls, go.stub = reads, provider_calls, frappe_stub
	return go


@pytest.mark.parametrize(
	("path", "form"),
	[
		("/", {}),
		("/app/user", {}),
		("/api/resource/User", {}),
		("/api/method/frappe.ping", {}),
		("/api/method/frappe.client.get_list", {}),
		("/api/v2/method/frappe.desk.search.search_link", {}),
		("/", {"cmd": "frappe.desk.form.load.getdoc"}),
		("/login", {"cmd": "login"}),
	],
)
def test_a_request_that_is_not_guarded_costs_no_redis_no_query_and_no_provider_call(run, path, form):
	assert run(path, form=dict(form)) == 0
	assert run.reads == [] and run.provider_calls == [] and run.stub.log.lines == []


def test_an_unguarded_api_method_is_resolved_once_per_process_not_per_request(run):
	actions._resolve.cache_clear()
	for _ in range(100):
		run("/api/method/some_app.api.thing", method="GET")
	info = actions._resolve.cache_info()
	assert info.misses == 1 and info.hits == 99


def test_the_cache_of_resolved_names_is_bounded(run):
	actions._resolve.cache_clear()
	for n in range(actions._resolve.cache_info().maxsize + 500):
		run("/", form={"cmd": f"junk.module.name{n}"})
	assert actions._resolve.cache_info().currsize <= actions._resolve.cache_info().maxsize


def test_a_guarded_guest_request_with_a_recipient_costs_two_round_trips(run):
	assert (
		run("/", form={"cmd": SIGN_UP, "email": "a@example.com"}) == 2
	)  # address + site, then the recipient
	assert run.provider_calls == ["sign_up"]


def test_a_guarded_form_without_a_recipient_costs_one_round_trip(run):
	assert run("/", form={"cmd": CONTACT}) == 1


def test_a_signed_in_session_costs_one_round_trip_for_all_its_counters(run):
	assert run("/", form={"cmd": SIGN_UP, "email": "a@example.com"}, user="a@example.com") == 1
	assert run.provider_calls == []


def test_a_refused_request_costs_at_most_one_more_round_trip_to_give_the_shared_counters_back(run):
	run.stub.conf["guard_limits"] = {"contact": [{"kind": "ip", "window": 3600, "soft": 1, "hard": 1}]}
	run("/", form={"cmd": CONTACT})
	with pytest.raises(run.stub.ValidationError):
		trips = run("/", form={"cmd": CONTACT})
		assert trips <= 2


def test_the_settings_are_queried_twice_for_any_number_of_requests(run):
	for n in range(200):
		run("/", form={"cmd": CONTACT}, forwarded=f"198.51.100.{n % 250}")
	assert len(run.reads) == 2


def test_the_provider_is_not_asked_when_a_counter_refuses_first(run):
	run.stub.conf["guard_limits"] = {"contact": [{"kind": "ip", "window": 3600, "soft": 1, "hard": 1}]}
	run("/", form={"cmd": CONTACT})
	assert run.provider_calls == ["contact"]
	with pytest.raises(run.stub.ValidationError):
		run("/", form={"cmd": CONTACT})
	assert run.provider_calls == ["contact"]  # the second request never reached the provider
