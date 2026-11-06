"""A micro-benchmark of the hook with a stub of Frappe (the cost of OUR Python, not of Redis or the network).

    python scripts/bench_hook.py

Prints microseconds per request for an unguarded page, an unguarded API call, a guarded guest request and a signed-in one. The
real cost adds one round trip to Redis per counter phase (see `tests/test_performance.py`: 0 for an unguarded request, 1 or 2
for a guarded one) and, for a guest, one call to the provider (not measured here).
"""

import sys
import time
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

import conftest
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from frappe_guard import check, hook
from frappe_guard.policy import Decision, Outcome

frappe = conftest.FRAPPE
frappe.local = types.SimpleNamespace(conf={}, form_dict={}, request=None, site="bench.local")
frappe.conf = frappe.local.conf
frappe.conf.update(guard_mode="enforce", guard_trusted_hops=1)
frappe.flags = types.SimpleNamespace(in_test=False)
frappe.db = conftest._Db()
frappe.cache = conftest.FakeCache()
frappe.headers = {}
check.evaluate = lambda *args, **kwargs: Decision(
	True, Outcome.PASS, 0.9, "enforce"
)  # the provider is not measured
BIG = 10**9  # no refusal: the benchmark measures the cost of a request that passes
frappe.conf["guard_limits"] = {
	action: [
		{"kind": kind, "window": 3600, "soft": BIG, "hard": BIG}
		for kind in ("ip", "account", "recipient", "site")
	]
	for action in ("sign_up", "contact")
}


def timed(label, path, form, user="Guest", n=20000):
	request = Request(EnvironBuilder(path=path, headers={"X-Forwarded-For": "203.0.113.7"}).get_environ())
	frappe.session = types.SimpleNamespace(user=user)
	start = time.perf_counter()
	for _ in range(n):
		frappe.local.request = request
		frappe.form_dict = dict(form)
		hook.guard_request()
	elapsed = (time.perf_counter() - start) / n * 1e6
	print(f"{label:55s} {elapsed:8.1f} us/request")


timed("unguarded page", "/", {})
timed("unguarded API call (router match)", "/api/method/frappe.client.get_list", {})
timed("unguarded cmd call", "/", {"cmd": "frappe.desk.form.load.getdoc"})
timed("guarded form, guest (1 counter phase)", "/", {"cmd": "frappe.www.contact.send_message"})
timed(
	"guarded sign_up, guest (2 counter phases)",
	"/",
	{"cmd": "frappe.core.doctype.user.user.sign_up", "email": "a@b.c"},
)
timed(
	"guarded sign_up, signed in",
	"/",
	{"cmd": "frappe.core.doctype.user.user.sign_up", "email": "a@b.c"},
	"u@example.com",
)
