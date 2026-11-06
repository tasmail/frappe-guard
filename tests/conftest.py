"""A stub of `frappe` for the unit tests: they run without a bench, a site or Redis.

The stub module is made once, so the modules of the app that import `frappe` keep working; the autouse fixture resets its state
for every test.
"""

import sys
import types

import pytest


class _Logger:
	def __init__(self):
		self.lines = []

	def info(self, message, *args):
		self.lines.append(message % args if args else message)


class _Db:
	def __init__(self):
		self.singles = {}

	def get_single_value(self, doctype, field):
		return self.singles.get((doctype, field))


def _make_frappe():
	frappe = types.ModuleType("frappe")
	frappe.ValidationError = type("ValidationError", (Exception,), {})
	frappe._ = lambda text: text

	def throw(message, exc=frappe.ValidationError):
		raise exc(message)

	frappe.throw = throw
	frappe.get_installed_apps = lambda: ["frappe", "frappe_guard"]
	frappe.log = _Logger()
	frappe.logger = lambda name=None: frappe.log
	model = types.ModuleType("frappe.model")
	document = types.ModuleType("frappe.model.document")
	document.Document = type("Document", (), {})
	sys.modules.update({"frappe": frappe, "frappe.model": model, "frappe.model.document": document})
	return frappe


FRAPPE = _make_frappe()


@pytest.fixture(autouse=True)
def frappe_stub():
	FRAPPE.local = types.SimpleNamespace(conf={}, form_dict={}, request=None)
	FRAPPE.conf = FRAPPE.local.conf
	FRAPPE.flags = types.SimpleNamespace(in_test=False)
	FRAPPE.db = _Db()
	FRAPPE.log.lines.clear()
	return FRAPPE
