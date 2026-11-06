"""A stub of `frappe` for the unit tests: they run without a bench, a site or Redis."""

import sys
import types

import pytest


@pytest.fixture(autouse=True)
def frappe_stub(monkeypatch):
	frappe = types.ModuleType("frappe")
	frappe.local = types.SimpleNamespace(conf={}, form_dict={}, request=None)
	frappe.conf = frappe.local.conf
	frappe.get_installed_apps = lambda: ["frappe", "frappe_guard"]
	frappe.ValidationError = type("ValidationError", (Exception,), {})

	def throw(message, exc=frappe.ValidationError):
		raise exc(message)

	frappe.throw = throw
	model = types.ModuleType("frappe.model")
	document = types.ModuleType("frappe.model.document")
	document.Document = type("Document", (), {})
	monkeypatch.setitem(sys.modules, "frappe", frappe)
	monkeypatch.setitem(sys.modules, "frappe.model", model)
	monkeypatch.setitem(sys.modules, "frappe.model.document", document)
	return frappe
