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


def _frappe_url_map():
	"""The routing of `frappe/api/__init__.py` (v15) with the same mounts and options and stand-in endpoints."""
	from werkzeug.routing import Map, Rule, Submount

	def handle_rpc_call(**kw):  # v1 and v2 name their endpoint like this
		return "rpc"

	def other(**kw):
		return "other"

	v1 = [
		Rule("/method/<path:method>", endpoint=handle_rpc_call),
		Rule("/resource/<doctype>", methods=["GET"], endpoint=other),
		Rule("/resource/<doctype>/<path:name>/", methods=["GET"], endpoint=other),
	]
	v2 = [
		Rule("/method/login", endpoint=other),
		Rule("/method/logout", endpoint=other),
		Rule("/method/ping", endpoint=other),
		Rule("/method/upload_file", endpoint=other),
		Rule("/method/<method>", endpoint=handle_rpc_call),
		Rule("/method/<doctype>/<method>", endpoint=handle_rpc_call),
		Rule("/document/<doctype>", methods=["GET"], endpoint=other),
	]
	return Map(
		[Submount("/api", v1), Submount("/api/v1", v1), Submount("/api/v2", v2)],
		strict_slashes=False,
		merge_slashes=False,
	)


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
	frappe.get_request_header = lambda name, default=None: frappe.headers.get(name, default)
	model = types.ModuleType("frappe.model")
	document = types.ModuleType("frappe.model.document")
	document.Document = type("Document", (), {})
	api = types.ModuleType("frappe.api")
	api.API_URL_MAP = _frappe_url_map()
	modules = types.ModuleType("frappe.modules")
	modules_utils = types.ModuleType("frappe.modules.utils")

	def load_doctype_module(doctype):
		if doctype not in frappe.doctype_modules:
			raise ImportError(doctype)
		return types.SimpleNamespace(__name__=frappe.doctype_modules[doctype])

	modules_utils.load_doctype_module = load_doctype_module
	sys.modules.update(
		{
			"frappe": frappe,
			"frappe.model": model,
			"frappe.model.document": document,
			"frappe.api": api,
			"frappe.modules": modules,
			"frappe.modules.utils": modules_utils,
		}
	)
	return frappe


FRAPPE = _make_frappe()


@pytest.fixture(autouse=True)
def frappe_stub():
	FRAPPE.local = types.SimpleNamespace(conf={}, form_dict={}, request=None)
	FRAPPE.conf = FRAPPE.local.conf
	FRAPPE.flags = types.SimpleNamespace(in_test=False)
	FRAPPE.db = _Db()
	FRAPPE.form_dict = {}
	FRAPPE.headers = {}
	FRAPPE.session = types.SimpleNamespace(user="Guest")
	FRAPPE.doctype_modules = {}
	FRAPPE.log.lines.clear()
	return FRAPPE
