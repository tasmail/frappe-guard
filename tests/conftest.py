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

	def error(self, message, *args, **kwargs):
		self.lines.append(message % args if args else message)


class _Db:
	def __init__(self):
		self.singles = {}

	def get_single_value(self, doctype, field):
		return self.singles.get((doctype, field))


def _frappe_url_map():
	"""The routing of `frappe/api/__init__.py` (v15) with the same mounts and options and stand-in endpoints."""
	from werkzeug.routing import Map, Rule, Submount

	def v1_rpc(**kw):
		return "rpc"

	def v2_rpc(**kw):
		return "rpc"

	def v2_upload(**kw):
		return "upload"

	def other(**kw):
		return "other"

	v1 = [
		Rule("/method/<path:method>", endpoint=v1_rpc),
		Rule("/resource/<doctype>", methods=["GET"], endpoint=other),
		Rule("/resource/<doctype>/<path:name>/", methods=["GET"], endpoint=other),
	]
	v2 = [
		Rule("/method/login", endpoint=other),
		Rule("/method/logout", endpoint=other),
		Rule("/method/ping", endpoint=other),
		Rule("/method/upload_file", endpoint=v2_upload),
		Rule("/method/<method>", endpoint=v2_rpc),
		Rule("/method/<doctype>/<method>", endpoint=v2_rpc),
		Rule("/document/<doctype>", methods=["GET"], endpoint=other),
	]
	url_map = Map(
		[Submount("/api", v1), Submount("/api/v1", v1), Submount("/api/v2", v2)],
		strict_slashes=False,
		merge_slashes=False,
	)
	return (
		url_map,
		types.SimpleNamespace(handle_rpc_call=v1_rpc),
		types.SimpleNamespace(handle_rpc_call=v2_rpc, upload_file=v2_upload),
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
	frappe.attrs = {}

	def get_attr(name):
		if name not in frappe.attrs:
			raise AttributeError(name)
		return frappe.attrs[name]

	frappe.get_attr = get_attr
	handler = types.ModuleType("frappe.handler")
	handler.upload_file = lambda: None
	frappe.handler = handler
	frappe.get_request_header = lambda name, default=None: frappe.headers.get(name, default)
	model = types.ModuleType("frappe.model")
	document = types.ModuleType("frappe.model.document")
	document.Document = type("Document", (), {})
	api = types.ModuleType("frappe.api")
	api.API_URL_MAP, api.v1, api.v2 = _frappe_url_map()
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
			"frappe.handler": handler,
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
	FRAPPE.attrs = {"frappe.handler.upload_file": FRAPPE.handler.upload_file}
	FRAPPE.log.lines.clear()
	return FRAPPE
