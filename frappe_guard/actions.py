"""Which request is which action: the requested method of a request and the map method -> action.

The requested method is read exactly as Frappe dispatches it: `cmd` of `frappe.form_dict` (query string, form or JSON, on any
path and with any HTTP method) wins over the path; only when `cmd` is empty is the path matched with the router of Frappe itself
(the mounts `/api`, `/api/v1` and `/api/v2`, non-strict slashes), so a version prefix, a trailing slash or a suffix after the
method cannot bypass the map. The name is matched as requested, before `override_whitelisted_methods`.
"""

import importlib

import frappe

# The stock endpoints. A site adds its own in `guard_action_map` of the site config ({"dotted.method": "action"}); the sites of
# FOSS use `contact`, `download` and `calculation`. `login` is not here: it is processed before the hooks (LoginManager).
DEFAULT_MAP = {
	"frappe.core.doctype.user.user.sign_up": "sign_up",
	"frappe.core.doctype.user.user.reset_password": "reset_password",
	"frappe.www.login.send_login_link": "send_login_link",
	"frappe.www.contact.send_message": "contact",
	"fossdoc_shop.downloads.request_download": "download",
	"fossdoc_shop.api.send_calculation": "calculation",
}
API_PREFIX = "/api/"
# `upload_file` is open to guests and calls the method named in its `method` field: that name is the requested method then.
# (`uploadfile`, the legacy name, never dispatches `method`: it is listed only to be conservative)
UPLOAD_METHODS = {"upload_file", "frappe.handler.upload_file", "uploadfile"}


def action_map() -> dict[str, str]:
	"""The defaults plus the site's map; an entry that is not a string pair is ignored."""
	site = frappe.conf.get("guard_action_map")
	extra = (
		{
			method: action
			for method, action in site.items()
			if isinstance(method, str) and isinstance(action, str)
		}
		if isinstance(site, dict)
		else {}
	)
	return {**DEFAULT_MAP, **extra}


def requested_method(request, form_dict, known=()) -> str | None:
	"""The dotted method that Frappe will call for this request, or None when it is not a method call."""
	cmd = form_dict.get("cmd") if isinstance(form_dict, dict) else None
	path = request.path or ""
	if cmd:
		# a non-string `cmd` fails in the handler of Frappe itself: nothing is run
		method = cmd if isinstance(cmd, str) else None
	elif path.startswith(API_PREFIX) and "/method/" in path:
		method = _routed_method(request, known)
	else:
		return None
	# `upload_file` calls the method named in its `method` field: only a request that has such a field can be one
	if isinstance(form_dict, dict) and isinstance(form_dict.get("method"), str) and _is_upload(method, known):
		return form_dict["method"]
	return method


def _is_upload(method, known) -> bool:
	"""True when `method` names `frappe.handler.upload_file`, by name or as any alias that resolves to that function."""
	if not method:
		return False
	if method in UPLOAD_METHODS:
		return True
	if method in known:
		return False
	return _resolve(method) is _handler().upload_file  # an alias such as `frappe.api.v2.upload_file`


def _handler():
	from frappe import handler

	return handler


_RESOLVED: dict[tuple[str, str], object] = {}
_RESOLVED_MAX = 2048


def _resolve(method: str):
	"""The function a requested name stands for, as `frappe.handler.get_attr` finds it, or None.

	`frappe.get_attr` is not used: on a failure it throws and leaves a message in the response of a request that Frappe
	answers fine (a dotless name such as `ping` or a server-script API). A name that resolved is remembered per site (the
	installed apps differ per site, and the workers serve all the sites of a bench); a failure is never remembered (an app
	may be installed later, an import may fail once), and the table is bounded.
	"""
	site = str(getattr(frappe.local, "site", "") or "")
	key = (site, method)
	if key in _RESOLVED:
		return _RESOLVED[key]
	try:
		if "." not in method:  # the deprecated shorthand: a name of the globals of `frappe.handler`
			found = getattr(_handler(), method, None)
		else:
			path, name = method.rsplit(".", 1)
			if path.split(".")[0] not in frappe.get_installed_apps():
				return None
			found = getattr(importlib.import_module(path), name, None)
	except Exception:  # noqa: BLE001  Frappe fails the same lookup and answers
		return None
	if found is not None:
		if len(_RESOLVED) >= _RESOLVED_MAX:
			_RESOLVED.clear()
		_RESOLVED[key] = found
	return found


def _bare_names(known) -> set[str]:
	"""The last segment of every guarded method (and of the `upload_file` names)."""
	return {name.rsplit(".", 1)[-1] for name in (*known, *UPLOAD_METHODS)}


def _v2():
	from frappe.api import v2

	return v2


def _rpc_endpoints() -> tuple:
	from frappe.api import v1

	return (v1.handle_rpc_call, _v2().handle_rpc_call)


def _routed_method(request, known=()) -> str | None:
	from frappe.api import API_URL_MAP

	try:
		endpoint, arguments = API_URL_MAP.bind_to_environ(request.environ).match()
	except Exception:  # noqa: BLE001  NotFound, MethodNotAllowed, RequestRedirect: Frappe answers these itself
		return None
	# the static v2 rule `/method/upload_file`: it calls the method of its `method` field
	if endpoint is _v2().upload_file:
		return "upload_file"
	if endpoint not in _rpc_endpoints():  # by identity: a renamed or foreign endpoint must not match by name
		return None
	method = arguments.get("method")
	if not isinstance(method, str):
		return None
	# v1: `/method/<m>/anything` still runs <m> (backward compatibility of Frappe)
	method = method.split("/")[0]
	if arguments.get("doctype"):  # v2: `/method/<doctype>/<method>` calls the method of the controller module
		# Resolving the module costs a Redis read and an unpickle: only for a name that can be a guarded method or upload_file
		if method not in _bare_names(known):
			return None
		try:
			from frappe.modules.utils import load_doctype_module

			method = f"{load_doctype_module(arguments['doctype']).__name__}.{method}"
		except Exception:  # noqa: BLE001  the same lookup fails in Frappe, which answers
			return None
	return method


def action_of(request, form_dict) -> str | None:
	"""The guarded action of a request, or None."""
	mapping = action_map()  # once per request
	method = requested_method(request, form_dict, mapping)
	return mapping.get(method) if method else None
