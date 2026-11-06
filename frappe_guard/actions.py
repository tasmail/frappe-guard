"""Which request is which action: the requested method of a request and the map method -> action.

The requested method is read exactly as Frappe dispatches it: `cmd` of `frappe.form_dict` (query string, form or JSON, on any
path and with any HTTP method) wins over the path; only when `cmd` is empty is the path matched with the router of Frappe itself
(the mounts `/api`, `/api/v1` and `/api/v2`, non-strict slashes), so a version prefix, a trailing slash or a suffix after the
method cannot bypass the map. The name is matched as requested, before `override_whitelisted_methods`.
"""

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
RPC_ENDPOINT = "handle_rpc_call"


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


def requested_method(request, form_dict) -> str | None:
	"""The dotted method that Frappe will call for this request, or None when it is not a method call."""
	cmd = form_dict.get("cmd") if isinstance(form_dict, dict) else None
	if cmd:
		return (
			cmd if isinstance(cmd, str) else None
		)  # a non-string `cmd` fails in the handler of Frappe itself
	if not (request.path or "").startswith(API_PREFIX):
		return None
	return _routed_method(request)


def _routed_method(request) -> str | None:
	from frappe.api import API_URL_MAP

	try:
		endpoint, arguments = API_URL_MAP.bind_to_environ(request.environ).match()
	except Exception:  # noqa: BLE001  NotFound, MethodNotAllowed, RequestRedirect: Frappe answers these itself
		return None
	if getattr(endpoint, "__name__", "") != RPC_ENDPOINT:
		return None
	method = arguments.get("method")
	if not isinstance(method, str):
		return None
	method = method.split("/")[
		0
	]  # v1: `/method/<m>/anything` still runs <m> (backward compatibility of Frappe)
	if arguments.get("doctype"):  # v2: `/method/<doctype>/<method>` calls the method of the controller module
		try:
			from frappe.modules.utils import load_doctype_module

			method = f"{load_doctype_module(arguments['doctype']).__name__}.{method}"
		except Exception:  # noqa: BLE001  the same lookup fails in Frappe, which answers
			return None
	return method


def action_of(request, form_dict) -> str | None:
	"""The guarded action of a request, or None."""
	method = requested_method(request, form_dict)
	return action_map().get(method) if method else None
