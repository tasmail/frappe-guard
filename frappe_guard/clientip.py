"""The address of the client behind the proxies of the platform, and what a counter identifies it by.

`frappe.local.request_ip` is the left-most entry of `X-Forwarded-For` and is chosen by the client: nothing here uses it. The
address is the N-th entry from the right of the configured header, N = the number of trusted hops (`guard_trusted_hops`, default
1: the nginx in front of the bench appended the client). The entries to the left of the trusted ones are whatever the client
sent and are never read. A request that did not come through a proxy chain of that length has the address of the connection.
"""

import hashlib
import ipaddress

import frappe

DEFAULT_HEADER = "X-Forwarded-For"
DEFAULT_HOPS = 1
UNKNOWN = "unknown"


def _hops() -> int:
	value = frappe.conf.get("guard_trusted_hops")
	return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else DEFAULT_HOPS


def _normal(address: str) -> str | None:
	"""A valid address; an IPv6 address stands for its /64 (a client rotates the rest at will)."""
	try:
		parsed = ipaddress.ip_address(address.strip())
	except ValueError:
		return None
	if parsed.version == 6:
		return str(ipaddress.ip_network(f"{parsed}/64", strict=False).network_address) + "/64"
	return str(parsed)


def client_ip(request) -> str:
	header = frappe.conf.get("guard_ip_header")
	header = header if isinstance(header, str) and header else DEFAULT_HEADER
	entries = [entry.strip() for entry in (request.headers.get(header) or "").split(",") if entry.strip()]
	hops = _hops()
	if len(entries) >= hops:
		address = _normal(entries[-hops])
		if address:
			return address
	return _normal(request.remote_addr or "") or UNKNOWN


def identifier(value: str) -> str:
	"""What a counter key holds: a hash, so no address or e-mail is readable in Redis."""
	return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
