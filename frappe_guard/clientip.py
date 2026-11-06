"""The address of the client behind the proxies of the platform, and what a counter identifies it by.

`frappe.local.request_ip` is the left-most entry of `X-Forwarded-For` and is chosen by the client: nothing here uses it. The
address is the N-th entry from the right of the configured header, N = the number of trusted hops (`guard_trusted_hops`, default
1: the nginx in front of the bench appended the client; the real chain is settled by the reads of package P4). The entries to the
left of the trusted ones are whatever the client sent and are never read.

A request whose chain is shorter than N, or whose entry is not an address, has an UNKNOWN client: the address of the connection
is the proxy, and bucketing every client on it would lock all of them out together. The counters skip an unknown address (the
site counter still protects), and the first such request of a process is logged loudly: it means the chain is not what the
configuration says.
"""

import hashlib
import hmac
import ipaddress

import frappe

DEFAULT_HEADER = "X-Forwarded-For"
DEFAULT_HOPS = 1
UNKNOWN = "unknown"
_warned: set[str] = set()


def _hops() -> int:
	value = frappe.conf.get("guard_trusted_hops")
	return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else DEFAULT_HOPS


def _strip_port(entry: str) -> str:
	entry = entry.strip()
	if entry.startswith("["):  # [::1]:443
		return entry[1:].split("]", 1)[0]
	if entry.count(":") == 1:  # 1.2.3.4:443
		return entry.split(":", 1)[0]
	return entry


def _normal(entry: str) -> str | None:
	"""A valid address; an IPv4-mapped IPv6 address is its IPv4 address, an IPv6 address stands for its /64."""
	try:
		parsed = ipaddress.ip_address(_strip_port(entry))
	except ValueError:
		return None
	if parsed.version == 6 and parsed.ipv4_mapped:
		parsed = parsed.ipv4_mapped
	if parsed.version == 6:
		return str(ipaddress.ip_network(f"{parsed}/64", strict=False).network_address) + "/64"
	return str(parsed)


def _warn_once(reason: str) -> None:
	if reason not in _warned:
		_warned.add(reason)
		frappe.logger("frappe_guard").error("the client address cannot be told: %s", reason)


def client_ip(request) -> str:
	header = frappe.conf.get("guard_ip_header")
	header = header if isinstance(header, str) and header else DEFAULT_HEADER
	lines = request.headers.getlist(header)  # every line of the header, not only the first
	entries = [entry.strip() for line in lines for entry in line.split(",") if entry.strip()]
	hops = _hops()
	if len(entries) < hops:
		_warn_once(f"{header} has {len(entries)} entries, {hops} trusted hops are configured")
		return UNKNOWN
	address = _normal(entries[-hops])
	if not address:
		_warn_once(f"the trusted entry of {header} is not an address")
		return UNKNOWN
	return address


def identifier(value: str) -> str:
	"""What a counter key holds: a keyed hash (the site's encryption key), so no address or e-mail is readable in Redis."""
	key = str(frappe.conf.get("encryption_key") or "") + "|frappe_guard"
	return hmac.new(key.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
