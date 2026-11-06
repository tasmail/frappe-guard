"""The address of the client behind the proxies of the platform, and what a counter identifies it by.

`frappe.local.request_ip` is the left-most entry of `X-Forwarded-For` and is chosen by the client: nothing here uses it. The
address is the N-th entry from the right of the configured header, N = the number of trusted hops (`guard_trusted_hops`, which
has NO default: the real chain of the platform is read in package P4 and written to the site config by Press; until it is, every
client is unknown). The entries to the left of the trusted ones are whatever the client sent and are never read.

A request whose chain is shorter than N, or whose entry is not an address, has an UNKNOWN client: the address of the connection
is the proxy, and bucketing every client on it would lock all of them out together. The counters do not count it per
client; they count the requests of unknown clients per action (never refused), the site limit can then only raise the score (one
client must not be able to lock everyone out) and the first such request of a process is logged loudly: it means the chain is
not what the configuration says.
"""

import hashlib
import hmac
import ipaddress

import frappe

DEFAULT_HEADER = "X-Forwarded-For"
UNKNOWN = "unknown"
_warned: set[str] = set()


def _hops() -> int | None:
	"""The number of trusted proxies; None when it is not configured (the platform writes it, see package P4)."""
	value = frappe.conf.get("guard_trusted_hops")
	return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


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
		try:
			frappe.logger("frappe_guard").error("the client address cannot be told: %s", reason)
		except Exception:  # noqa: BLE001, S110  a failing logger must not become an outage of the counters
			pass


def client_ip(request) -> str:
	header = frappe.conf.get("guard_ip_header")
	header = header if isinstance(header, str) and header else DEFAULT_HEADER
	lines = request.headers.getlist(header)  # every line of the header, not only the first
	entries = [entry.strip() for line in lines for entry in line.split(",") if entry.strip()]
	hops = _hops()
	if hops is None:
		# a hard gate: with no verified chain every client would share one bucket (or be taken for someone else)
		_warn_once("guard_trusted_hops is not configured")
		return UNKNOWN
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
	if not frappe.conf.get("encryption_key"):
		_warn_once("encryption_key is not set: the hashes of the counters are not keyed")
	key = str(frappe.conf.get("encryption_key") or "") + "|frappe_guard"
	return hmac.new(key.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
