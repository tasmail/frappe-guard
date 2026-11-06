import pytest
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from frappe_guard import clientip


def req(forwarded=None, remote="10.0.0.9", **headers):
	builder = EnvironBuilder(headers=headers, environ_base={"REMOTE_ADDR": remote})
	if forwarded is not None:
		builder.headers["X-Forwarded-For"] = forwarded
	return Request(builder.get_environ())


def test_one_trusted_hop_takes_the_last_entry_and_ignores_what_the_client_put_on_the_left(frappe_stub):
	assert clientip.client_ip(req("6.6.6.6, 1.1.1.1, 203.0.113.7")) == "203.0.113.7"
	assert clientip.client_ip(req("203.0.113.7")) == "203.0.113.7"


def test_two_trusted_hops_take_the_second_entry_from_the_right(frappe_stub):
	frappe_stub.conf["guard_trusted_hops"] = 2
	assert clientip.client_ip(req("6.6.6.6, 203.0.113.7, 10.1.1.1")) == "203.0.113.7"


def test_a_forged_left_entry_changes_nothing(frappe_stub):
	frappe_stub.conf["guard_trusted_hops"] = 2
	assert clientip.client_ip(req("203.0.113.7, 10.1.1.1")) == clientip.client_ip(
		req("9.9.9.9, 203.0.113.7, 10.1.1.1")
	)


def test_a_chain_shorter_than_the_hops_or_no_header_is_unknown_not_the_proxy_address(frappe_stub):
	frappe_stub.conf["guard_trusted_hops"] = 2
	assert clientip.client_ip(req("203.0.113.7")) == clientip.UNKNOWN
	assert clientip.client_ip(req()) == clientip.UNKNOWN


@pytest.mark.parametrize("value", [0, -1, True, "2", None, 1.5])
def test_an_invalid_hop_count_is_one(frappe_stub, value):
	frappe_stub.conf["guard_trusted_hops"] = value
	assert clientip.client_ip(req("6.6.6.6, 203.0.113.7")) == "203.0.113.7"


def test_the_header_name_is_configurable(frappe_stub):
	frappe_stub.conf["guard_ip_header"] = "X-Real-Client"
	assert clientip.client_ip(req(None, **{"X-Real-Client": "203.0.113.7"})) == "203.0.113.7"
	frappe_stub.conf["guard_ip_header"] = 5
	assert clientip.client_ip(req("203.0.113.7")) == "203.0.113.7"


@pytest.mark.parametrize("entry", ["not an ip", "", "999.1.1.1", "1.1.1"])
def test_an_entry_that_is_not_an_address_is_unknown(frappe_stub, entry):
	assert clientip.client_ip(req(entry)) == clientip.UNKNOWN


def test_an_ipv6_client_is_its_64_prefix(frappe_stub):
	a = clientip.client_ip(req("2001:db8:1:2:aaaa:bbbb:cccc:dddd"))
	b = clientip.client_ip(req("2001:db8:1:2:1111:2222:3333:4444"))
	assert a == b == "2001:db8:1:2::/64"


def test_the_first_unknown_client_of_a_process_is_logged_loudly_once(frappe_stub):
	clientip._warned.clear()
	clientip.client_ip(req())
	clientip.client_ip(req())
	assert len(frappe_stub.log.lines) == 1 and "cannot be told" in frappe_stub.log.lines[0]


def test_every_line_of_a_repeated_header_is_read(frappe_stub):
	builder = EnvironBuilder(environ_base={"REMOTE_ADDR": "10.0.0.9"})
	builder.headers.add("X-Forwarded-For", "6.6.6.6")
	builder.headers.add("X-Forwarded-For", "203.0.113.7")
	assert clientip.client_ip(Request(builder.get_environ())) == "203.0.113.7"  # the last line is the proxy's


@pytest.mark.parametrize(
	("entry", "expected"),
	[
		("::ffff:1.2.3.4", "1.2.3.4"),
		("::ffff:5.6.7.8", "5.6.7.8"),  # mapped addresses are their IPv4 address, not one shared /64
		("1.2.3.4:443", "1.2.3.4"),
		("[2001:db8:1:2::5]:443", "2001:db8:1:2::/64"),
	],
)
def test_mapped_addresses_and_ports(frappe_stub, entry, expected):
	assert clientip.client_ip(req(entry)) == expected


def test_the_identifier_is_a_keyed_hash_without_the_value(frappe_stub):
	assert clientip.identifier("a@example.com") == clientip.identifier("a@example.com")
	assert "example" not in clientip.identifier("a@example.com") and len(clientip.identifier("x")) == 32
	unkeyed = clientip.identifier("1.2.3.4")
	frappe_stub.conf["encryption_key"] = "site-secret"
	assert (
		clientip.identifier("1.2.3.4") != unkeyed
	)  # a dictionary of addresses does not reverse it without the key
