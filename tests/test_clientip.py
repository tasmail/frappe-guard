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


def test_a_chain_shorter_than_the_hops_or_no_header_gives_the_connection_address(frappe_stub):
	frappe_stub.conf["guard_trusted_hops"] = 2
	assert clientip.client_ip(req("203.0.113.7")) == "10.0.0.9"
	assert clientip.client_ip(req()) == "10.0.0.9"


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
def test_an_entry_that_is_not_an_address_falls_back_to_the_connection(frappe_stub, entry):
	assert clientip.client_ip(req(entry)) == "10.0.0.9"


def test_an_ipv6_client_is_its_64_prefix(frappe_stub):
	a = clientip.client_ip(req("2001:db8:1:2:aaaa:bbbb:cccc:dddd"))
	b = clientip.client_ip(req("2001:db8:1:2:1111:2222:3333:4444"))
	assert a == b == "2001:db8:1:2::/64"


def test_nothing_usable_is_unknown(frappe_stub):
	assert clientip.client_ip(req(None, remote="")) == clientip.UNKNOWN


def test_the_identifier_is_a_stable_hash_without_the_value():
	assert clientip.identifier("a@example.com") == clientip.identifier("a@example.com")
	assert "example" not in clientip.identifier("a@example.com") and len(clientip.identifier("x")) == 32
