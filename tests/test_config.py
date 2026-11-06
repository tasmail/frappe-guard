from frappe_guard import config
from frappe_guard.policy import ENFORCE, MONITOR


def test_the_keys_and_hosts_come_from_the_site_config(frappe_stub):
	assert (config.secret(), config.site_key(), config.hosts()) == ("", "", [])
	frappe_stub.conf.update(guard_recaptcha_secret="s", guard_recaptcha_site_key="k", guard_hosts="a.example")
	assert (config.secret(), config.site_key(), config.hosts()) == ("s", "k", ["a.example"])
	frappe_stub.conf["guard_hosts"] = ["a.example", "b.example"]
	assert config.hosts() == ["a.example", "b.example"]


def test_the_policy_layers_settings_then_site_config(frappe_stub):
	assert config.policy_for("contact").mode == MONITOR
	config.reset()  # the settings are remembered for a short time: the first read above
	frappe_stub.db.singles[("Guard Settings", "default_mode")] = "enforce"
	frappe_stub.db.singles[("Guard Settings", "action_overrides")] = '{"contact": {"threshold": 0.3}}'
	policy = config.policy_for("contact")
	assert (policy.mode, policy.threshold) == (ENFORCE, 0.3)
	frappe_stub.conf["guard_mode"] = "monitor"  # the site config wins
	frappe_stub.conf["guard_actions"] = {"contact": {"threshold": 0.6}}
	policy = config.policy_for("contact")
	assert (policy.mode, policy.threshold) == (MONITOR, 0.6)


def test_a_bad_site_mode_is_ignored(frappe_stub):
	frappe_stub.conf["guard_mode"] = "loud"
	assert config.policy_for("contact").mode == MONITOR


def test_a_malformed_site_config_is_ignored_not_a_crash(frappe_stub):
	frappe_stub.conf.update(
		guard_recaptcha_secret=5, guard_recaptcha_site_key=["k"], guard_hosts=5, guard_actions="x"
	)
	assert (config.secret(), config.site_key(), config.hosts()) == ("", "", [])
	assert config.policy_for("contact").mode == MONITOR
	frappe_stub.conf.update(guard_hosts=["a.example", 5, None], guard_actions={"*": "x", "contact": 5})
	assert config.hosts() == ["a.example"]
	assert config.policy_for("contact").mode == MONITOR


def test_guard_mode_does_not_touch_the_site_config_and_guard_actions_overrides_it(frappe_stub):
	frappe_stub.conf.update(guard_mode="enforce", guard_actions={"*": {"mode": "off"}})
	assert config.policy_for("contact").mode == "off"
	assert frappe_stub.conf["guard_actions"] == {"*": {"mode": "off"}}
	frappe_stub.conf["guard_actions"] = {"*": {"threshold": 0.7}}
	assert config.policy_for("contact").mode == ENFORCE
	assert frappe_stub.conf["guard_actions"] == {"*": {"threshold": 0.7}}


def test_an_invalid_override_is_logged_by_field_name_only(frappe_stub):
	frappe_stub.conf["guard_actions"] = {"contact": {"mode": "enfroce", "bogus": 1}}
	assert config.policy_for("contact").mode == MONITOR
	assert sorted(frappe_stub.log.lines) == [
		"ignored an invalid override: action=contact field=bogus",
		"ignored an invalid override: action=contact field=mode",
	]


def test_a_missing_doctype_or_a_database_error_leaves_the_code_defaults(frappe_stub):
	def boom(doctype, field):
		raise RuntimeError("no such doctype")

	frappe_stub.db.get_single_value = boom
	assert config.policy_for("contact").mode == MONITOR


def test_an_invalid_star_mode_does_not_shadow_guard_mode(frappe_stub):
	frappe_stub.conf.update(guard_mode="enforce", guard_actions={"*": {"mode": "bogus"}})
	assert config.policy_for("contact").mode == ENFORCE
	assert "field=mode" in frappe_stub.log.lines[0]


def test_an_invalid_guard_mode_is_logged_and_ignored(frappe_stub):
	frappe_stub.conf["guard_mode"] = "loud"
	assert config.policy_for("contact").mode == MONITOR
	assert frappe_stub.log.lines == ["ignored an invalid override: action=* field=guard_mode"]


def test_the_site_config_mode_beats_a_per_action_mode_of_guard_settings(frappe_stub):
	frappe_stub.db.singles[("Guard Settings", "action_overrides")] = '{"contact": {"mode": "off"}}'
	frappe_stub.conf["guard_mode"] = "enforce"
	assert config.policy_for("contact").mode == ENFORCE


def test_a_provider_action_override_works_with_a_star_layer(frappe_stub):
	frappe_stub.conf["guard_actions"] = {
		"*": {"threshold": 0.8},
		"contact": {"provider_action": "contact_form"},
	}
	policy = config.policy_for("contact")
	assert (policy.provider_action, policy.threshold) == ("contact_form", 0.8)


def test_the_settings_are_read_from_the_database_once_per_ttl_not_per_request(frappe_stub, monkeypatch):
	reads = []
	real = frappe_stub.db.get_single_value

	def counted(doctype, field):
		reads.append(field)
		return real(doctype, field)

	frappe_stub.db.get_single_value = counted
	for _ in range(50):
		config.policy_for("contact")
	assert reads == ["default_mode", "action_overrides"]  # two queries for fifty requests
	clock = {"t": 0.0}
	monkeypatch.setattr(config.time, "monotonic", lambda: clock["t"])
	config.reset()
	config.policy_for("contact")
	clock["t"] += config.SETTINGS_TTL + 1
	config.policy_for("contact")
	assert len(reads) == 2 + 2 + 2  # read again after the TTL


def test_a_change_of_the_settings_reaches_the_process_after_the_ttl(frappe_stub, monkeypatch):
	clock = {"t": 100.0}
	monkeypatch.setattr(config.time, "monotonic", lambda: clock["t"])
	assert config.policy_for("contact").mode == MONITOR
	frappe_stub.db.singles[("Guard Settings", "default_mode")] = "enforce"
	assert config.policy_for("contact").mode == MONITOR  # still the remembered value
	clock["t"] += config.SETTINGS_TTL + 1
	assert config.policy_for("contact").mode == ENFORCE


def test_a_transient_failure_keeps_the_last_good_settings_and_is_retried_soon(frappe_stub, monkeypatch):
	clock = {"t": 0.0}
	monkeypatch.setattr(config.time, "monotonic", lambda: clock["t"])
	frappe_stub.db.singles[("Guard Settings", "default_mode")] = "enforce"
	assert config.policy_for("contact").mode == ENFORCE
	real = frappe_stub.db.get_single_value

	def boom(doctype, field):
		raise RuntimeError("MySQL server has gone away")

	frappe_stub.db.get_single_value = boom
	clock["t"] += config.SETTINGS_TTL + 1
	assert config.policy_for("contact").mode == ENFORCE  # not silently reverted to monitor
	frappe_stub.db.get_single_value = real
	clock["t"] += config.FAILURE_TTL + 1  # retried after a few seconds, not after 30
	frappe_stub.db.singles[("Guard Settings", "default_mode")] = "off"
	assert config.policy_for("contact").mode == "off"


def test_a_failure_with_no_good_value_uses_the_code_defaults_and_retries_soon(frappe_stub, monkeypatch):
	clock = {"t": 0.0}
	monkeypatch.setattr(config.time, "monotonic", lambda: clock["t"])
	real = frappe_stub.db.get_single_value
	frappe_stub.db.get_single_value = lambda doctype, field: (_ for _ in ()).throw(RuntimeError("down"))
	assert config.policy_for("contact").mode == MONITOR
	frappe_stub.db.get_single_value = real
	frappe_stub.db.singles[("Guard Settings", "default_mode")] = "enforce"
	clock["t"] += config.FAILURE_TTL + 1
	assert config.policy_for("contact").mode == ENFORCE
