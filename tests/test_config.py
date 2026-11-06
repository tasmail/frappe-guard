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
