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
