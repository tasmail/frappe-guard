import importlib
import json
from pathlib import Path

try:
	import tomllib
except ModuleNotFoundError:  # Python 3.10
	import tomli as tomllib


ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "frappe_guard"


def test_hooks_name_the_app_and_a_hook_that_exists():
	hooks = importlib.import_module("frappe_guard.hooks")
	assert hooks.app_name == "frappe_guard"
	for path in hooks.after_install:
		module, function = path.rsplit(".", 1)
		assert callable(getattr(importlib.import_module(module), function))


def test_the_module_in_modules_txt_has_its_folder_and_doctype():
	modules = (PACKAGE / "modules.txt").read_text().splitlines()
	assert "Frappe Guard" in modules
	definition = PACKAGE / "frappe_guard" / "doctype" / "guard_settings" / "guard_settings.json"
	doctype = json.loads(definition.read_text())
	assert doctype["issingle"] == 1
	assert doctype["module"] == "Frappe Guard"
	assert {"default_mode", "action_overrides"} <= {field["fieldname"] for field in doctype["fields"]}


def test_the_doctype_class_imports_with_the_stub():
	module = importlib.import_module("frappe_guard.frappe_guard.doctype.guard_settings.guard_settings")
	assert module.GuardSettings


def test_frappe_is_a_bench_dependency_not_a_pip_one():
	project = tomllib.loads((ROOT / "pyproject.toml").read_text())
	assert project["project"]["dependencies"] == []
	assert project["tool"]["bench"]["frappe-dependencies"]["frappe"] == ">=15.0.0,<16.0.0"
	assert project["project"]["requires-python"] == ">=3.10"
