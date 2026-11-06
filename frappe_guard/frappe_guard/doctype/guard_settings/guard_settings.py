from frappe.model.document import Document


class GuardSettings(Document):
	"""Tunables of the guard (modes, thresholds). Never a secret: keys live in the site config."""
