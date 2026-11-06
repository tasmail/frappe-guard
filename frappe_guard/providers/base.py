from typing import Protocol

from frappe_guard.policy import Verdict


class Provider(Protocol):
	def verify(self, token: str, expected_action: str, threshold: float) -> Verdict:
		"""Verify one token; never raise, a failure of the provider is the outcome `provider_error`."""
