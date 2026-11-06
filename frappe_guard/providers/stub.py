from frappe_guard.policy import Outcome, Verdict


class StubProvider:
	"""A provider for tests: answers the given outcome and remembers what it was asked."""

	def __init__(self, outcome: Outcome = Outcome.PASS, score: float | None = 0.9):
		self.outcome = outcome
		self.score = score
		self.calls = []

	def verify(self, token: str, expected_action: str, threshold: float) -> Verdict:
		self.calls.append((token, expected_action, threshold))
		return Verdict(self.outcome, self.score)
