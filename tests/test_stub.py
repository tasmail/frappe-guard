from frappe_guard.policy import Outcome
from frappe_guard.providers.base import Provider
from frappe_guard.providers.stub import StubProvider


def test_the_stub_answers_the_given_outcome_and_remembers_the_calls():
	provider: Provider = StubProvider(Outcome.LOW_SCORE, 0.2)
	verdict = provider.verify("tok", "contact", 0.5)
	assert (verdict.outcome, verdict.score) == (Outcome.LOW_SCORE, 0.2)
	assert provider.calls == [("tok", "contact", 0.5)]
