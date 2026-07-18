from agent.triage.exceptions import ProviderRateLimitError
from agent.triage.retry import with_retry


def test_retry_honors_provider_retry_after() -> None:
    sleeps: list[float] = []
    attempts = 0

    def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ProviderRateLimitError(retry_after_seconds=17.5)
        return "ok"

    result, retry_count = with_retry(operation, sleeper=sleeps.append)

    assert result == "ok"
    assert retry_count == 1
    assert sleeps == [17.5]


def test_retry_bounds_provider_retry_after() -> None:
    sleeps: list[float] = []

    def operation() -> str:
        raise ProviderRateLimitError(retry_after_seconds=600)

    try:
        with_retry(operation, max_retries=1, sleeper=sleeps.append)
    except ProviderRateLimitError:
        pass

    assert sleeps == [60.0]
