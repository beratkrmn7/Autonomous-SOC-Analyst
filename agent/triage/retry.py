import time
from typing import Callable, Any
from agent.triage.exceptions import ProviderRateLimitError, ProviderTimeoutError, ProviderUnavailableError

def with_retry(
    func: Callable,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 10.0,
    sleeper: Callable[[float], None] = time.sleep
) -> Any:
    attempt = 0
    while True:
        try:
            return func(), attempt
        except (ProviderRateLimitError, ProviderTimeoutError, ProviderUnavailableError) as e:
            attempt += 1
            if attempt > max_retries:
                raise e
            
            delay = min(base_delay * (2 ** (attempt - 1)), max_delay)
            if isinstance(e, ProviderRateLimitError) and e.retry_after_seconds is not None:
                # Provider guidance is the earliest safe retry time. Bound it so
                # a malformed response cannot block a worker indefinitely.
                delay = max(delay, min(max(e.retry_after_seconds, 0.0), 60.0))
            sleeper(delay)
