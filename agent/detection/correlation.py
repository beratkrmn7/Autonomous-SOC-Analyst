from typing import List, Callable, Dict, Any, TypeVar, Tuple, Deque
from collections import deque
from agent.schema import CanonicalLogEvent

T = TypeVar('T')

def sliding_window_scan(
    events: List[CanonicalLogEvent],
    window_seconds: int,
    condition_fn: Callable[[deque[CanonicalLogEvent]], Tuple[bool, Dict[str, Any]]]
) -> List[Tuple[List[CanonicalLogEvent], Dict[str, Any]]]:
    """
    O(N) sliding window across a chronologically sorted list of events.
    condition_fn takes a deque of events currently in the window, and returns
    a tuple (is_match, context_dict). If matched, the window is yielded and we clear it
    to avoid overlapping redundant matches for the exact same pattern.
    """
    results = []
    window: Deque[CanonicalLogEvent] = deque()
    
    for event in events:
        window.append(event)
        
        # Remove events outside the window
        while window and event.timestamp and window[0].timestamp and (event.timestamp - window[0].timestamp).total_seconds() > window_seconds:
            window.popleft()
            
        is_match, context = condition_fn(window)
        if is_match:
            # We found a match. 
            # We yield a copy of the window. We DO NOT clear the window because 
            # long-running patterns might need to continuously match and update
            # the last_seen time instead of resetting state and losing context.
            results.append((list(window), context))
            
    return results
