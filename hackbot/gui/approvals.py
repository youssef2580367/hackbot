"""
GUI approval queue
==================
Bridges ToolRunner's human-only ``on_approve`` callback to the browser.

The agent runs in a worker thread. When a gate needs a human decision the
worker calls :meth:`ApprovalQueue.request`, which parks the request and
blocks until the GUI user approves/denies it via the API — or until the
timeout passes, which counts as **deny**. ``auto_confirm`` never touches
this queue.
"""

from __future__ import annotations

import itertools
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PendingApproval:
    id: int
    command: str
    reason: str
    created_at: float = field(default_factory=time.time)
    decision: Optional[bool] = None
    decided_at: Optional[float] = None
    _event: threading.Event = field(default_factory=threading.Event, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "command": self.command, "reason": self.reason,
                "created_at": self.created_at, "decision": self.decision,
                "decided_at": self.decided_at}


class ApprovalQueue:
    def __init__(self, timeout: float = 300.0, history_size: int = 100):
        self.timeout = timeout
        self._pending: Dict[int, PendingApproval] = {}
        self._history: List[PendingApproval] = []
        self._history_size = history_size
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def request(self, command: str, reason: str) -> bool:
        """Block the calling (agent) thread until a human decides."""
        item = PendingApproval(id=next(self._ids), command=command, reason=reason)
        with self._lock:
            self._pending[item.id] = item
        decided = item._event.wait(self.timeout)
        with self._lock:
            self._pending.pop(item.id, None)
            if not decided:
                item.decision = False
                item.decided_at = time.time()
            self._history.append(item)
            self._history = self._history[-self._history_size:]
        return bool(item.decision)

    def decide(self, item_id: int, approve: bool) -> bool:
        """Record a human decision. Returns False if nothing is pending."""
        with self._lock:
            item = self._pending.get(item_id)
            if item is None or item.decision is not None:
                return False
            item.decision = bool(approve)
            item.decided_at = time.time()
        item._event.set()
        return True

    def pending(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [p.to_dict() for p in self._pending.values()]

    def history(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [p.to_dict() for p in self._history]
