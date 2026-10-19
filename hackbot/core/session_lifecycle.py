"""
HackBot session-lifecycle checks
================================
Does a credential keep working after the event that should have killed it?

HackBot never performs the lifecycle event. The flow is split so the
state change stays in the hunter's hands, on the hunter's own test account:

1. ``begin``   snapshot identity X's current credentials as ``X.before`` and
               prove they work: a GET whose response carries X's own marker.
2. (hunter)    change the password / log out / downgrade the role / disable
               the account in the app, then ``record_event``. Record the
               event itself (screenshot or request) and ``/attest`` it — the
               proof gate requires that recording for this class.
3. ``verify``  re-send the same GET with the **old** ``X.before`` credentials.
               Still 2xx with X's marker → the old session survived the event.

Probes are GET/HEAD only and go through the gated runner like every request.
"""

from __future__ import annotations

import copy
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from hackbot.core.authz_diff import SAFE_METHODS, AuthzDiff, Response, _DENIED_RE, _excerpt
from hackbot.core.corpus import Corpus, Exchange
from hackbot.core.identities import ANONYMOUS, IdentityError, IdentityVault

EVENTS = {
    "password_change": "Session not invalidated after password change",
    "logout": "Session not invalidated after logout",
    "role_downgrade": "Privileges not revoked after role downgrade",
    "account_disabled": "Session not invalidated after account disable",
    "token_revoked": "Session not invalidated after token revocation",
}


@dataclass
class SessionTest:
    identity: str
    retired: str
    exchange_id: int
    method: str
    url: str
    template: str
    command: str
    marker: str = ""
    before_step: int = 0
    before_status: int = 0
    began_at: float = 0.0
    event: str = ""
    event_note: str = ""
    event_at: float = 0.0
    after_step: int = 0
    after_status: int = 0
    after_at: float = 0.0
    verdict: str = "begun"   # begun | event_recorded | still_valid | invalidated | inconclusive
    excerpt: str = ""
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


class SessionLifecycle:
    def __init__(self) -> None:
        self.tests: Dict[str, SessionTest] = {}
        self._snapshots: Dict[str, Any] = {}

    # ── 1. begin ─────────────────────────────────────────────────────────
    def _probe(self, corpus: Corpus, vault: IdentityVault, identity: str,
               exchange_id: Optional[int]) -> Exchange:
        markers = [m for m in vault.get(identity).markers if m]
        if exchange_id is not None:
            ex = corpus.get(exchange_id)
            if ex is None:
                raise ValueError(f"no exchange #{exchange_id}")
            if ex.method not in SAFE_METHODS:
                raise ValueError("the probe must be a GET/HEAD request")
            return ex
        for ex in corpus.exchanges:
            if ex.identity == identity and ex.method == "GET" and 200 <= ex.status < 300 \
                    and any(m in ex.response_body for m in markers):
                return ex
        raise ValueError(f"no GET in the corpus where {identity}'s own markers appear — "
                         "pass an exchange # (e.g. a profile / dashboard request)")

    def begin(self, vault: IdentityVault, corpus: Corpus,
              execute: Callable[[str, str], Tuple[int, str]], identity: str,
              exchange_id: Optional[int] = None) -> SessionTest:
        if identity == ANONYMOUS or identity not in vault.identities:
            raise IdentityError(f"{identity!r} is not an authenticated test identity")
        ident = vault.get(identity)
        if not [m for m in ident.markers if m]:
            raise ValueError(f"{identity} has no markers to recognise its own data")
        ex = self._probe(corpus, vault, identity, exchange_id)
        snapshot = copy.deepcopy(ident)
        snapshot.name = f"{identity}.before"
        self._snapshots[identity] = snapshot
        vault.add_retired(snapshot)

        test = SessionTest(identity, snapshot.name, ex.id, ex.method, ex.url, ex.template,
                           AuthzDiff(corpus, vault, execute).build_command(ex, snapshot.name),
                           began_at=time.time())
        test.before_step, raw = execute(test.command,
                                        f"session begin: {identity}'s current credentials")
        resp = Response.parse(raw)
        test.before_status = resp.status
        test.marker = next((m for m in ident.markers if m and m in resp.body), "")
        if not (200 <= resp.status < 300 and test.marker):
            test.verdict = "inconclusive"
            test.detail = (f"probe as {identity} returned HTTP {resp.status} without "
                           f"{identity}'s marker — it cannot prove the session works")
        self.tests[identity] = test
        return test

    # ── 2. the hunter's event ────────────────────────────────────────────
    def record_event(self, identity: str, event: str, note: str = "") -> SessionTest:
        if event not in EVENTS:
            raise ValueError(f"event must be one of {', '.join(EVENTS)}")
        test = self.tests.get(identity)
        if test is None:
            raise ValueError(f"run begin for {identity} first")
        if test.verdict == "inconclusive":
            raise ValueError("the begin probe did not prove the session works — begin again")
        test.event, test.event_note, test.event_at = event, note, time.time()
        test.verdict = "event_recorded"
        return test

    # ── 3. verify ────────────────────────────────────────────────────────
    def verify(self, vault: IdentityVault,
               execute: Callable[[str, str], Tuple[int, str]], identity: str) -> SessionTest:
        test = self.tests.get(identity)
        if test is None or not test.event:
            raise ValueError(f"record the lifecycle event for {identity} first")
        # The vault may have been reloaded with fresh credentials since begin.
        if test.retired not in vault.retired:
            vault.add_retired(self._snapshots[identity])
        test.after_step, raw = execute(
            test.command, f"session verify: {identity}'s pre-{test.event} credentials")
        test.after_at = time.time()
        if raw.startswith("BLOCKED") or "\nBLOCKED:" in raw:
            test.verdict, test.detail = "inconclusive", raw.strip()[:300]
            return test
        resp = Response.parse(raw)
        test.after_status = resp.status
        if 200 <= resp.status < 300 and test.marker in resp.body:
            test.verdict = "still_valid"
            test.excerpt = _excerpt(resp.body, test.marker)
            test.detail = (f"old credentials still authenticated as {identity} "
                           f"{test.after_at - test.event_at:.0f}s after the {test.event}")
        elif resp.status in (401, 403, 419, 440) or 300 <= resp.status < 400 or \
                _DENIED_RE.search(resp.body[:2000]):
            test.verdict, test.detail = "invalidated", f"HTTP {resp.status} — good"
        else:
            test.verdict, test.detail = "inconclusive", f"HTTP {resp.status}, marker absent"
        return test

    # ── finding ──────────────────────────────────────────────────────────
    def finding_action(self, test: SessionTest, vault: IdentityVault) -> Optional[Dict[str, Any]]:
        if test.verdict != "still_valid" or not test.excerpt:
            return None
        label = EVENTS[test.event]
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(test.event_at))
        return {
            "action": "finding",
            "title": f"{label}: {test.identity}'s earlier token still accepted by "
                     f"{test.method} {test.template}",
            "severity": "Low",
            "vuln_class": "session management",
            "boundary_type": "session_lifecycle",
            "asset": test.url,
            "behavior": (f"{test.identity}'s credentials worked before the event (step "
                         f"{test.before_step}, HTTP {test.before_status}); the hunter recorded a "
                         f"{test.event.replace('_', ' ')} at {when}; the same credentials then "
                         f"returned HTTP {test.after_status} with {test.identity}'s marker "
                         f"(step {test.after_step})"),
            "boundary": f"session invalidation on {test.event.replace('_', ' ')}",
            "impact": (f"a token issued to {test.identity} before the "
                       f"{test.event.replace('_', ' ')} still authenticated as {test.identity} "
                       f"after it"),
            "evidence_refs": [{"step": test.after_step, "excerpt": test.excerpt,
                               "supports": "both"}],
            "reproduction": (f"1. capture a token for {test.identity}\n"
                             f"2. {test.event.replace('_', ' ')} in the application\n"
                             f"3. {test.command}"),
            "attacker_identity": test.identity,
            "privileges_required": vault.get(test.identity).role,
            "description": (f"Hunter note on the event: {test.event_note or '-'}. Attach the "
                            "recording of the event with /attest — required for confirmation."),
        }
