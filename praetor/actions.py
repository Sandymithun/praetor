"""Doing something about it -- carefully.

Everything before this module could only ever be *wrong*. This one can be
*destructive*. A scoring bug prints a bad number; an action bug blocks your
own DNS server and takes the company offline while nobody can log in to fix
it.

So the design is built around three rules:

  1. Scoring says an action *should* happen. This module decides whether it
     *may*. Those are different questions and they live in different files.
  2. Nothing runs unless explicitly armed. Dry-run is the permanent default,
     not a development convenience someone removes later.
  3. Nothing is ever silently dropped. A refused action produces a record
     saying what was refused and why.
"""

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Protocol, runtime_checkable

from .alert import Alert, utcnow
from .observables import Observable, ObservableType
from .scoring import RiskBand, RiskScore


class ActionType(str, Enum):
    TAG = "tag"                     # annotate the case
    NOTIFY = "notify"               # tell a human
    BLOCK_IP = "block_ip"           # firewall rule
    ISOLATE_HOST = "isolate_host"   # cut a machine off the network
    CLOSE = "close"                 # auto-resolve, no human involved


class Tier(int, Enum):
    """How much damage getting this wrong does.

    The tier, not the score, decides whether a human has to approve.
    """

    BENIGN = 0        # writing a note; wrong costs nothing
    VISIBLE = 1       # pings a human; wrong costs attention
    DISRUPTIVE = 2    # changes the network; wrong costs an outage


TIERS: dict[ActionType, Tier] = {
    ActionType.TAG: Tier.BENIGN,
    ActionType.CLOSE: Tier.BENIGN,
    ActionType.NOTIFY: Tier.VISIBLE,
    ActionType.BLOCK_IP: Tier.DISRUPTIVE,
    ActionType.ISOLATE_HOST: Tier.DISRUPTIVE,
}


@dataclass(frozen=True)
class Action:
    """Something we propose to do, and the sentence justifying it."""

    type: ActionType
    target: str
    because: str
    tier: Tier = Tier.BENIGN

    def __str__(self) -> str:
        return f"{self.type.value.upper()} {self.target}"


@dataclass
class Outcome:
    """What actually happened to a proposed action. This is the audit trail.

    Every field exists to answer a question someone asks three weeks later:
    what did it do, why, did it really run, and what did the backend say.
    """

    action: Action
    performed: bool = False
    dry_run: bool = False
    refused: str | None = None
    detail: str = ""
    at: datetime = field(default_factory=utcnow)

    @property
    def status(self) -> str:
        if self.refused:
            return "REFUSED"
        if self.dry_run:
            return "DRY RUN"
        return "DONE" if self.performed else "FAILED"

    def __str__(self) -> str:
        line = f"{self.action}  [{self.status}]"
        note = self.refused or self.detail
        return f"{line} - {note}" if note else line


# --------------------------------------------------------------------------- #
# Guards: the code that says no
# --------------------------------------------------------------------------- #

# Addresses that must never be blocked no matter what any feed claims. A
# shared CDN or a DNS resolver gets listed by somebody every week; block one
# and you have broken name resolution for the entire estate.
NEVER_BLOCK: set[str] = {
    "8.8.8.8", "8.8.4.4",          # Google DNS
    "1.1.1.1", "1.0.0.1",          # Cloudflare DNS
    "9.9.9.9",                     # Quad9
}


class Refusal(Exception):
    """A guard said no. Carries the reason, because the reason gets logged."""


def guard_block_ip(target: str, protected: set[str] | None = None) -> None:
    """Refuse to block anything that is ours, reserved, or infrastructure.

    This function is the single most important safety mechanism in the
    project. Every check below corresponds to a real way that automated
    blocking has taken a real company offline.
    """
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise Refusal(f"not an IP address: {target}") from exc

    # Order matters only for the message: loopback and link-local are also
    # "private", and a refusal that names the real reason is worth more to
    # whoever reads the audit log than one that is merely technically true.
    if target in NEVER_BLOCK or target in (protected or set()):
        raise Refusal(f"{target} is on the never-block list")
    if address.is_unspecified:
        raise Refusal(f"{target} is the unspecified address")
    if address.is_loopback:
        raise Refusal(f"{target} is loopback - that is this machine")
    if address.is_link_local:
        raise Refusal(f"{target} is link-local")
    if address.is_multicast:
        raise Refusal(f"{target} is multicast")
    if address.is_reserved:
        raise Refusal(f"{target} is reserved address space")
    if address.is_private:
        raise Refusal(f"{target} is inside our own network")
    if not address.is_global:
        raise Refusal(f"{target} is not a globally routable address")


def guard_confidence(score: RiskScore, minimum: float) -> None:
    """Never take a disruptive action on evidence we do not trust."""
    if score.partial:
        raise Refusal("evidence is incomplete - a lookup failed or was skipped")
    if score.confidence < minimum:
        raise Refusal(f"confidence {score.confidence:.0%} is below the {minimum:.0%} floor")


# --------------------------------------------------------------------------- #
# Backends: the code that does
# --------------------------------------------------------------------------- #

@runtime_checkable
class Backend(Protocol):
    """Anything that can carry out one kind of action.

    Swap `MockFirewall` for something that talks to a real appliance and
    nothing else in this file changes. That is the point of the protocol.
    """

    name: str

    def handles(self, action: Action) -> bool: ...

    def perform(self, action: Action) -> str: ...


@dataclass
class MockFirewall:
    """Records blocks instead of making them. The default, on purpose."""

    name: str = "mock-firewall"
    blocked: list[str] = field(default_factory=list)

    def handles(self, action: Action) -> bool:
        return action.type is ActionType.BLOCK_IP

    def perform(self, action: Action) -> str:
        self.blocked.append(action.target)
        return f"added deny rule for {action.target}"


@dataclass
class MockEDR:
    """Records host isolations instead of performing them.

    Isolating a machine cuts it off the network. Done to the wrong host at
    3am, the on-call engineer cannot reach the box they need to fix.
    """

    name: str = "mock-edr"
    isolated: list[str] = field(default_factory=list)

    def handles(self, action: Action) -> bool:
        return action.type is ActionType.ISOLATE_HOST

    def perform(self, action: Action) -> str:
        self.isolated.append(action.target)
        return f"isolated {action.target} from the network"


@dataclass
class ConsoleNotifier:
    """Prints where a real deployment would call Slack or PagerDuty."""

    name: str = "console"
    sent: list[str] = field(default_factory=list)

    def handles(self, action: Action) -> bool:
        return action.type in (ActionType.NOTIFY, ActionType.TAG, ActionType.CLOSE)

    def perform(self, action: Action) -> str:
        message = f"{action.type.value} -> {action.target}: {action.because}"
        self.sent.append(message)
        return message


# --------------------------------------------------------------------------- #
# The responder
# --------------------------------------------------------------------------- #

@dataclass
class Responder:
    """Plans actions from a score, guards them, then maybe performs them."""

    backends: list[Backend] = field(
        default_factory=lambda: [MockFirewall(), MockEDR(), ConsoleNotifier()]
    )

    dry_run: bool = True                  # arming this is a deliberate choice
    allow_disruptive: bool = False        # blocking/isolating needs opting in
    min_confidence: float = 0.7           # for disruptive actions only
    notify_channel: str = "#soc-alerts"
    protected: set[str] = field(default_factory=set)

    audit: list[Outcome] = field(default_factory=list)

    # ------------------------------------------------------------------ #
    # Plan
    # ------------------------------------------------------------------ #

    def plan(self, score: RiskScore) -> list[Action]:
        """Band in, proposed actions out. No side effects, easy to test.

        Notice this reads `score.band`, never `score.value`. Policy belongs
        in bands so that retuning the scorer does not silently change what
        the system *does*.
        """
        alert = score.alert
        actions: list[Action] = [
            Action(
                type=ActionType.TAG,
                target=alert.fingerprint()[:12],
                because=f"risk {score.value} ({score.band.value})",
                tier=Tier.BENIGN,
            )
        ]

        if score.band.rank >= RiskBand.MEDIUM.rank:
            actions.append(
                Action(
                    type=ActionType.NOTIFY,
                    target=self.notify_channel,
                    because=f"{alert.title} on {alert.host or 'unknown host'} "
                            f"scored {score.value}",
                    tier=Tier.VISIBLE,
                )
            )

        if score.band.rank >= RiskBand.HIGH.rank:
            for observable in self._convicted_addresses(score):
                actions.append(
                    Action(
                        type=ActionType.BLOCK_IP,
                        target=observable.value,
                        because=f"confirmed malicious in {alert.title}",
                        tier=Tier.DISRUPTIVE,
                    )
                )

        if score.band is RiskBand.CRITICAL and alert.host:
            actions.append(
                Action(
                    type=ActionType.ISOLATE_HOST,
                    target=alert.host,
                    because=f"risk {score.value}: {alert.title}",
                    tier=Tier.DISRUPTIVE,
                )
            )

        if score.auto_closable:
            actions.append(
                Action(
                    type=ActionType.CLOSE,
                    target=alert.fingerprint()[:12],
                    because=f"risk {score.value}, nothing to investigate",
                    tier=Tier.BENIGN,
                )
            )

        return actions

    @staticmethod
    def _convicted_addresses(score: RiskScore) -> list[Observable]:
        """Only block addresses a provider actually convicted.

        Not every observable on a bad alert is bad. The victim's own address
        is on that alert too, and blocking it is how you punish the person
        who got attacked.
        """
        wanted = []
        for reason in score.reasons:
            if reason.signal != "intel" or "malicious" not in reason.text:
                continue
            value = reason.text.split()[0]
            if value.startswith(("ipv4=", "ipv6=")):
                _, _, address = value.partition("=")
                wanted.append(Observable(ObservableType.IPV4, address))
        return wanted

    # ------------------------------------------------------------------ #
    # Execute
    # ------------------------------------------------------------------ #

    def execute(self, action: Action, score: RiskScore) -> Outcome:
        try:
            self._check(action, score)
        except Refusal as refusal:
            return self._record(Outcome(action=action, refused=str(refusal)))

        if self.dry_run:
            return self._record(
                Outcome(action=action, dry_run=True, detail="not performed")
            )

        backend = next((b for b in self.backends if b.handles(action)), None)
        if backend is None:
            return self._record(
                Outcome(action=action, refused=f"no backend handles {action.type.value}")
            )

        try:
            detail = backend.perform(action)
        except Exception as exc:   # a backend failure is a logged fact,
            return self._record(   # never a silent no-op
                Outcome(
                    action=action,
                    performed=False,
                    detail=f"{backend.name} raised {type(exc).__name__}: {exc}",
                )
            )

        return self._record(Outcome(action=action, performed=True, detail=detail))

    def _check(self, action: Action, score: RiskScore) -> None:
        if action.tier is Tier.DISRUPTIVE:
            if not self.allow_disruptive:
                raise Refusal("disruptive actions require --allow-disruptive")
            guard_confidence(score, self.min_confidence)
            if action.type is ActionType.BLOCK_IP:
                guard_block_ip(action.target, self.protected)

    def _record(self, outcome: Outcome) -> Outcome:
        self.audit.append(outcome)
        return outcome

    def respond(self, score: RiskScore) -> list[Outcome]:
        return [self.execute(action, score) for action in self.plan(score)]

    # ------------------------------------------------------------------ #

    def audit_summary(self) -> str:
        if not self.audit:
            return "No actions considered."
        counts: dict[str, int] = {}
        for outcome in self.audit:
            counts[outcome.status] = counts.get(outcome.status, 0) + 1
        parts = "  ".join(f"{status}={n}" for status, n in sorted(counts.items()))
        mode = "DRY RUN" if self.dry_run else "ARMED"
        return f"{len(self.audit)} action(s) considered [{mode}]  {parts}"
