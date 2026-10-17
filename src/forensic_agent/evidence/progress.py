"""In-process counters for case phases; they never alter forensic decisions."""

from contextvars import ContextVar
from dataclasses import dataclass
from time import monotonic
from typing import Callable


@dataclass
class Counter:
    record: dict
    emit: Callable[[dict], None]
    started: float
    last_progress: float

    def changed(self) -> None:
        now = monotonic()
        if now - self.last_progress < 1:
            return
        self.last_progress = now
        self.record["elapsed_seconds"] = round(now - self.started, 6)
        self.emit(self.record)


_ACTIVE: ContextVar[Counter | None] = ContextVar("forensic_phase_counter", default=None)


def activate(record: dict, emit: Callable[[dict], None]):
    now = monotonic()
    return _ACTIVE.set(Counter(record=record, emit=emit, started=now, last_progress=now))


def deactivate(token) -> None:
    _ACTIVE.reset(token)


def note_hash_pass() -> None:
    active = _ACTIVE.get()
    if active is not None:
        active.record["hash_passes"] += 1
        active.changed()


def note_hash_bytes(size: int) -> None:
    active = _ACTIVE.get()
    if active is not None:
        active.record["hash_bytes"] += size
        active.changed()


def note_copy_bytes(size: int) -> None:
    active = _ACTIVE.get()
    if active is not None:
        active.record["copy_bytes"] += size
        active.changed()
