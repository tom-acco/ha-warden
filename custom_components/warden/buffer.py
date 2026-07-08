"""In-memory write buffer that batches security events before persisting.

Rationale (see docs/ARCHITECTURE.md, "Write buffering"): writing one row per
event means one sqlite commit - and an fsync - per service call / state
change, and each write is its own executor job. Buffering and flushing in
batches turns that into a single commit per flush via
SecurityStorage.append_batch, which is the throughput win and takes pressure
off the shared executor pool.

The tradeoff is durability: events sitting in the buffer are lost if the
process dies before a flush. For a *security* log that is a real cost, so it
is bounded deliberately - a short time-based flush interval, an event-count
flush threshold, and a flush on unload - rather than left open-ended.
"""
from __future__ import annotations

import logging
from collections import deque
from datetime import timedelta

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval

from .storage import LogEvent, SecurityStorage

_LOGGER = logging.getLogger(__name__)


class WriteBuffer:
    """Accumulates LogEvents and flushes them in batches on whichever trigger
    fires first: the buffer reaching `max_events`, or `flush_seconds` elapsing.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        storage: SecurityStorage,
        max_events: int,
        flush_seconds: int,
    ) -> None:
        self._hass = hass
        self._storage = storage
        self._max_events = max(1, max_events)
        self._flush_seconds = max(1, flush_seconds)
        self._queue: deque[LogEvent] = deque()
        self._flush_requested = False
        self._overflow_warned = False
        self._unsub_timer = None

    def start(self) -> None:
        self._unsub_timer = async_track_time_interval(
            self._hass, self._on_timer, timedelta(seconds=self._flush_seconds)
        )

    def add(self, event: LogEvent) -> None:
        """Enqueue an event. Safe to call from the event loop or from a
        logging-handler thread (the ban-log capture): the deque append is
        atomic under the GIL, and the only loop interaction - requesting an
        early flush when the count threshold is hit - is bounced onto the loop
        via call_soon_threadsafe.
        """
        self._queue.append(event)
        depth = len(self._queue)
        if depth >= self._max_events and not self._flush_requested:
            self._flush_requested = True
            self._hass.loop.call_soon_threadsafe(self._request_flush)
        elif depth >= self._max_events * 10 and not self._overflow_warned:
            self._overflow_warned = True
            _LOGGER.warning(
                "Warden: write buffer backlog exceeded %d events; "
                "persistence is not keeping up with event volume",
                self._max_events * 10,
            )

    @callback
    def _request_flush(self) -> None:
        self._flush_requested = False
        self._hass.async_create_task(self._flush())

    async def _on_timer(self, _now) -> None:
        await self._flush()

    async def _flush(self) -> None:
        if not self._queue:
            return
        # Drain synchronously (no await) so concurrent _flush calls can't both
        # claim the same events; the executor write happens after.
        batch: list[LogEvent] = []
        while self._queue:
            batch.append(self._queue.popleft())
        try:
            await self._hass.async_add_executor_job(
                self._storage.append_batch, batch
            )
        except Exception as exc:  # noqa: BLE001 - a dropped security event must be surfaced
            _LOGGER.error(
                "Warden: failed to persist %d buffered events: %s",
                len(batch),
                exc,
            )

    async def async_shutdown(self) -> None:
        """Stop the timer and flush anything still buffered. Call on unload."""
        if self._unsub_timer is not None:
            self._unsub_timer()
            self._unsub_timer = None
        await self._flush()
