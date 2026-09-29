"""Shared adapter for sources that already implement ``SIEMIngestionService``.

The four cloud SIEMs (Azure Sentinel, AWS Security Hub, Microsoft Defender,
Elastic Security) all expose ``async fetch_alerts(start_time, limit)`` and
``transform_alert_to_finding(alert)`` via the
:class:`core.ingestion.siem_ingestion_service.SIEMIngestionService` base class. This
adapter wraps that contract so each concrete source needs only a one-line
factory module.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional

from core.config import is_integration_enabled
from core.federation.adapters._base import cursor_at, fresh_cursor, parse_cursor_since
from core.federation.contract import FetchResult
from core.time import utcnow

logger = logging.getLogger(__name__)

# How far past a stuck instant the cursor steps. Elastic's ``date`` fields and
# Security Hub's ``CreatedAt`` resolve to the millisecond, so a smaller step
# would round back to the same instant on their side and re-read the same page
# every tick; Defender and Sentinel compare finer than this and lose nothing
# they were not already losing at that instant.
_CURSOR_STEP = timedelta(milliseconds=1)


class SIEMIngestionAdapter:
    """Adapter wrapping any ``SIEMIngestionService`` subclass.

    The adapter is intentionally not generic over the integration_id — the
    caller passes the source name, integration id (for the ``is_configured``
    check), default interval, and a service factory. This keeps each concrete
    adapter file under 30 lines.
    """

    def __init__(
        self,
        *,
        name: str,
        integration_id: str,
        default_interval: int,
        service_factory: Callable[[], Any],
        external_id_prefix: str,
        alert_time: Optional[Callable[[Dict[str, Any]], Optional[datetime]]] = None,
        settle_delay: Optional[timedelta] = None,
    ) -> None:
        self.name = name
        self._integration_id = integration_id
        self._default_interval = default_interval
        self._service_factory = service_factory
        self._service: Optional[Any] = None
        self._external_id_prefix = external_id_prefix
        # Reads a raw alert's creation time as naive UTC. With it, a full batch
        # advances the cursor only to the newest alert returned; without it the
        # cursor goes to now, as it did before, and a full batch skips the rest
        # of its window.
        self._alert_time = alert_time
        # How long a source may take to make an alert searchable after the time
        # stamped on it (Filebeat indexing into Elastic, for one). With it, each
        # tick reads only up to now minus the delay and persists that instant,
        # so an alert stamped just before a poll but indexed just after it is
        # read by the next tick rather than skipped. The state is only the
        # persisted cursor, so it survives a restart.
        self._settle_delay = settle_delay

    def is_configured(self) -> bool:
        return is_integration_enabled(self._integration_id)

    def default_interval(self) -> int:
        return self._default_interval

    def _get_service(self):
        if self._service is not None:
            return self._service
        if not self.is_configured():
            return None
        # A configured source whose service cannot be built is failing, not
        # empty: let the error reach the runner so the cursor is kept.
        self._service = self._service_factory()
        return self._service

    async def fetch(
        self,
        *,
        since: Optional[datetime],
        cursor: Dict[str, Any],
        max_items: int,
    ) -> FetchResult:
        svc = self._get_service()
        if svc is None:
            return FetchResult(findings=[], cursor=fresh_cursor())

        start_time = parse_cursor_since(cursor) or since
        if start_time is None:
            # First run: small window so we don't backfill on enable.
            start_time = utcnow() - timedelta(minutes=1)

        # A raised fetch reaches the runner, which records the failure and keeps
        # the cursor; swallowing it here would advance the cursor past alerts
        # the source never returned.
        #
        # oldest_first: when the batch fills max_items, the alerts that do not
        # fit must be the newest ones so the next tick, starting from the newest
        # returned time, picks them up. Newest-first would drop the oldest of
        # the window for good.
        # Taken before the fetch: the cursor never moves past the "now" the
        # pre-change code would have stored, even if a source returns an alert
        # stamped ahead of our clock. With a settle delay the tick reads, and
        # the cursor stops, at now minus the delay.
        now = utcnow()
        window_end = now - self._settle_delay if self._settle_delay else None
        if window_end is not None and window_end <= start_time:
            # The cursor is already inside the settle window (it was stored as
            # now by an earlier release, or the delay was raised): nothing is
            # settled yet, so read nothing and keep the cursor where it is.
            return FetchResult(findings=[], cursor=cursor_at(start_time))

        fetch_kwargs: Dict[str, Any] = {
            "start_time": start_time,
            "limit": max_items,
            "oldest_first": True,
        }
        if window_end is not None:
            fetch_kwargs["end_time"] = window_end
        alerts = list(await svc.fetch_alerts(**fetch_kwargs) or [])
        truncated = len(alerts) >= max_items
        alerts = alerts[:max_items]

        findings = []
        for alert in alerts:
            try:
                finding = svc.transform_alert_to_finding(alert)
            except Exception as e:
                logger.debug("%s transform failed: %s", self.name, e)
                continue
            if not finding:
                continue
            # Backfill external_id from the prefix-stripped finding_id when
            # the underlying service doesn't set it explicitly. We need
            # external_id populated for the (data_source, external_id) UNIQUE
            # dedup index to do its job.
            if not finding.get("external_id"):
                fid = finding.get("finding_id", "")
                prefix = f"{self._external_id_prefix}-"
                if fid.startswith(prefix):
                    finding["external_id"] = fid[len(prefix) :]
                else:
                    finding["external_id"] = fid
            findings.append(finding)

        return FetchResult(
            findings=findings,
            cursor=self._next_cursor(
                alerts, truncated=truncated, start=start_time, now=now, end=window_end
            ),
        )

    def _next_cursor(
        self,
        alerts: list,
        *,
        truncated: bool,
        start: datetime,
        now: datetime,
        end: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Where the next tick starts.

        ``end`` is the upper bound of the window read when the adapter has a
        settle delay; it stands in for now below, so the cursor never passes an
        instant the tick did not read.

        A short batch drained its window, so the cursor moves to now. A full
        batch may have left alerts behind, so the cursor stops at the newest
        alert actually returned; the next tick re-reads that boundary alert
        (the start filters are inclusive) and the runner's dedup and the
        ``(data_source, external_id)`` unique index absorb it. The cursor is
        capped at ``now`` (taken before the fetch): only Elastic's query has an
        upper bound of its own, so an alert stamped ahead of our clock must
        not carry the cursor into the future, where later alerts with earlier
        times would be skipped.
        """
        drained = cursor_at(end) if end is not None else fresh_cursor()
        ceiling = end if end is not None else now
        if not truncated or self._alert_time is None:
            return drained

        newest: Optional[datetime] = None
        for alert in alerts:
            try:
                when = self._alert_time(alert)
            except Exception as e:  # a malformed record must not fail the poll
                logger.debug("%s: alert time unreadable: %s", self.name, e)
                when = None
            if when is not None and when.tzinfo is not None:
                when = when.astimezone(timezone.utc).replace(tzinfo=None)
            if when is not None and (newest is None or when > newest):
                newest = when

        if newest is None:
            logger.warning(
                "Federation %s: batch filled max_items=%d but no alert carried a "
                "readable time; cursor moves to now and the rest of the window "
                "is skipped",
                self.name,
                len(alerts),
            )
            return drained

        if newest > ceiling:
            logger.warning(
                "Federation %s: newest alert time %s is %s %s; capping the "
                "cursor there",
                self.name,
                newest.isoformat(),
                (
                    "ahead of this host's clock"
                    if end is None
                    else "past the settled end of the window read"
                ),
                ceiling.isoformat(),
            )
            newest = ceiling

        if newest <= start:
            # Every alert in a full batch sits at or before the tick's start.
            # Step just past that instant so the next tick cannot fetch the
            # same page forever; any alerts at the instant that did not fit
            # this batch are skipped, and the warning says so.
            logger.warning(
                "Federation %s: batch filled max_items=%d with newest alert time "
                "%s not past the tick start %s; stepping the cursor to %s. Alerts "
                "at that instant beyond this batch are skipped",
                self.name,
                len(alerts),
                newest.isoformat(),
                start.isoformat(),
                (start + _CURSOR_STEP).isoformat(),
            )
            newest = start + _CURSOR_STEP

        return cursor_at(newest)
