"""Group raw alerts into incident candidates.

Alerts are grouped per source IP into sessions: an alert joins the current
incident for its source if it arrives within ``window_minutes`` of that
incident's previous alert, so the window slides forward with every new alert.
A longer gap starts a new incident. Pure stdlib, so it works on ORM rows or any
other objects with ``id``, ``src_ip`` and ``timestamp`` attributes.
"""

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol


class AlertLike(Protocol):
    """The alert fields grouping needs (satisfied by ``models.RawAlert``)."""

    id: int
    src_ip: str
    timestamp: datetime


@dataclass
class IncidentCandidate:
    """A run of alerts from one source with no gap longer than the window."""

    src_ip: str
    start_time: datetime
    end_time: datetime
    alert_ids: list[int] = field(default_factory=list)


def group_alerts(alerts: Iterable[AlertLike], window_minutes: float = 10) -> list[IncidentCandidate]:
    """Group alerts by ``src_ip`` into incident candidates.

    Within each source, alerts are ordered by timestamp (then id, for ties). An
    alert belongs to the same incident as the previous one when the gap between
    them is at most ``window_minutes``; otherwise it starts a new incident. A
    steady trickle of alerts therefore forms one long incident, however long
    it lasts in total.

    Args:
        alerts: Alerts to group, in any order. Timestamps must be all
            timezone-aware or all naive, so they can be compared.
        window_minutes: Maximum gap between consecutive alerts of one incident.

    Returns:
        Incident candidates ordered by ``start_time``, then ``src_ip``. Each
        lists its member alert ids in time order.

    Raises:
        ValueError: If ``window_minutes`` is not positive.
    """
    if window_minutes <= 0:
        raise ValueError("window_minutes must be positive")
    window = timedelta(minutes=window_minutes)

    by_source: dict[str, list[AlertLike]] = defaultdict(list)
    for alert in alerts:
        by_source[alert.src_ip].append(alert)

    incidents: list[IncidentCandidate] = []
    for src_ip, source_alerts in by_source.items():
        source_alerts.sort(key=lambda a: (a.timestamp, a.id))
        current: IncidentCandidate | None = None
        for alert in source_alerts:
            if current is None or alert.timestamp - current.end_time > window:
                current = IncidentCandidate(src_ip, alert.timestamp, alert.timestamp)
                incidents.append(current)
            current.end_time = alert.timestamp
            current.alert_ids.append(alert.id)

    incidents.sort(key=lambda i: (i.start_time, i.src_ip))
    return incidents
