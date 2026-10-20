"""Group raw alerts into incident candidates and score them.

Alerts are grouped per source IP into sessions: an alert joins the current
incident for its source if it arrives within ``window_minutes`` of that
incident's previous alert, so the window slides forward with every new alert.
A longer gap starts a new incident.

Each incident is then scored 0-100 from how threatening the activity looks
(alert severity, volume, signature diversity) multiplied by how much the
targeted asset matters (its criticality).

Pure stdlib, so it works on ORM rows (``models.RawAlert``, ``models.Asset``) or
any other objects with the attributes in the protocols below.
"""

import math
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol


class AlertLike(Protocol):
    """The alert fields the engine needs (satisfied by ``models.RawAlert``)."""

    id: int
    src_ip: str
    dest_ip: str | None
    signature: str
    severity: int | None
    timestamp: datetime


class AssetLike(Protocol):
    """The asset fields scoring needs (satisfied by ``models.Asset``)."""

    ip: str
    criticality: int


@dataclass
class IncidentCandidate:
    """A run of alerts from one source with no gap longer than the window."""

    src_ip: str
    start_time: datetime
    end_time: datetime
    alert_ids: list[int] = field(default_factory=list)
    alerts: list[AlertLike] = field(default_factory=list, repr=False)


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
        lists its member alert ids (and alerts) in time order.

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
            current.alerts.append(alert)

    incidents.sort(key=lambda i: (i.start_time, i.src_ip))
    return incidents


# --- Scoring ---------------------------------------------------------------

# Weights of the threat factors; they sum to 1 so the threat score is 0-1.
SEVERITY_WEIGHT = 0.45
VOLUME_WEIGHT = 0.30
DIVERSITY_WEIGHT = 0.25

# Suricata severity is a priority: 1 is the most severe.
SEVERITY_FACTOR = {1: 1.0, 2: 0.7, 3: 0.4, 4: 0.2}
UNKNOWN_SEVERITY_FACTOR = 0.4

# Alert count at which the volume factor saturates (log scale below it).
VOLUME_SATURATION = 100
# Distinct signatures at which the diversity factor saturates.
DIVERSITY_SATURATION = 5

# Asset criticality multiplies the threat score. Deliberately steep: the same
# attack scores 4x higher on a criticality-5 asset than on a workstation (2).
CRITICALITY_WEIGHT = {1: 0.1, 2: 0.25, 3: 0.45, 4: 0.7, 5: 1.0}
# Targets not in the asset inventory are treated as medium criticality.
UNKNOWN_CRITICALITY = 3


def severity_factor(alerts: Iterable[AlertLike]) -> float:
    """0-1 factor for the most severe alert (Suricata severity 1 is highest)."""
    severities = [a.severity for a in alerts if a.severity is not None]
    if not severities:
        return UNKNOWN_SEVERITY_FACTOR
    return SEVERITY_FACTOR.get(min(severities), UNKNOWN_SEVERITY_FACTOR)


def volume_factor(alert_count: int) -> float:
    """0-1 factor growing logarithmically with alert count: 1 alert ~0.15, 10 ~0.5, 100+ = 1."""
    return min(1.0, math.log1p(alert_count) / math.log1p(VOLUME_SATURATION))


def diversity_factor(alerts: Iterable[AlertLike]) -> float:
    """0-1 factor for distinct signatures; varied techniques suggest a deliberate attack."""
    return min(1.0, len({a.signature for a in alerts}) / DIVERSITY_SATURATION)


def target_criticality(alerts: Iterable[AlertLike], assets: Iterable[AssetLike]) -> int:
    """Highest criticality among the incident's destination IPs.

    Destinations missing from the asset inventory count as ``UNKNOWN_CRITICALITY``.
    """
    criticality_by_ip = {asset.ip: asset.criticality for asset in assets}
    dest_ips = {a.dest_ip for a in alerts if a.dest_ip}
    if not dest_ips:
        return UNKNOWN_CRITICALITY
    return max(criticality_by_ip.get(ip, UNKNOWN_CRITICALITY) for ip in dest_ips)


def score_incident(incident: IncidentCandidate, assets: Iterable[AssetLike]) -> float:
    """Compute an incident's severity score from 0 to 100.

    The score is a threat score multiplied by the targeted asset's weight::

        threat = 0.45 * severity + 0.30 * volume + 0.25 * diversity   (each 0-1)
        score  = 100 * threat * CRITICALITY_WEIGHT[criticality]

    - severity: the most severe alert in the incident.
    - volume: number of alerts, on a log scale saturating at 100.
    - diversity: distinct signatures, saturating at 5.
    - criticality: the highest criticality among the hosts the incident
      targeted, looked up by ``dest_ip`` in ``assets``.

    Because criticality multiplies rather than adds, only a serious attack on a
    critical asset approaches 100, and a criticality-5 target scores 4x a
    workstation for the same activity.

    Args:
        incident: An incident candidate from ``group_alerts``.
        assets: Known assets, e.g. all rows of the ``assets`` table.

    Returns:
        The severity score, rounded to one decimal place.
    """
    threat = (
        SEVERITY_WEIGHT * severity_factor(incident.alerts)
        + VOLUME_WEIGHT * volume_factor(len(incident.alerts))
        + DIVERSITY_WEIGHT * diversity_factor(incident.alerts)
    )
    weight = CRITICALITY_WEIGHT.get(target_criticality(incident.alerts, assets), 1.0)
    return round(100 * threat * weight, 1)
