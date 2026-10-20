"""Tail Suricata's eve.json and forward alert events to POST /alerts.

The read offset is stored in the ingest_state table and only advanced after an
alert has been accepted, so restarts (including uvicorn --reload) resume where
they left off. If the file is replaced or truncated, reading starts over.
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Any

import httpx

from ..db import SessionLocal
from ..models import IngestState

log = logging.getLogger(__name__)

EVE_LOG_PATH = os.environ.get("EVE_LOG_PATH", "/logs/eve.json")
ALERTS_API_URL = os.environ.get("ALERTS_API_URL", "http://127.0.0.1:8000/alerts")
POLL_INTERVAL = float(os.environ.get("EVE_POLL_INTERVAL", "1.0"))


def parse_eve_timestamp(value: str) -> datetime:
    # Suricata writes e.g. 2023-11-14T22:13:20.000000+0000
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")


def to_alert_payload(event: dict[str, Any]) -> dict[str, Any] | None:
    """Map an eve.json event to the raw_alerts schema, or None if it isn't an alert."""
    if event.get("event_type") != "alert":
        return None
    alert = event.get("alert", {})
    return {
        "src_ip": event["src_ip"],
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "signature": alert.get("signature", ""),
        "category": alert.get("category"),
        "severity": alert.get("severity"),
        "timestamp": parse_eve_timestamp(event["timestamp"]).isoformat(),
        "raw_json": event,
    }


def load_offset(path: str, inode: int, size: int) -> int:
    with SessionLocal() as db:
        state = db.get(IngestState, path)
        if state is None or state.inode != inode or state.offset > size:
            return 0
        return state.offset


def save_offset(path: str, inode: int, offset: int) -> None:
    with SessionLocal() as db:
        db.merge(IngestState(path=path, inode=inode, offset=offset))
        db.commit()


async def post_alert(client: httpx.AsyncClient, payload: dict[str, Any]) -> None:
    """POST one alert, retrying until the API accepts it (e.g. while the server starts)."""
    delay = 1.0
    while True:
        try:
            resp = await client.post(ALERTS_API_URL, json=payload)
            if resp.status_code < 500:
                if resp.is_error:
                    # A 4xx won't succeed on retry; log and drop it.
                    log.warning("Alert rejected (%s): %s", resp.status_code, resp.text)
                return
            log.warning("Alert POST failed with %s, retrying", resp.status_code)
        except httpx.TransportError as exc:
            log.debug("Alert POST failed (%s), retrying", exc)
        await asyncio.sleep(delay)
        delay = min(delay * 2, 30.0)


async def process_new_lines(client: httpx.AsyncClient, path: str) -> None:
    stat = os.stat(path)
    offset = await asyncio.to_thread(load_offset, path, stat.st_ino, stat.st_size)
    if offset == stat.st_size:
        return

    with open(path, "rb") as f:
        f.seek(offset)
        for line in f:
            if not line.endswith(b"\n"):
                break  # partial line still being written; pick it up next poll
            offset += len(line)
            try:
                payload = to_alert_payload(json.loads(line))
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                log.warning("Skipping unparseable eve.json line: %s", exc)
                payload = None
            if payload is not None:
                await post_alert(client, payload)
                await asyncio.to_thread(save_offset, path, stat.st_ino, offset)

    await asyncio.to_thread(save_offset, path, stat.st_ino, offset)


async def watch_eve_log(path: str = EVE_LOG_PATH) -> None:
    log.info("Watching %s for Suricata alerts", path)
    async with httpx.AsyncClient(timeout=10.0) as client:
        while True:
            try:
                if os.path.exists(path):
                    await process_new_lines(client, path)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("eve.json watcher error")
            await asyncio.sleep(POLL_INTERVAL)
