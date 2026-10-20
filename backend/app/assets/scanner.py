"""Discover hosts on a subnet with nmap and upsert them into the assets table."""

import ipaddress
import os
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from ..models import Asset

SCAN_SUBNET = os.environ.get("SCAN_SUBNET", "")
SCAN_TOP_PORTS = int(os.environ.get("SCAN_TOP_PORTS", "100"))
SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "600"))
# Refuse very large ranges: an IPv4 /20 is 4096 addresses.
MAX_SCAN_ADDRESSES = 4096
NMAP_SERVICES_FILE = "/usr/share/nmap/nmap-services"

# First matching rule wins: (role, criticality, ports that indicate it).
ROLE_RULES: list[tuple[str, int, set[int]]] = [
    ("domain_controller", 5, {88, 389, 636, 3268}),
    ("database", 5, {1433, 1521, 3306, 5432, 6379, 27017}),
    ("web_server", 4, {80, 443, 8000, 8080, 8443}),
    ("server", 3, {22, 3389}),
    ("printer", 1, {515, 631, 9100}),
]
DEFAULT_ROLE = ("workstation", 2)


class ScanError(Exception):
    pass


@dataclass
class OpenPort:
    port: int
    protocol: str
    service: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass
class ScannedHost:
    ip: str
    hostname: str | None = None
    mac: str | None = None
    open_ports: list[OpenPort] = field(default_factory=list)
    role: str = DEFAULT_ROLE[0]
    criticality: int = DEFAULT_ROLE[1]

    def to_dict(self) -> dict:
        return asdict(self)


def validate_subnet(subnet: str) -> str:
    try:
        network = ipaddress.ip_network(subnet.strip(), strict=False)
    except ValueError as exc:
        raise ScanError(f"Invalid subnet {subnet!r}: {exc}") from exc
    if network.num_addresses > MAX_SCAN_ADDRESSES:
        raise ScanError(f"Subnet {network} is too large (max {MAX_SCAN_ADDRESSES} addresses)")
    return str(network)


def infer_role(ports: list[OpenPort]) -> tuple[str, int]:
    open_tcp = {p.port for p in ports if p.protocol == "tcp"}
    for role, criticality, indicators in ROLE_RULES:
        if open_tcp & indicators:
            return role, criticality
    return DEFAULT_ROLE


def top_tcp_ports(n: int) -> list[int]:
    """The n most common TCP ports according to nmap's frequency table."""
    ranked = []
    try:
        with open(NMAP_SERVICES_FILE) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and not line.startswith("#") and parts[1].endswith("/tcp"):
                    ranked.append((float(parts[2]), int(parts[1].split("/")[0])))
    except OSError:
        return []
    ranked.sort(reverse=True)
    return [port for _, port in ranked[:n]]


def scan_ports() -> str:
    """Top-N common ports plus every port the role rules look for.

    Some role ports (e.g. Redis 6379, MongoDB 27017) are rare enough that they
    fall outside nmap's top 1000, so --top-ports alone would miss them.
    """
    ports = set(top_tcp_ports(SCAN_TOP_PORTS))
    for _, _, indicators in ROLE_RULES:
        ports |= indicators
    return ",".join(str(p) for p in sorted(ports))


def run_nmap(subnet: str) -> str:
    cmd = [
        "nmap", "-oX", "-", "-T4",
        "-sV", "--version-light",
        "-p", scan_ports(),
        subnet,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT, check=False)
    except FileNotFoundError as exc:
        raise ScanError("nmap is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"nmap timed out after {SCAN_TIMEOUT}s") from exc
    if result.returncode != 0:
        raise ScanError(f"nmap failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def parse_nmap_xml(xml_output: str) -> list[ScannedHost]:
    hosts = []
    for host_el in ET.fromstring(xml_output).iter("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

        host = ScannedHost(ip="")
        for addr in host_el.iter("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                host.ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                host.mac = addr.get("addr")
        if not host.ip:
            continue

        hostname_el = host_el.find("hostnames/hostname")
        if hostname_el is not None:
            host.hostname = hostname_el.get("name")

        for port_el in host_el.iter("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port_el.find("service")
            host.open_ports.append(
                OpenPort(
                    port=int(port_el.get("portid", 0)),
                    protocol=port_el.get("protocol", "tcp"),
                    service=service.get("name") if service is not None else None,
                    product=service.get("product") if service is not None else None,
                    version=service.get("version") if service is not None else None,
                )
            )

        host.role, host.criticality = infer_role(host.open_ports)
        hosts.append(host)
    return hosts


def upsert_assets(db: Session, hosts: list[ScannedHost]) -> None:
    """Insert new hosts; for known IPs refresh role/criticality/last_seen and keep
    previously known hostname/mac if this scan didn't see one."""
    if not hosts:
        return
    stmt = insert(Asset).values(
        [
            {"ip": h.ip, "hostname": h.hostname, "mac": h.mac, "role": h.role, "criticality": h.criticality}
            for h in hosts
        ]
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[Asset.ip],
        set_={
            "hostname": func.coalesce(stmt.excluded.hostname, Asset.hostname),
            "mac": func.coalesce(stmt.excluded.mac, Asset.mac),
            "role": stmt.excluded.role,
            "criticality": stmt.excluded.criticality,
            "last_seen": func.now(),
        },
    )
    db.execute(stmt)
    db.commit()


def scan_subnet(db: Session, subnet: str | None = None) -> tuple[str, list[ScannedHost]]:
    target = subnet or SCAN_SUBNET
    if not target:
        raise ScanError("No subnet given and SCAN_SUBNET is not set")
    target = validate_subnet(target)
    hosts = parse_nmap_xml(run_nmap(target))
    upsert_assets(db, hosts)
    return target, hosts
