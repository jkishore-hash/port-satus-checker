#!/usr/bin/env python3
"""
Port Status Checker (task2)
===========================
Checks whether a TCP port on a given host is OPEN, CLOSED or FILTERED.

How it works
------------
A TCP connection starts with a "three-way handshake" (SYN -> SYN/ACK -> ACK).
This script simply tries to complete that handshake with the target port:

  * Handshake succeeds          -> OPEN     (a service is listening)
  * Connection actively refused -> CLOSED   (host replied with RST: nothing listening)
  * No reply before timeout     -> FILTERED (a firewall is probably dropping packets)

Usage
-----
    python port_status_checker.py 80                       # checks localhost:80
    python port_status_checker.py 443 --host example.com
    python port_status_checker.py 22 -H 192.168.1.10 -t 3
    python port_status_checker.py                          # interactive prompts
    python port_status_checker.py 8000-8010 --host localhost   # a small range

Only scan systems you own or have permission to test.
Requires Python 3.8+ and no third-party packages.
"""

from __future__ import annotations

import argparse
import errno
import socket
import sys
from typing import List, Optional

# Common ports, so the output can say what service usually lives there.
COMMON_SERVICES = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP submission",
    993: "IMAPS", 995: "POP3S", 1433: "MS SQL", 1521: "Oracle DB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP alt",
    8080: "HTTP proxy/alt", 8443: "HTTPS alt", 27017: "MongoDB",
}

MAX_RANGE = 1024  # safety cap on how many ports one run may check


def check_port(host: str, port: int, timeout: float = 2.0) -> str:
    """Return 'open', 'closed', 'filtered' or 'error: <reason>' for host:port."""
    try:
        # getaddrinfo handles both IPv4 and IPv6 targets.
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return f"error: cannot resolve host ({exc.strerror})"

    last_status = "closed"
    for family, socktype, proto, _, sockaddr in infos:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex(sockaddr)
            if code == 0:
                return "open"
            if code in (errno.ECONNREFUSED, getattr(errno, "WSAECONNREFUSED", -1)):
                last_status = "closed"
            elif code in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK,
                          getattr(errno, "WSAETIMEDOUT", -1)):
                last_status = "filtered"
            elif code in (errno.EHOSTUNREACH, errno.ENETUNREACH):
                last_status = "error: host or network unreachable"
            else:
                last_status = f"error: {errno.errorcode.get(code, code)}"
        except socket.timeout:
            last_status = "filtered"
        except OSError as exc:
            last_status = f"error: {exc.strerror or exc}"
        finally:
            sock.close()
    return last_status


def validate_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise ValueError(f"'{value}' is not a number")
    if not 1 <= port <= 65535:
        raise ValueError(f"port {port} is out of range (1-65535)")
    return port


def parse_ports(spec: str) -> List[int]:
    """Accepts '80', '80,443,8080', '8000-8010', or a mix of these."""
    ports: List[int] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, hi_s = chunk.split("-", 1)
            lo, hi = validate_port(lo_s), validate_port(hi_s)
            if lo > hi:
                raise ValueError(f"invalid range {chunk}: start is greater than end")
            ports.extend(range(lo, hi + 1))
        else:
            ports.append(validate_port(chunk))
    unique = list(dict.fromkeys(ports))
    if not unique:
        raise ValueError("no ports given")
    if len(unique) > MAX_RANGE:
        raise ValueError(f"too many ports ({len(unique)}); limit is {MAX_RANGE} per run")
    return unique


def describe(status: str) -> str:
    return {
        "open": "OPEN      - a service is accepting connections",
        "closed": "CLOSED    - host is reachable but nothing is listening",
        "filtered": "FILTERED  - no response (likely blocked by a firewall)",
    }.get(status, status.upper())


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Check whether a TCP port is open or closed.")
    ap.add_argument("port", nargs="?", help="Port number, list (80,443) or range (8000-8010)")
    ap.add_argument("-H", "--host", default="127.0.0.1", help="Target host/IP (default: 127.0.0.1)")
    ap.add_argument("-t", "--timeout", type=float, default=2.0, help="Timeout in seconds (default: 2)")
    args = ap.parse_args(argv)

    # Interactive mode if no port was supplied
    if args.port is None:
        try:
            host_in = input(f"Host [{args.host}]: ").strip()
            if host_in:
                args.host = host_in
            args.port = input("Port number: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 130

    try:
        ports = parse_ports(args.port)
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    if args.timeout <= 0:
        print("Input error: timeout must be greater than 0", file=sys.stderr)
        return 2

    print(f"Checking {args.host} ...")
    open_count = 0
    had_error = False
    for port in ports:
        status = check_port(args.host, port, args.timeout)
        service = COMMON_SERVICES.get(port, "")
        label = f"{port}/tcp" + (f" ({service})" if service else "")
        print(f"  {label:<24} {describe(status)}")
        if status == "open":
            open_count += 1
        elif status.startswith("error"):
            had_error = True

    if len(ports) > 1:
        print(f"\nSummary: {open_count} open out of {len(ports)} checked.")

    if had_error:
        return 3
    return 0 if open_count else 1  # exit 0 = at least one open port


if __name__ == "__main__":
    sys.exit(main())
