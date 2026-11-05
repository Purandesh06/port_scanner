#!/usr/bin/env python3

"""
port_scanner - A simple multithreaded TCP connect scanner.
Only scan systems you own or have explicit permission to test.
"""

from __future__ import annotations

import argparse
import csv
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080,
    8443, 9200, 27017,
]


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                raise ValueError(f"Invalid range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    if not ports:
        raise ValueError("No ports specified")
    if min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be between 1 and 65535")
    return sorted(ports)


def get_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(sock: socket.socket) -> str:
    try:
        data = sock.recv(1024)
    except socket.timeout:
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(1024)
        except (socket.timeout, OSError):
            return ""
    except OSError:
        return ""
    return data.decode(errors="replace").strip().splitlines()[0][:100] if data else ""


def scan_port(ip: str, port: int, timeout: float, banners: bool) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) != 0:
                return None
            banner = grab_banner(sock) if banners else ""
            return {"port": port, "service": get_service(port), "banner": banner}
    except OSError:
        return None


def run_scan(ip: str, ports: list[int], timeout: float, threads: int,
             banners: bool) -> list[dict]:
    results = []
    done = 0
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(scan_port, ip, p, timeout, banners) for p in ports]
        try:
            for future in as_completed(futures):
                done += 1
                result = future.result()
                if result:
                    results.append(result)
                print(f"\rProgress: {done}/{len(ports)}", end="", file=sys.stderr)
        except KeyboardInterrupt:
            print("\nInterrupted - cancelling remaining scans...", file=sys.stderr)
            for f in futures:
                f.cancel()
    print(file=sys.stderr)
    return sorted(results, key=lambda r: r["port"])


def print_table(results: list[dict]) -> None:
    if not results:
        print("No open ports found.")
        return
    print(f"\n{'PORT':<8}{'STATE':<8}{'SERVICE':<14}BANNER")
    print("-" * 60)
    for r in results:
        print(f"{r['port']:<8}{'open':<8}{r['service']:<14}{r['banner']}")


def save_results(path: str, host: str, ip: str, results: list[dict]) -> None:
    if path.endswith(".json"):
        with open(path, "w") as f:
            json.dump({"host": host, "ip": ip, "open_ports": results}, f, indent=2)
    elif path.endswith(".csv"):
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["port", "service", "banner"])
            writer.writeheader()
            writer.writerows(results)
    else:
        raise ValueError("Output file must end in .json or .csv")
    print(f"Results saved to {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple multithreaded TCP port scanner")
    parser.add_argument("target", help="Hostname or IPv4 address to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports, e.g. '80', '22,80,443', '1-1024' (default: 1-1024)")
    parser.add_argument("--top", action="store_true",
                        help="Scan a list of common ports instead of --ports")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Number of worker threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Per-port timeout in seconds (default: 1.0)")
    parser.add_argument("-b", "--banners", action="store_true",
                        help="Attempt banner grabbing on open ports")
    parser.add_argument("-o", "--output", help="Save results to a .json or .csv file")
    args = parser.parse_args()

    try:
        ports = TOP_PORTS if args.top else parse_ports(args.ports)
    except ValueError as e:
        parser.error(str(e))

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Error: could not resolve '{args.target}'", file=sys.stderr)
        return 1

    print(f"Scanning {args.target} ({ip}) - {len(ports)} ports, "
          f"{args.threads} threads, {args.timeout}s timeout")

    start = time.time()
    results = run_scan(ip, ports, args.timeout, args.threads, args.banners)
    elapsed = time.time() - start

    print_table(results)
    print(f"\nScan finished in {elapsed:.2f}s - {len(results)} open port(s)")

    if args.output:
        try:
            save_results(args.output, args.target, ip, results)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
