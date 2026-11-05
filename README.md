# Python Port Scanner

A simple multithreaded TCP connect scanner. Uses only the Python standard library (Python 3.8+).

> Only scan systems you own or have explicit permission to test.
> `scanme.nmap.org` is a public host intended for practice scans.

## Usage

```bash
# Scan the default range (1-1024)
python port_scanner.py 127.0.0.1

# Specific ports and ranges
python port_scanner.py scanme.nmap.org -p 22,80,443,8000-8100

# Common ports only, with banner grabbing
python port_scanner.py 192.168.1.10 --top -b

# Faster scan with more threads and a shorter timeout, saved to JSON
python port_scanner.py 192.168.1.10 -p 1-10000 -t 200 --timeout 0.5 -o results.json
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --ports` | Ports to scan (`80`, `22,80`, `1-1024`) | `1-1024` |
| `--top` | Scan a built-in list of common ports | off |
| `-t, --threads` | Worker threads | `100` |
| `--timeout` | Per-port timeout (seconds) | `1.0` |
| `-b, --banners` | Try to grab a service banner | off |
| `-o, --output` | Save results to `.json` or `.csv` | none |

## How it works

1. `parse_ports()` turns the port spec into a sorted list.
2. The hostname is resolved to an IPv4 address.
3. A `ThreadPoolExecutor` runs `scan_port()` for each port. It calls `connect_ex()`, and a return value of `0` means the port is open.
4. For open ports, the scanner looks up the service name and optionally reads a banner.
5. Results are printed as a table and optionally saved.

## Ideas for extending it

- IPv6 and CIDR range support (e.g. `192.168.1.0/24`)
- UDP scanning
- SYN (half-open) scanning with `scapy` (requires root)
- Simple service fingerprinting from banners
- A `pytest` test suite and a `requirements.txt`
- Colored output or a progress bar using `rich`
