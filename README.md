# mptcp-scanner

Connects to TCP endpoints with `IPPROTO_MPTCP` enabled and reports, as JSONL,
whether the remote side actually spoke Multipath TCP.

## Requirements

**Must run on Linux (kernel >= 5.6, >= 5.16 recommended).** Go only implements
`IPPROTO_MPTCP` on Linux; on any other OS the dial silently falls back to plain
TCP and every target is reported as `tcp`. The scanner prints a warning on
stderr when it detects this, or when `net.mptcp.enabled=0`.

```sh
go build .                                                      # local
GOOS=linux GOARCH=amd64 go build -o mptcp-scanner-linux-amd64 . # for a Linux host
GOOS=linux GOARCH=arm64 go build -o mptcp-scanner-linux-arm64 .
```

The scanner is a single file with no dependencies outside the standard library.

## Usage

```sh
mptcp-scanner [options] [<ip|cidr|host|host:port> ...]

  -p value          port to probe; repeatable, accepts lists and ranges (default 80,443)
  -c int            number of concurrent probes (default 16)
  -t duration       per-connection timeout (default 2.5s)
  -timeout duration alias for -t (default 2.5s)
  -i string         read targets (host or host:port), one per line ("-" for stdin)
  -f string         alias for -i
  -o string         write JSONL here instead of stdout
  -max-targets int  refuse to expand more than this many unique addresses (default 1048576)
  -q                suppress warnings and the summary on stderr
```

Options must come before the targets. Targets may be IPs, CIDR blocks,
hostnames (all resolved addresses are probed), or `host:port` endpoints. Use
`[IPv6]:port` for IPv6 endpoints; bare IPv6 addresses are also accepted. A CIDR
wider than 2^20 addresses is rejected.

```sh
mptcp-scanner -p 8080 144.202.29.87
mptcp-scanner -c 16 -t 2.5s -p 8080,9090 144.202.29.87
mptcp-scanner -p 80,443 -p 8000-8010 -c 500 192.0.2.0/24
mptcp-scanner -i targets.txt -o results.jsonl
mptcp-scanner -i - -p 443 < targets.txt
```

`-i` adds file entries to any command-line targets. Use one target per line;
blank lines and lines starting with `#` are ignored. For example:

```text
144.202.29.87:8080
example.com
[::1]:9090
```

An entry with a port probes that port plus any ports explicitly given with
`-p`, with duplicates removed. For example, `-i targets.txt -p 9090` probes
ports 8080 and 9090 for `144.202.29.87:8080`, and port 9090 for `example.com`.
Without `-p`, entries with a port use only that port, while entries without a
port use the default ports 80 and 443. `-i -` reads the list from stdin.

Each resolved IP/port pair is probed only once per run, including across file
entries, command-line targets, hostnames, and overlapping CIDRs. Additional
ports for an already seen IP are still checked. IPv4 and IPv4-mapped IPv6
addresses are treated as the same IP. `-max-targets` counts unique IP addresses;
the scanner keeps a record of scheduled IPs and ports in memory.

## Output

One JSON object per line:

```json
{"timestamp":"2026-11-03T20:11:04.21Z","target":"144.202.29.87","ip":"144.202.29.87","port":8080,"status":"mptcp","mptcp":true,"connected":true,"rtt_ms":45.8}
```

`status` is one of:

| status        | meaning                                                      |
| ------------- | ------------------------------------------------------------ |
| `mptcp`       | connected and the connection is using MPTCP                   |
| `tcp`         | connected, but fell back to plain TCP (no server support)     |
| `refused`     | connection refused or reset                                   |
| `timeout`     | no answer within `-t`                                         |
| `unreachable` | host or network unreachable                                   |
| `error`       | anything else; see the `error` field                          |

`target` is the first spec that requested that IP/port pair, as written on the
command line or in the input file, including any explicit port. Command-line
targets are processed before file entries.

Filter for servers that answered `MP_CAPABLE`:

```sh
mptcp-scanner -q -p 80,443 192.0.2.0/24 | jq -c 'select(.mptcp)'
```

## How the check works

The dialer requests MPTCP; the kernel falls back to plain TCP if the peer (or a
middlebox) does not answer `MP_CAPABLE`. After connecting,
`(*net.TCPConn).MultipathTCP()` asks the kernel whether MPTCP is still in use.
On Linux >= 5.16 that also catches fallback that happened after the handshake.
