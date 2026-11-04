# mptcprobe

Connects to TCP endpoints with `IPPROTO_MPTCP` enabled and reports, as JSONL,
whether the remote side actually spoke Multipath TCP.

Repository: [st3fan/mptcprobe](https://github.com/st3fan/mptcprobe).

## Requirements

**Must run on Linux (kernel >= 5.6, >= 5.16 recommended).** Go only implements
`IPPROTO_MPTCP` on Linux; on any other OS the dial silently falls back to plain
TCP and every target is reported as `tcp`. The scanner prints a warning on
stderr when it detects this, or when `net.mptcp.enabled=0`.

Install it into `$GOBIN` (or `$GOPATH/bin`) with Go:

```sh
go install github.com/st3fan/mptcprobe@latest
```

This requires Go 1.27.1 or newer. The installed binary is named `mptcprobe`;
make sure `$GOBIN` (or `$GOPATH/bin`) is on your `PATH`.

To build from a local checkout instead:

```sh
go build -o mptcprobe .                                 # local
GOOS=linux GOARCH=amd64 go build -o mptcprobe-linux-amd64 . # for a Linux host
GOOS=linux GOARCH=arm64 go build -o mptcprobe-linux-arm64 .
```

The scanner is a single file with no dependencies outside the standard library.

## Usage

```sh
mptcprobe [options] [<ip|cidr|host|host:port> ...]

  -p value          port to probe; repeatable, accepts lists and ranges (default 80,443)
  -c int            number of concurrent probes (default 16)
  -t duration       per-connection timeout (default 2.5s)
  -timeout duration alias for -t (default 2.5s)
  -i string         read targets (host or host:port), one per line ("-" for stdin)
  -f string         alias for -i
  -o string         write JSONL here instead of stdout
  -max-targets int  refuse to expand more than this many unique addresses (default 1048576)
  -q                suppress all logging on stderr
  -only-mptcp       write only results that used MPTCP
```

Options must come before the targets. Targets may be IPs, CIDR blocks,
hostnames (all resolved addresses are probed), or `host:port` endpoints. Use
`[IPv6]:port` for IPv6 endpoints; bare IPv6 addresses are also accepted. A CIDR
wider than 2^20 addresses is rejected.

```sh
mptcprobe -p 8080 144.202.29.87
mptcprobe -c 16 -t 2.5s -p 8080,9090 144.202.29.87
mptcprobe -p 80,443 -p 8000-8010 -c 500 192.0.2.0/24
mptcprobe -i targets.txt -o results.jsonl
mptcprobe -i - -p 443 < targets.txt
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

Pipe open ports discovered by [Naabu](https://github.com/projectdiscovery/naabu)
into the scanner to check them for MPTCP support:

```sh
naabu -host 192.0.2.0/24 -p 80,443 -silent |
  ./mptcprobe -i -
```

`192.0.2.0/24` is reserved for documentation; replace it with your target network.

Each resolved IP/port pair is probed only once per run, including across file
entries, command-line targets, hostnames, and overlapping CIDRs. Additional
ports for an already seen IP are still checked. IPv4 and IPv4-mapped IPv6
addresses are treated as the same IP. `-max-targets` counts unique IP addresses;
the scanner keeps a record of scheduled IPs and ports in memory.

Logs go to stderr through Go's `log` package. Every log line starts with an
ISO 8601 timestamp with a timezone offset, using the local timezone selected
by `TZ` (for example, `TZ=America/Toronto`). JSONL result timestamps remain UTC.
At startup, a plan reports the input count, ports, concurrency, timeout,
address limit, and output destination. Input counts are target specifications,
before DNS resolution, CIDR expansion, and deduplication.

Progress is logged every 256 unique IPs with at least one completed probe.
Additional ports on the same IP do not advance the address count. Progress
and the final summary include address and probe counts, elapsed time, and all
status counts. Scans below 256 addresses log only the plan, any warnings, and
the summary. If target expansion stops early, the summary covers completed work.

Use `-q` to suppress all logging, including warnings and runtime errors, while
keeping JSONL results. Failures still exit with a nonzero status. Explicit help
and flag usage are displayed normally.

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
mptcprobe -q -p 80,443 192.0.2.0/24 | jq -c 'select(.mptcp)'
```

`-only-mptcp` applies the same filter without `jq`, writing only results whose
`status` is `mptcp`:

```sh
mptcprobe -only-mptcp -q -p 80,443 192.0.2.0/24
```

Filtering only affects which JSONL lines are written. Every probe is still
counted, so the plan, progress, and summary report the whole scan. On a host
that cannot originate MPTCP (see Requirements) this flag produces no output at
all; the warning and a summary with `mptcp=0` explain why.

## How the check works

The dialer requests MPTCP; the kernel falls back to plain TCP if the peer (or a
middlebox) does not answer `MP_CAPABLE`. After connecting,
`(*net.TCPConn).MultipathTCP()` asks the kernel whether MPTCP is still in use.
On Linux >= 5.16 that also catches fallback that happened after the handshake.
