# AGENTS.md

Notes for the next session. See `README.md` for user-facing usage.

## What this is

`mptcpain` probes a list of TCP endpoints with `IPPROTO_MPTCP` requested
and reports, as JSONL, whether each server actually spoke Multipath TCP. The
point is reconnaissance: finding out which hosts on a network support MPTCP.

Whole program is `main.go`. Standard library only, no dependencies. Regression
tests for target input and expansion are in `main_test.go`.

## The one constraint that governs everything

**Go implements `IPPROTO_MPTCP` only on Linux.** On every other OS,
`net/mptcpsock_stub.go` makes `dialMPTCP` a plain `dialTCP`, and
`isUsingMultipathTCP` returns a hardcoded `false`. So:

- A scan run on macOS reports `"status":"tcp"` for **every** target,
  regardless of what the server supports. Such a run is meaningless — do not
  draw conclusions from it, and say so plainly if asked to.
- The development machine here is darwin/arm64. Real runs happen on a Linux
  box the user copies the binary to.
- `localMPTCPWarning()` prints the caveat to stderr (non-Linux, or
  `net.mptcp.enabled=0`, or the sysctl missing). Keep that warning working;
  it is the main guard against misreading results.

Kernel floor is 5.6 for MPTCP at all; on >= 5.16 `(*net.TCPConn).MultipathTCP()`
additionally detects fallback that happened after the handshake, so below 5.16
a `true` can be a false positive.

## Status

The user confirmed MPTCP detection works on Linux. The test host is
144.202.29.87: port 8080 uses an `IPPROTO_MPTCP` socket, while port 9090 uses
plain TCP.

The repository is https://github.com/st3fan/mptcpain. The Go module is
`github.com/st3fan/mptcpain`, and the executable is `mptcpain`. Cross-compiled
binaries are named `mptcpain-linux-amd64` / `mptcpain-linux-arm64`.
`.gitignore` covers only `/mptcpain`; cross-compiled binaries are not ignored.

## Design decisions already made

- **One detection method.** `net.Dialer.SetMultipathTCP(true)`, dial, then
  `(*net.TCPConn).MultipathTCP()`. No raw sockets, no packet crafting.
- **Targets stream.** `expand()` sends jobs into a channel rather than building
  a slice. It retains resolved IP/port pairs in memory for deduplication. A
  prefix with more than 2^20 hosts is refused outright; `-max-targets` caps the
  total unique IP addresses.
- **One writer goroutine** owns the encoder so JSONL lines never interleave.
  Workers send `result` values to it over a channel.
- **Flags must precede targets.** Go's `flag` stops at the first positional, so
  a trailing `-p 443` would otherwise be DNS-resolved as a hostname.
  `expand()` rejects any target starting with `-` with a pointed error.
- **`status` is a closed set**: `mptcp`, `tcp`, `refused`, `timeout`,
  `unreachable`, `error`. `classify()` maps errno values onto it. Adding a
  value means updating the README table and the summary line in `main()`.
- **`target` preserves the first spec requesting each IP/port pair** (the CIDR,
  hostname, or endpoint as typed) next to the resolved `ip`, so results trace
  back to their input.

## Working on it

```sh
go build -o mptcpain . && go test -race ./... && go vet ./... && gofmt -l .
GOOS=linux GOARCH=amd64 go build -o mptcpain-linux-amd64 .
```

Quick local smoke test (expect all `tcp`/`refused`/`timeout` on macOS):

```sh
./mptcpain -timeout 3s -p 80,443 1.1.1.1 example.com 127.0.0.1/30
```

## Ideas not yet pursued

- Automated MPTCP detection tests. An `httptest`-style listener with
  `net.ListenConfig`'s `SetMultipathTCP(true)` would give a real positive case,
  but only on Linux — it would need a build tag and CI that runs there.
- Reporting MPTCP version or subflow details from `MPTCP_INFO` (Go does not
  expose it; would need a raw `getsockopt`).
- Progress output for large scans; retries; rate limiting.
