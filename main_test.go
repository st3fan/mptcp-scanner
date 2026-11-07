package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProbeWithRetries(t *testing.T) {
	for _, tt := range []struct {
		name     string
		retries  int
		statuses []string
	}{
		{"disabled", 0, []string{"timeout"}},
		{"exhausted", 3, []string{"timeout", "timeout", "timeout", "timeout"}},
		{"one retry", 1, []string{"timeout", "timeout"}},
		{"success after timeout", 3, []string{"timeout", "mptcp"}},
		{"success on last retry", 3, []string{"timeout", "timeout", "timeout", "tcp"}},
		{"immediate success", 3, []string{"tcp"}},
		{"refused", 3, []string{"refused"}},
		{"unreachable", 3, []string{"unreachable"}},
		{"error", 3, []string{"error"}},
		{"refused after timeout", 3, []string{"timeout", "refused"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			j := job{"example.com:443", netip.MustParseAddr("192.0.2.1"), 443}
			calls := 0
			var last result
			got := probeWithRetries(j, time.Second, tt.retries, func(gotJob job, timeout time.Duration) result {
				if gotJob != j || timeout != time.Second {
					t.Fatalf("attempt got job=%v timeout=%v", gotJob, timeout)
				}
				if calls >= len(tt.statuses) {
					t.Fatal("unexpected extra attempt")
				}
				status := tt.statuses[calls]
				calls++
				last = result{
					Timestamp: fmt.Sprint(calls), Target: j.spec, IP: j.ip.String(), Port: j.port,
					Status: status, MPTCP: status == "mptcp", Connected: status == "mptcp" || status == "tcp",
					RTTms: float64(calls),
				}
				if !last.Connected {
					last.Error = status
				}
				return last
			})
			if calls != len(tt.statuses) || got != last {
				t.Fatalf("got %d attempts and %+v, want %d attempts and %+v", calls, got, len(tt.statuses), last)
			}
		})
	}
}

func TestCLIRetries(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"default", nil, "retries=3"},
		{"disabled", []string{"-r", "0"}, "retries=0"},
		{"custom", []string{"-r", "5"}, "retries=5"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := append(tt.args, "-p", "1", "-t", "1ms", "127.0.0.1")
			stdout, stderr, err := runCLI(t, "UTC", "", args...)
			if err != nil || !strings.Contains(stderr, tt.want) || strings.Count(stdout, "\n") != 1 {
				t.Fatalf("unexpected CLI result: stdout=%q stderr=%q error=%v", stdout, stderr, err)
			}
		})
	}
	for _, quiet := range []bool{false, true} {
		args := []string{"-r", "-1", "127.0.0.1"}
		if quiet {
			args = append([]string{"-q"}, args...)
		}
		stdout, stderr, err := runCLI(t, "UTC", "", args...)
		if err == nil || stdout != "" {
			t.Fatalf("expected negative retry count to fail: stdout=%q error=%v", stdout, err)
		}
		if quiet && stderr != "" || !quiet && !strings.Contains(stderr, "-r must be at least 0") {
			t.Fatalf("unexpected validation log (quiet=%v): %q", quiet, stderr)
		}
	}
}

func TestParseTarget(t *testing.T) {
	for _, tt := range []struct {
		name  string
		spec  string
		ports []int
		host  string
		want  []int
	}{
		{"hostname defaults", "example.com", nil, "example.com", []int{80, 443}},
		{"hostname endpoint", "example.com:8080", nil, "example.com", []int{8080}},
		{"additive ports", "example.com:8080", []int{443, 9090}, "example.com", []int{443, 8080, 9090}},
		{"duplicate port", "example.com:8080", []int{8080}, "example.com", []int{8080}},
		{"bare IPv6", "2001:db8::1", nil, "2001:db8::1", []int{80, 443}},
		{"IPv6 endpoint", "[2001:db8::1]:9090", []int{443}, "2001:db8::1", []int{443, 9090}},
		{"IPv6 zone", "[fe80::1%eth0]:8080", nil, "fe80::1%eth0", []int{8080}},
		{"IPv6 CIDR", "2001:db8::/126", nil, "2001:db8::/126", []int{80, 443}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			host, ports, err := parseTarget(tt.spec, tt.ports)
			if err != nil {
				t.Fatal(err)
			}
			if host != tt.host || !reflect.DeepEqual(ports, tt.want) {
				t.Fatalf("got (%q, %v), want (%q, %v)", host, ports, tt.host, tt.want)
			}
		})
	}
}

func TestParseTargetRejectsInvalidEndpoints(t *testing.T) {
	for _, spec := range []string{
		"example.com:", "example.com:http", "example.com:0",
		"example.com:-1", "example.com:65536", "example.com:80,443",
		":8080", "[::1]", "[::1:8080", "[::1]:8080:9090",
	} {
		t.Run(spec, func(t *testing.T) {
			if _, _, err := parseTarget(spec, nil); err == nil {
				t.Fatalf("accepted invalid endpoint %q", spec)
			}
		})
	}
}

func collectJobs(specs []string, ports []int, maxTargets int) ([]job, error) {
	jobs := make(chan job)
	done := make(chan error, 1)
	go func() {
		done <- expand(specs, ports, maxTargets, true, jobs)
		close(jobs)
	}()
	var out []job
	for j := range jobs {
		out = append(out, j)
	}
	return out, <-done
}

func TestExpandEndpointPortsStayWithTheirTarget(t *testing.T) {
	// Extra capacity catches accidental mutation when endpoint ports are appended.
	ports := make([]int, 1, 8)
	ports[0] = 443
	got, err := collectJobs([]string{"192.0.2.1:8080", "[::1]:9090", "192.0.2.2/31"}, ports, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []job{
		{"192.0.2.1:8080", netip.MustParseAddr("192.0.2.1"), 443},
		{"192.0.2.1:8080", netip.MustParseAddr("192.0.2.1"), 8080},
		{"[::1]:9090", netip.MustParseAddr("::1"), 443},
		{"[::1]:9090", netip.MustParseAddr("::1"), 9090},
		{"192.0.2.2/31", netip.MustParseAddr("192.0.2.2"), 443},
		{"192.0.2.2/31", netip.MustParseAddr("192.0.2.3"), 443},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExpandMixedDefaults(t *testing.T) {
	got, err := collectJobs([]string{"192.0.2.1:8080", "192.0.2.2"}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []job{
		{"192.0.2.1:8080", netip.MustParseAddr("192.0.2.1"), 8080},
		{"192.0.2.2", netip.MustParseAddr("192.0.2.2"), 80},
		{"192.0.2.2", netip.MustParseAddr("192.0.2.2"), 443},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExpandEndpointTargetLimit(t *testing.T) {
	got, err := collectJobs([]string{"192.0.2.1:8080", "192.0.2.2:9090"}, []int{443}, 1)
	if err == nil || !strings.Contains(err.Error(), "target limit") {
		t.Fatalf("expected target limit error, got %v", err)
	}
	if len(got) != 2 || got[0].port != 443 || got[1].port != 8080 {
		t.Fatalf("expected both ports for the first address, got %v", got)
	}
}

func TestExpandDeduplicatesEndpoints(t *testing.T) {
	for _, tt := range []struct {
		name  string
		specs []string
		ports []int
		want  []job
	}{
		{
			name:  "repeated targets with additional ports",
			specs: []string{"192.0.2.1:8080", "192.0.2.1:8080", "192.0.2.1", "192.0.2.1:9090"},
			ports: []int{443},
			want: []job{
				{"192.0.2.1:8080", netip.MustParseAddr("192.0.2.1"), 443},
				{"192.0.2.1:8080", netip.MustParseAddr("192.0.2.1"), 8080},
				{"192.0.2.1:9090", netip.MustParseAddr("192.0.2.1"), 9090},
			},
		},
		{
			name:  "endpoint and bare target defaults",
			specs: []string{"192.0.2.1:8080", "192.0.2.1", "192.0.2.1:443"},
			want: []job{
				{"192.0.2.1:8080", netip.MustParseAddr("192.0.2.1"), 8080},
				{"192.0.2.1", netip.MustParseAddr("192.0.2.1"), 80},
				{"192.0.2.1", netip.MustParseAddr("192.0.2.1"), 443},
			},
		},
		{
			name:  "overlapping CIDRs and individual IPs",
			specs: []string{"192.0.2.0/31", "192.0.2.1", "192.0.2.0/30"},
			ports: []int{443},
			want: []job{
				{"192.0.2.0/31", netip.MustParseAddr("192.0.2.0"), 443},
				{"192.0.2.0/31", netip.MustParseAddr("192.0.2.1"), 443},
				{"192.0.2.0/30", netip.MustParseAddr("192.0.2.2"), 443},
				{"192.0.2.0/30", netip.MustParseAddr("192.0.2.3"), 443},
			},
		},
		{
			name:  "equivalent IPv6 spellings",
			specs: []string{"2001:db8::1", "2001:0db8:0:0:0:0:0:1", "[2001:db8::1]:8080"},
			ports: []int{443},
			want: []job{
				{"2001:db8::1", netip.MustParseAddr("2001:db8::1"), 443},
				{"[2001:db8::1]:8080", netip.MustParseAddr("2001:db8::1"), 8080},
			},
		},
		{
			name:  "IPv4-mapped IPv6 including CIDRs",
			specs: []string{"192.0.2.1:8080", "[::ffff:192.0.2.1]:8080", "::ffff:192.0.2.1/128"},
			ports: []int{8080},
			want: []job{
				{"192.0.2.1:8080", netip.MustParseAddr("192.0.2.1"), 8080},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := collectJobs(tt.specs, tt.ports, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExpandDuplicatesDoNotExhaustTargetLimit(t *testing.T) {
	got, err := collectJobs([]string{"192.0.2.1:8080", "192.0.2.1:8080", "192.0.2.1:9090", "192.0.2.1/32"}, []int{443}, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []job{
		{"192.0.2.1:8080", netip.MustParseAddr("192.0.2.1"), 443},
		{"192.0.2.1:8080", netip.MustParseAddr("192.0.2.1"), 8080},
		{"192.0.2.1:9090", netip.MustParseAddr("192.0.2.1"), 9090},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestReadTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("# targets\r\n 192.0.2.1:8080 \r\n\n example.com\n [::1]:9090"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readTargets(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1:8080", "example.com", "[::1]:9090"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestTimestampWriterPrefixesEveryLine(t *testing.T) {
	var out bytes.Buffer
	logger := log.New(timestampWriter{out: &out}, "", 0)
	logger.Print("first line\nsecond line")
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two log lines, got %q", out.String())
	}
	for i, line := range lines {
		stamp, message, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("missing timestamp in %q", line)
		}
		if _, err := time.Parse(time.RFC3339, stamp); err != nil {
			t.Fatalf("invalid ISO timestamp %q: %v", stamp, err)
		}
		if want := []string{"first line", "second line"}[i]; message != want {
			t.Fatalf("got message %q, want %q", message, want)
		}
	}
}

func TestEmitResultOnlyMPTCP(t *testing.T) {
	for _, tt := range []struct {
		status    string
		onlyMPTCP bool
		want      bool
	}{
		{"mptcp", true, true},
		{"tcp", true, false},
		{"refused", true, false},
		{"timeout", true, false},
		{"unreachable", true, false},
		{"error", true, false},
		{"tcp", false, true},
		{"refused", false, true},
	} {
		if got := emitResult(result{Status: tt.status}, tt.onlyMPTCP); got != tt.want {
			t.Errorf("emitResult(status=%q, onlyMPTCP=%v) = %v, want %v", tt.status, tt.onlyMPTCP, got, tt.want)
		}
	}
}

func TestScanStatsProgressCountsUniqueAddresses(t *testing.T) {
	stats := newScanStats()
	for i := 0; i < 512; i++ {
		ip := netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)}).String()
		if got, want := stats.record(result{IP: ip, Port: 80, Status: "tcp"}), (i+1)%256 == 0; got != want {
			t.Fatalf("address %d: progress=%v, want %v", i+1, got, want)
		}
		if stats.record(result{IP: ip, Port: 443, Status: "mptcp"}) {
			t.Fatalf("additional port advanced progress at address %d", i+1)
		}
	}
	if len(stats.addresses) != 512 || stats.probes != 1024 || stats.counts["tcp"] != 512 || stats.counts["mptcp"] != 512 {
		t.Fatalf("incorrect totals: %+v", stats)
	}
	var out bytes.Buffer
	stats.report(log.New(&out, "", 0), "summary")
	for _, want := range []string{"summary: addresses=512 probes=1024 elapsed=", "mptcp=512 tcp=512 refused=0 timeout=0 unreachable=0 error=0"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in summary %q", want, out.String())
		}
	}
}

// Run the real CLI in a subprocess so flag parsing, os.Exit, and TZ are isolated.
func TestCLIHelperProcess(t *testing.T) {
	if os.Getenv("MPTCPROBE_CLI_HELPER") != "1" {
		return
	}
	os.Args = append([]string{"mptcprobe"}, flag.Args()...)
	flag.CommandLine = flag.NewFlagSet("mptcprobe", flag.ExitOnError)
	main()
	os.Exit(0)
}

func runCLI(t *testing.T, timezone, input string, args ...string) (string, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestCLIHelperProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "MPTCPROBE_CLI_HELPER=1", "TZ="+timezone)
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("CLI timed out: %s", stderr.String())
	}
	return stdout.String(), stderr.String(), err
}

func TestCLILoggingRespectsTimezone(t *testing.T) {
	for _, timezone := range []string{"UTC", "America/Toronto"} {
		t.Run(timezone, func(t *testing.T) {
			location, err := time.LoadLocation(timezone)
			if err != nil {
				t.Fatal(err)
			}
			stdout, stderr, err := runCLI(t, timezone, "", "-t", "1ms", "-p", "1", "127.0.0.1")
			if err != nil {
				t.Fatalf("CLI failed: %v: %s", err, stderr)
			}
			lines := strings.Split(strings.TrimSpace(stderr), "\n")
			if !strings.Contains(lines[0], " plan: inputs=1 ") || !strings.Contains(lines[len(lines)-1], " summary: addresses=1 probes=1 ") {
				t.Fatalf("missing plan/summary: %s", stderr)
			}
			for _, want := range []string{"ports=\"[1] plus per-target ports\"", "concurrency=16", "timeout=1ms", "max_addresses=1048576", "output=\"stdout\""} {
				if !strings.Contains(lines[0], want) {
					t.Fatalf("missing %q in plan: %s", want, lines[0])
				}
			}
			for _, line := range lines {
				stamp, _, _ := strings.Cut(line, " ")
				parsed, err := time.Parse(time.RFC3339, stamp)
				if err != nil {
					t.Fatalf("invalid log timestamp %q: %v", stamp, err)
				}
				_, got := parsed.Zone()
				if _, want := parsed.In(location).Zone(); got != want {
					t.Fatalf("timestamp %q has offset %d, want %d", stamp, got, want)
				}
			}
			var r result
			if err := json.Unmarshal([]byte(stdout), &r); err != nil {
				t.Fatalf("invalid JSONL result: %v: %s", err, stdout)
			}
			if !strings.HasSuffix(r.Timestamp, "Z") {
				t.Fatalf("JSON timestamp should remain UTC: %q", r.Timestamp)
			}
			if strings.Contains(stderr, " progress:") {
				t.Fatalf("unexpected progress for small scan: %s", stderr)
			}
		})
	}
}

func TestCLIProgressAndQuiet(t *testing.T) {
	input := "127.0.0.0/23\n127.0.0.1:3\n127.0.0.1:3\n"
	for _, quiet := range []bool{false, true} {
		t.Run(fmt.Sprintf("quiet=%v", quiet), func(t *testing.T) {
			args := []string{"-i", "-", "-p", "1,2", "-t", "1ms"}
			if quiet {
				args = append(args, "-q")
			}
			stdout, stderr, err := runCLI(t, "UTC", input, args...)
			if err != nil {
				t.Fatalf("CLI failed: %v: %s", err, stderr)
			}
			if got := len(strings.Split(strings.TrimSpace(stdout), "\n")); got != 1025 {
				t.Fatalf("got %d results, want 1025", got)
			}
			if quiet {
				if stderr != "" {
					t.Fatalf("quiet scan logged: %s", stderr)
				}
				return
			}
			if strings.Count(stderr, " progress:") != 2 {
				t.Fatalf("expected two progress messages: %s", stderr)
			}
			for _, want := range []string{"progress: addresses=256 ", "progress: addresses=512 ", "summary: addresses=512 probes=1025 "} {
				if !strings.Contains(stderr, want) {
					t.Fatalf("missing %q in logs: %s", want, stderr)
				}
			}
		})
	}
}

func TestCLIQuietRuntimeError(t *testing.T) {
	stdout, stderr, err := runCLI(t, "UTC", "", "-q", "-c", "0", "127.0.0.1")
	if err == nil || stdout != "" || stderr != "" {
		t.Fatalf("expected silent failure, got stdout=%q stderr=%q error=%v", stdout, stderr, err)
	}
}

func TestCLIExpansionErrorStillSummarizes(t *testing.T) {
	stdout, stderr, err := runCLI(t, "UTC", "", "-max-targets", "1", "-p", "1", "-t", "1ms", "127.0.0.1", "127.0.0.2")
	if err == nil {
		t.Fatal("expected target limit failure")
	}
	if got := strings.Count(stdout, "\n"); got != 1 {
		t.Fatalf("expected one result, got %d: %s", got, stdout)
	}
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	if !strings.Contains(stderr, "error: mptcprobe: target limit") || !strings.Contains(lines[len(lines)-1], "summary: addresses=1 probes=1 ") {
		t.Fatalf("expected error followed by a final partial summary: %s", stderr)
	}
}

func TestCLIOnlyMPTCPFiltersOutputButKeepsSummary(t *testing.T) {
	args := []string{"-p", "1", "-t", "1ms", "127.0.0.1"}
	all, stderr, err := runCLI(t, "UTC", "", args...)
	if err != nil {
		t.Fatalf("CLI failed: %v: %s", err, stderr)
	}
	if strings.Contains(all, `"mptcp":true`) {
		t.Skipf("loopback answered with MPTCP; cannot test filtering: %s", all)
	}
	filtered, stderr, err := runCLI(t, "UTC", "", append([]string{"-only-mptcp"}, args...)...)
	if err != nil {
		t.Fatalf("CLI failed: %v: %s", err, stderr)
	}
	if filtered != "" {
		t.Fatalf("expected no JSONL with -only-mptcp, got %q", filtered)
	}
	if !strings.Contains(stderr, "summary: addresses=1 probes=1 ") {
		t.Fatalf("filtered scan should still summarize the whole scan: %s", stderr)
	}
}
