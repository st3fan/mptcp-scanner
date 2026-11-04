// mptcp-scanner connects to TCP endpoints with MPTCP (IPPROTO_MPTCP) enabled
// and reports, as JSONL, whether the remote side actually spoke Multipath TCP.
//
// Targets may be IP addresses, CIDR blocks, hostnames or host:port endpoints.
// Explicit endpoint ports are probed in addition to any requested ports;
// targets without a port default to 80 and 443 when no ports are requested.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type result struct {
	Timestamp string  `json:"timestamp"`
	Target    string  `json:"target"`
	IP        string  `json:"ip"`
	Port      int     `json:"port"`
	Status    string  `json:"status"`
	MPTCP     bool    `json:"mptcp"`
	Connected bool    `json:"connected"`
	RTTms     float64 `json:"rtt_ms"`
	Error     string  `json:"error,omitempty"`
}

// job is a single IP/port probe. spec is the target as the user wrote it,
// which differs from ip when the target was a hostname or a CIDR.
type job struct {
	spec string
	ip   netip.Addr
	port int
}

type portList []int

func (p *portList) String() string { return fmt.Sprint(*p) }

func (p *portList) Set(v string) error {
	ports, err := parsePorts(v)
	if err != nil {
		return err
	}
	*p = append(*p, ports...)
	return nil
}

// parsePorts accepts "443", "80,443" and ranges such as "8000-8010".
func parsePorts(v string) ([]int, error) {
	var out []int
	for _, field := range strings.Split(v, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(field, "-")
		first, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", field)
		}
		last := first
		if isRange {
			last, err = strconv.Atoi(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q", field)
			}
		}
		if first < 1 || first > 65535 || last < 1 || last > 65535 || last < first {
			return nil, fmt.Errorf("port out of range: %q", field)
		}
		for p := first; p <= last; p++ {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports in %q", v)
	}
	return out, nil
}

func dedupePorts(ports []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, p := range ports {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

func main() {
	var ports portList
	flag.Var(&ports, "p", "port to probe; repeatable, accepts lists and ranges (default 80,443)")
	concurrency := flag.Int("c", 16, "number of concurrent probes")
	timeout := flag.Duration("t", 2500*time.Millisecond, "per-connection timeout")
	flag.DurationVar(timeout, "timeout", 2500*time.Millisecond, "alias for -t")
	outPath := flag.String("o", "", "write JSONL here instead of stdout")
	targetsFile := flag.String("i", "", "read targets (host or host:port), one per line (\"-\" for stdin)")
	flag.StringVar(targetsFile, "f", "", "alias for -i")
	maxTargets := flag.Int("max-targets", 1<<20, "refuse to expand more than this many addresses (0 = no limit)")
	quiet := flag.Bool("q", false, "suppress warnings and the summary on stderr")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [options] [<ip|cidr|host|host:port> ...]\n\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nOutput is one JSON object per line:\n")
		fmt.Fprintf(os.Stderr, "  status is one of mptcp, tcp, refused, timeout, unreachable, error\n")
	}
	flag.Parse()

	ports = dedupePorts(ports)

	specs := flag.Args()
	if *targetsFile != "" {
		extra, err := readTargets(*targetsFile)
		if err != nil {
			fatal("reading targets: %v", err)
		}
		specs = append(specs, extra...)
	}
	if len(specs) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if *concurrency < 1 {
		fatal("-c must be at least 1")
	}

	if !*quiet {
		if warning := localMPTCPWarning(); warning != "" {
			fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
		}
	}

	out := io.Writer(os.Stdout)
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fatal("%v", err)
		}
		defer f.Close()
		out = f
	}
	w := bufio.NewWriter(out)
	defer w.Flush()
	enc := json.NewEncoder(w)

	jobs := make(chan job)
	results := make(chan result)

	var wg sync.WaitGroup
	for range *concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results <- probe(j, *timeout)
			}
		}()
	}

	// A single writer owns the output, so lines never interleave.
	writerDone := make(chan struct{})
	counts := map[string]int{}
	go func() {
		defer close(writerDone)
		for r := range results {
			counts[r.Status]++
			if err := enc.Encode(r); err != nil {
				fatal("writing output: %v", err)
			}
		}
	}()

	expandErr := expand(specs, ports, *maxTargets, *quiet, jobs)
	close(jobs)
	wg.Wait()
	close(results)
	<-writerDone
	w.Flush()

	if expandErr != nil {
		fatal("%v", expandErr)
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "summary: mptcp=%d tcp=%d refused=%d timeout=%d unreachable=%d error=%d\n",
			counts["mptcp"], counts["tcp"], counts["refused"], counts["timeout"],
			counts["unreachable"], counts["error"])
	}
}

// probe dials one endpoint with MPTCP requested and reports what came back.
func probe(j job, timeout time.Duration) result {
	r := result{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Target:    j.spec,
		IP:        j.ip.String(),
		Port:      j.port,
	}

	var d net.Dialer
	d.Timeout = timeout
	d.SetMultipathTCP(true)

	addr := netip.AddrPortFrom(j.ip, uint16(j.port)).String()
	start := time.Now()
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	r.RTTms = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		r.Status = classify(err)
		r.Error = err.Error()
		return r
	}
	defer conn.Close()

	r.Connected = true
	// MultipathTCP() reports whether the connection is still using MPTCP: the
	// kernel falls back to plain TCP when the peer (or a middlebox) does not
	// support it. On Linux >= 5.16 the check also catches post-handshake
	// fallback.
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		r.Status = "error"
		r.Error = "connection is not a TCP connection"
		return r
	}
	mptcp, err := tc.MultipathTCP()
	if err != nil {
		r.Status = "error"
		r.Error = err.Error()
		return r
	}
	r.MPTCP = mptcp
	if mptcp {
		r.Status = "mptcp"
	} else {
		r.Status = "tcp"
	}
	return r
}

func classify(err error) string {
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return "timeout"
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNRESET):
		return "refused"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.EHOSTDOWN), errors.Is(err, syscall.ENETDOWN):
		return "unreachable"
	}
	return "error"
}

// parseTarget combines an endpoint's port with explicitly requested ports.
// Only targets without either kind of port use the default ports.
func parseTarget(spec string, ports []int) (string, []int, error) {
	host := spec
	if _, err := netip.ParseAddr(spec); err != nil && strings.ContainsAny(spec, ":[]") && !strings.Contains(spec, "/") {
		var portText string
		host, portText, err = net.SplitHostPort(spec)
		if err != nil {
			return "", nil, fmt.Errorf("invalid endpoint %q: %v", spec, err)
		}
		if host == "" {
			return "", nil, fmt.Errorf("invalid endpoint %q: host is required", spec)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return "", nil, fmt.Errorf("invalid endpoint %q: port must be a number between 1 and 65535", spec)
		}
		// Copy before appending so one endpoint's port cannot affect another.
		ports = dedupePorts(append(append([]int(nil), ports...), port))
	}
	if len(ports) == 0 {
		ports = []int{80, 443}
	}
	return host, ports, nil
}

// expand turns the target specs into jobs, streaming them so that large CIDRs
// do not have to be held in memory.
func expand(specs []string, ports []int, maxTargets int, quiet bool, jobs chan<- job) error {
	emitted := 0
	emit := func(spec string, ip netip.Addr, ports []int) error {
		if maxTargets > 0 && emitted >= maxTargets {
			return fmt.Errorf("target limit of %d addresses reached (raise -max-targets)", maxTargets)
		}
		emitted++
		for _, p := range ports {
			jobs <- job{spec: spec, ip: ip, port: p}
		}
		return nil
	}

	for _, spec := range specs {
		if strings.HasPrefix(spec, "-") && spec != "-" {
			return fmt.Errorf("%q looks like a flag: options must come before the targets", spec)
		}
		host, targetPorts, err := parseTarget(spec, ports)
		if err != nil {
			return err
		}
		switch {
		case strings.Contains(host, "/"):
			prefix, err := netip.ParsePrefix(host)
			if err != nil {
				return fmt.Errorf("invalid CIDR %q: %v", spec, err)
			}
			prefix = prefix.Masked()
			hostBits := prefix.Addr().BitLen() - prefix.Bits()
			if hostBits > 20 {
				return fmt.Errorf("%s covers 2^%d addresses, refusing to scan it", spec, hostBits)
			}
			for ip := prefix.Addr(); prefix.Contains(ip); ip = ip.Next() {
				if err := emit(spec, ip, targetPorts); err != nil {
					return err
				}
			}
		default:
			if ip, err := netip.ParseAddr(host); err == nil {
				if err := emit(spec, ip.Unmap(), targetPorts); err != nil {
					return err
				}
				continue
			}
			ips, err := net.LookupIP(host)
			if err != nil {
				if !quiet {
					fmt.Fprintf(os.Stderr, "warning: cannot resolve %q: %v\n", spec, err)
				}
				continue
			}
			for _, raw := range ips {
				ip, ok := netip.AddrFromSlice(raw)
				if !ok {
					continue
				}
				if err := emit(spec, ip.Unmap(), targetPorts); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func readTargets(path string) ([]string, error) {
	f := os.Stdin
	if path != "-" {
		var err error
		f, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
	}
	var out []string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, s.Err()
}

// localMPTCPWarning reports why this host cannot originate MPTCP connections,
// which would make every probe come back as plain tcp.
func localMPTCPWarning() string {
	if runtime.GOOS != "linux" {
		return fmt.Sprintf("Go only implements IPPROTO_MPTCP on Linux; on %s every connection falls back to plain TCP and will be reported as tcp", runtime.GOOS)
	}
	b, err := os.ReadFile("/proc/sys/net/mptcp/enabled")
	if err != nil {
		return "cannot read /proc/sys/net/mptcp/enabled; this kernel may not support MPTCP (needs Linux >= 5.6)"
	}
	if strings.TrimSpace(string(b)) == "0" {
		return "MPTCP is disabled locally (net.mptcp.enabled=0); enable it with: sysctl -w net.mptcp.enabled=1"
	}
	return ""
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "mptcp-scanner: "+format+"\n", args...)
	os.Exit(1)
}
