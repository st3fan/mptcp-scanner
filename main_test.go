package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

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
