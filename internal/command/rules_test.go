package command

import (
	"bytes"
	"context"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func TestParseNetworkRule(t *testing.T) {
	for _, tc := range []struct {
		value string
		rule  sdk.NetworkRule
		ok    bool
	}{
		{"10.0.0.0/8:443", sdk.NetworkRule{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443}, true},
		{"udp:10.0.0.0/8:53", sdk.NetworkRule{Protocol: "udp", CIDR: "10.0.0.0/8", Port: 53}, true},
		{"0.0.0.0/0", sdk.NetworkRule{Protocol: "tcp", CIDR: "0.0.0.0/0"}, true},
		{"2001:db8::/32", sdk.NetworkRule{Protocol: "tcp", CIDR: "2001:db8::/32"}, true},
		{"domain.example:443", sdk.NetworkRule{Protocol: "tcp", Domain: "domain.example", Port: 443}, true},
		{"*.example.com:443", sdk.NetworkRule{Protocol: "tcp", Domain: "*.example.com", Port: 443}, true},
		{"**", sdk.NetworkRule{Protocol: "tcp", CIDR: "0.0.0.0/0"}, true},
		{"10.0.0.0/8:99999", sdk.NetworkRule{}, false},
		{"192.0.2.10:443", sdk.NetworkRule{Protocol: "tcp", CIDR: "192.0.2.10/32", Port: 443}, true},
		{"deny-ip.example:80", sdk.NetworkRule{Protocol: "tcp", Domain: "deny-ip.example", Port: 80}, true},
		{"192.0.2.10/32", sdk.NetworkRule{Protocol: "tcp", CIDR: "192.0.2.10/32"}, true},
		{"2001:db8::1", sdk.NetworkRule{Protocol: "tcp", CIDR: "2001:db8::1/128"}, true},
		{"[2001:db8::1]:443", sdk.NetworkRule{Protocol: "tcp", CIDR: "2001:db8::1/128", Port: 443}, true},
	} {
		rule, err := parseNetworkRule(tc.value)
		if (err == nil) != tc.ok || rule != tc.rule {
			t.Fatalf("parseNetworkRule(%q)=%+v,%v", tc.value, rule, err)
		}
	}
}

func TestCreatePassesNetworkRules(t *testing.T) {
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{
		"create", "--allow-network", "10.0.0.0/8:443", "--allow-network", "0.0.0.0/0:80",
		"--deny-network", "udp:10.1.0.0/16:53", "dev",
	}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(sandbox.request.Allow) != 2 || sandbox.request.Allow[1].Port != 80 || len(sandbox.request.Deny) != 1 || sandbox.request.Deny[0].Protocol != "udp" {
		t.Fatalf("rules=%+v/%+v", sandbox.request.Allow, sandbox.request.Deny)
	}
}

func TestRunPassesNetworkRulesOnCreate(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--allow-network", "0.0.0.0/0:80", "--name", "dev", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if len(sandboxes.created.Allow) != 1 || sandboxes.created.Allow[0].Port != 80 {
		t.Fatalf("allow=%+v", sandboxes.created.Allow)
	}
}
