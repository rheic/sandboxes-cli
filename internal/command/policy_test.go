package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func TestEvaluatePolicy(t *testing.T) {
	ip := net.ParseIP("10.2.3.4")
	allow := []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443}}
	deny := []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.2.0.0/16", Port: 443}}
	if allowed, reason := evaluatePolicy(allow, nil, "tcp", ip, 443); !allowed || !strings.Contains(reason, "allow") {
		t.Fatalf("allow=%v reason=%s", allowed, reason)
	}
	if allowed, reason := evaluatePolicy(allow, deny, "tcp", ip, 443); allowed || !strings.Contains(reason, "deny") {
		t.Fatalf("deny precedence=%v reason=%s", allowed, reason)
	}
	if allowed, _ := evaluatePolicy(allow, nil, "tcp", ip, 80); allowed {
		t.Fatal("port mismatch allowed")
	}
	anyPort := []sdk.NetworkRule{{Protocol: "udp", CIDR: "10.0.0.0/8"}}
	if allowed, _ := evaluatePolicy(anyPort, nil, "udp", ip, 53); !allowed {
		t.Fatal("port zero did not match")
	}
	if allowed, reason := evaluatePolicy(nil, nil, "tcp", ip, 443); allowed || reason != "default deny" {
		t.Fatalf("default=%v %s", allowed, reason)
	}
	emptyProtocol := []sdk.NetworkRule{{CIDR: "10.0.0.0/8", Port: 443}}
	if allowed, _ := evaluatePolicy(emptyProtocol, nil, "tcp", ip, 443); !allowed {
		t.Fatal("empty protocol must default to tcp")
	}
	if allowed, _ := evaluatePolicy(emptyProtocol, nil, "udp", ip, 443); allowed {
		t.Fatal("empty protocol incorrectly matched udp")
	}
}

func TestParsePolicyDestinationAcceptsSingleAddress(t *testing.T) {
	if _, err := parsePolicyDestination("10.0.0.0/8"); err == nil {
		t.Fatal("CIDR destination accepted")
	}
	ip, err := parsePolicyDestination("2001:db8::1")
	if err != nil || ip.To4() != nil {
		t.Fatalf("IPv6 destination = %v, %v", ip, err)
	}
}

func TestPolicyListAndCheck(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev",
		Allow: []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443}},
		Deny:  []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.9.0.0/16", Port: 443}},
	}}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"policy", "ls", "dev"}); code != 0 {
		t.Fatalf("ls exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "10.0.0.0/8") || !strings.Contains(out.String(), "deny") {
		t.Fatalf("ls output=%q", out.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "ls", "--json", "dev"}); code != 0 {
		t.Fatalf("json exit=%d output=%q", code, out.String())
	}
	var rules []policyRuleOutput
	if err := json.Unmarshal(out.Bytes(), &rules); err != nil || len(rules) != 2 || rules[0].Action != "allow" {
		t.Fatalf("rules=%+v err=%v", rules, err)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "check", "dev", "10.1.2.3", "443"}); code != 0 {
		t.Fatalf("allowed check exit=%d output=%q", code, out.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "check", "dev", "10.9.1.2", "443"}); code != 1 {
		t.Fatalf("denied check exit=%d output=%q", code, out.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "allow", "dev", "10.0.0.0/8"}); code != 1 {
		t.Fatalf("dynamic policy exit=%d output=%q", code, out.String())
	}
}

type policyUpdateClient struct {
	fakeClient
	base        *lifecycleSandbox
	allow, deny []sdk.NetworkRule
	profile     string
}

func (p *policyUpdateClient) PolicyService() sdk.PolicyService { return p }

func (p *policyUpdateClient) GetPolicyProfile(context.Context) (string, error) {
	if p.profile == "" {
		return "deny-all", nil
	}
	return p.profile, nil
}

func (p *policyUpdateClient) SetPolicyProfile(_ context.Context, profile string) (string, error) {
	p.profile = profile
	return profile, nil
}

func (p *policyUpdateClient) UpdatePolicy(_ context.Context, id string, allow, deny []sdk.NetworkRule) (*sdk.Sandbox, error) {
	_ = id
	p.allow = append([]sdk.NetworkRule(nil), allow...)
	p.deny = append([]sdk.NetworkRule(nil), deny...)
	if p.base != nil && len(p.base.items) > 0 {
		p.base.items[0].Allow = p.allow
		p.base.items[0].Deny = p.deny
	}
	return &sdk.Sandbox{ID: "sb-1", Name: "dev", Allow: allow, Deny: deny}, nil
}

func (p *policyUpdateClient) Check(ctx context.Context, id, protocol, address, domain string, port uint16) (sdk.PolicyDecision, error) {
	return fakePolicyCheck{sandboxes: p.fakeClient.sandbox}.Check(ctx, id, protocol, address, domain, port)
}

func (p *policyUpdateClient) GetGlobalPolicy(context.Context) ([]sdk.NetworkRule, []sdk.NetworkRule, error) {
	return nil, nil, nil
}

func (p *policyUpdateClient) MutateGlobalPolicy(context.Context, string, sdk.NetworkRule) ([]sdk.NetworkRule, []sdk.NetworkRule, error) {
	return nil, nil, nil
}

func (p *policyUpdateClient) Refresh(context.Context) (int, error) { return 0, nil }

func (p *policyUpdateClient) ResetGlobal(context.Context) ([]sdk.NetworkRule, []sdk.NetworkRule, string, error) {
	return nil, nil, "deny-all", nil
}

func (p *policyUpdateClient) MutatePolicy(ctx context.Context, id, action string, rule sdk.NetworkRule) (*sdk.Sandbox, error) {
	allow := append([]sdk.NetworkRule(nil), p.base.items[0].Allow...)
	deny := append([]sdk.NetworkRule(nil), p.base.items[0].Deny...)
	switch action {
	case "allow":
		allow = append(allow, rule)
	case "deny":
		deny = append(deny, rule)
	case "rm":
		if !slices.Contains(allow, rule) && !slices.Contains(deny, rule) {
			return nil, errors.New("policy rule not found")
		}
		allow = slices.DeleteFunc(allow, func(r sdk.NetworkRule) bool { return r == rule })
		deny = slices.DeleteFunc(deny, func(r sdk.NetworkRule) bool { return r == rule })
	}
	return p.UpdatePolicy(ctx, id, allow, deny)
}

func TestPolicyDynamicUpdates(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev",
		Allow: []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443}},
	}}}
	client := &policyUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"policy", "allow", "dev", "0.0.0.0/0:80"}); code != 0 {
		t.Fatalf("allow exit=%d output=%q", code, out.String())
	}
	if len(client.allow) != 2 || client.allow[1].Port != 80 {
		t.Fatalf("allow=%+v", client.allow)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "deny", "dev", "10.9.0.0/16:443"}); code != 0 {
		t.Fatalf("deny exit=%d output=%q", code, out.String())
	}
	if len(client.deny) != 1 {
		t.Fatalf("deny=%+v", client.deny)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "rm", "dev", "10.0.0.0/8:443"}); code != 0 {
		t.Fatalf("rm exit=%d output=%q", code, out.String())
	}
	if len(client.allow) != 1 || client.allow[0].Port != 80 {
		t.Fatalf("allow after rm=%+v", client.allow)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "rm", "dev", "192.0.2.0/24"}); code != 1 {
		t.Fatalf("missing rm exit=%d output=%q", code, out.String())
	}
}

func TestPolicyInitAndProfile(t *testing.T) {
	client := &policyUpdateClient{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"policy", "init", "balanced"}); code != 0 {
		t.Fatalf("init exit=%d output=%q", code, out.String())
	}
	if client.profile != "balanced" {
		t.Fatalf("profile=%q", client.profile)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "profile", "ls"}); code != 0 {
		t.Fatalf("profile exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "balanced") {
		t.Fatalf("output=%q", out.String())
	}
	if code := runner.Run(context.Background(), []string{"policy", "init", "unknown"}); code != 2 {
		t.Fatalf("unknown init exit=%d", code)
	}
}

func TestEvaluatePolicyName(t *testing.T) {
	allow := []sdk.NetworkRule{
		{Protocol: "tcp", Domain: "*.example.com", Port: 443},
		{Protocol: "tcp", Domain: "api[12].example.net", Port: 443},
	}
	deny := []sdk.NetworkRule{{Protocol: "tcp", Domain: "secret.example.com", Port: 443}}
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"api.example.com", true},
		{"a.b.example.com", false},
		{"example.com", false},
		{"api1.example.net", true},
		{"api3.example.net", false},
		{"secret.example.com", false},
	} {
		got, _ := evaluatePolicyName(allow, deny, "tcp", tc.name, 443)
		if got != tc.want {
			t.Fatalf("evaluatePolicyName(%q)=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFilesystemPolicyOutputAndCheck(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev",
		Workspaces: []sdk.Workspace{
			{Path: "/work"},
			{Path: "/readonly", ReadOnly: true},
		},
	}}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"policy", "ls", "dev", "--json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var rules []policyRuleOutput
	if err := json.Unmarshal(out.Bytes(), &rules); err != nil || len(rules) != 4 {
		t.Fatalf("rules=%+v err=%v", rules, err)
	}
	if rules[0].ResourceType != "filesystem" || rules[0].Path != "/work" || rules[0].Access != "read" {
		t.Fatalf("first rule=%+v", rules[0])
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"policy", "check", "filesystem", "--sandbox", "dev", "/work/a"}, 0, "workspace /work (read)"},
		{[]string{"policy", "check", "filesystem", "--sandbox", "dev", "--write", "/work/a"}, 0, "read-write"},
		{[]string{"policy", "check", "filesystem", "--sandbox", "dev", "--write", "/readonly/a"}, 1, "read-only"},
		{[]string{"policy", "check", "filesystem", "--sandbox", "dev", "/outside"}, 1, "outside"},
	} {
		out.Reset()
		if code := runner.Run(context.Background(), tc.args); code != tc.code || !strings.Contains(out.String(), tc.want) {
			t.Fatalf("%v exit=%d output=%q want %q", tc.args, code, out.String(), tc.want)
		}
	}
}

func TestFilesystemCheckUsesMostSpecificWorkspace(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev",
		Workspaces: []sdk.Workspace{{Path: "/work"}, {Path: "/work/protected", ReadOnly: true}},
	}}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"policy", "check", "filesystem", "--sandbox", "dev", "--write", "/work/protected/file"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "/work/protected") || !strings.Contains(out.String(), "read-only") {
		t.Fatalf("output=%q", out.String())
	}
}

type fakePolicyCheck struct{ sandboxes sdk.SandboxService }

func (f fakePolicyCheck) UpdatePolicy(context.Context, string, []sdk.NetworkRule, []sdk.NetworkRule) (*sdk.Sandbox, error) {
	return nil, errors.New("not implemented")
}
func (f fakePolicyCheck) MutatePolicy(context.Context, string, string, sdk.NetworkRule) (*sdk.Sandbox, error) {
	return nil, errors.New("not implemented")
}
func (f fakePolicyCheck) GetPolicyProfile(context.Context) (string, error)             { return "", nil }
func (f fakePolicyCheck) SetPolicyProfile(_ context.Context, p string) (string, error) { return p, nil }
func (f fakePolicyCheck) GetGlobalPolicy(context.Context) ([]sdk.NetworkRule, []sdk.NetworkRule, error) {
	return nil, nil, nil
}
func (f fakePolicyCheck) Refresh(context.Context) (int, error) { return 0, nil }

func (f fakePolicyCheck) ResetGlobal(context.Context) ([]sdk.NetworkRule, []sdk.NetworkRule, string, error) {
	return nil, nil, "deny-all", nil
}

func (f fakePolicyCheck) MutateGlobalPolicy(context.Context, string, sdk.NetworkRule) ([]sdk.NetworkRule, []sdk.NetworkRule, error) {
	return nil, nil, &sdk.Error{Code: "unsupported", Message: "global policy is not supported by this client"}
}
func (f fakePolicyCheck) Check(ctx context.Context, id, protocol, address, domain string, port uint16) (sdk.PolicyDecision, error) {
	if id == "" {
		return sdk.PolicyDecision{Allowed: false, Reason: "default deny"}, nil
	}
	page, err := f.sandboxes.List(ctx, sdk.ListOptions{})
	if err != nil {
		return sdk.PolicyDecision{}, err
	}
	for i := range page.Items {
		item := &page.Items[i]
		if id != "" && item.ID != id && item.Name != id {
			continue
		}
		if domain != "" {
			allowed, reason := evaluatePolicyName(item.Allow, item.Deny, protocol, domain, port)
			return sdk.PolicyDecision{Allowed: allowed, Reason: reason}, nil
		}
		ip := net.ParseIP(address)
		if ip == nil {
			return sdk.PolicyDecision{}, errors.New("invalid address")
		}
		allowed, reason := evaluatePolicyTarget(item.Allow, item.Deny, protocol, ip, port)
		return sdk.PolicyDecision{Allowed: allowed, Reason: reason}, nil
	}
	return sdk.PolicyDecision{Allowed: false, Reason: "default deny"}, nil
}

func (f fakeClient) PolicyService() sdk.PolicyService { return fakePolicyCheck{sandboxes: f.sandbox} }
