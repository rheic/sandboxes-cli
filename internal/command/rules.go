package command

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

type ruleOutput struct {
	RuleID       string `json:"rule_id" yaml:"rule_id"`
	Scope        string `json:"scope" yaml:"scope"`
	ResourceType string `json:"resource_type" yaml:"resource_type"`
	Action       string `json:"action" yaml:"action"`
	Provenance   string `json:"provenance" yaml:"provenance"`
	Protocol     string `json:"protocol" yaml:"protocol"`
	CIDR         string `json:"cidr,omitempty" yaml:"cidr,omitempty"`
	Domain       string `json:"domain,omitempty" yaml:"domain,omitempty"`
	Port         uint16 `json:"port" yaml:"port"`
}

func parseNetworkRule(value string) (sdk.NetworkRule, error) {
	protocol := tcpProtocol
	if strings.HasPrefix(value, "udp:") {
		protocol = udpProtocol
		value = strings.TrimPrefix(value, "udp:")
	}
	target := value
	port := uint16(0)
	// A bare IP literal has no port; IPv6 ports require brackets.
	if ip := net.ParseIP(target); ip != nil {
		bits := "128"
		if ip.To4() != nil {
			bits = "32"
		}
		return sdk.NetworkRule{Protocol: protocol, CIDR: ip.String() + "/" + bits, Port: 0}, nil
	}
	if index := strings.LastIndexByte(target, ':'); index > 0 {
		parsed, err := strconv.ParseUint(target[index+1:], 10, 16)
		if err == nil {
			if parsed == 0 {
				return sdk.NetworkRule{}, errors.New("network rule port must be 1..65535")
			}
			port = uint16(parsed)
			target = target[:index]
		}
	}
	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		target = strings.TrimSuffix(strings.TrimPrefix(target, "["), "]")
	}
	if _, network, err := net.ParseCIDR(target); err == nil {
		return sdk.NetworkRule{Protocol: protocol, CIDR: network.String(), Port: port}, nil
	}
	// A bare IP literal must become a /32 CIDR. Storing it as a domain rule
	// would silently never match an IP flow (including a deny).

	if ip := net.ParseIP(target); ip != nil {
		bits := "128"
		if ip.To4() != nil {
			bits = "32"
		}
		return sdk.NetworkRule{Protocol: protocol, CIDR: ip.String() + "/" + bits, Port: port}, nil
	}
	if target == "**" {
		return sdk.NetworkRule{Protocol: protocol, CIDR: "0.0.0.0/0", Port: port}, nil
	}
	if err := validateCLIDomain(target); err != nil {
		return sdk.NetworkRule{}, err
	}
	return sdk.NetworkRule{Protocol: protocol, Domain: strings.ToLower(target), Port: port}, nil
}

func validateCLIDomain(target string) error {
	if target == "" || len(target) > 253 || strings.ContainsAny(target, "\\ ") {
		return errors.New("network rule must be an IPv4 CIDR or a domain")
	}
	if net.ParseIP(target) != nil {
		return errors.New("network rule domain must not be an IP literal; use a CIDR")
	}
	base := strings.TrimPrefix(strings.TrimPrefix(target, "**."), "*.")
	if base == "" || strings.Contains(base, "*") || strings.Contains(base, "://") {
		return errors.New("invalid domain rule")
	}
	for _, label := range strings.Split(base, ".") {
		if !validCLIDomainLabel(label) {
			return errors.New("invalid domain rule")
		}
	}
	return nil
}

func validCLIDomainLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '?' || r == '[' || r == ']' || r == '!' {
			continue
		}
		return false
	}
	return true
}

func resolveNetworkRules(values []string) ([]sdk.NetworkRule, error) {
	if len(values) > 64 {
		return nil, errors.New("at most 64 network rules are supported")
	}
	rules := make([]sdk.NetworkRule, 0, len(values))
	for _, value := range values {
		rule, err := parseNetworkRule(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", value, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func rulesFor(sb *sdk.Sandbox) (allow, deny []ruleOutput) {
	convert := func(rules []sdk.NetworkRule) []ruleOutput {
		out := make([]ruleOutput, 0, len(rules))
		for i := range rules {
			out = append(out, ruleOutput{RuleID: rules[i].RuleID, Scope: sandboxPrefix, ResourceType: "network",
				Action: actionAllow, Provenance: "user", Protocol: rules[i].Protocol, CIDR: rules[i].CIDR,
				Domain: rules[i].Domain, Port: rules[i].Port})
		}
		return out
	}
	return convert(sb.Allow), convert(sb.Deny)
}

func formatRules(rules []sdk.NetworkRule) string {
	if len(rules) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(rules))
	for i := range rules {
		port := ""
		if rules[i].Port != 0 {
			port = fmt.Sprintf(":%d", rules[i].Port)
		}
		protocol := rules[i].Protocol
		if protocol == "" {
			protocol = tcpProtocol
		}
		target := rules[i].CIDR
		if rules[i].Domain != "" {
			target = rules[i].Domain
		}
		parts = append(parts, fmt.Sprintf("%s:%s%s", protocol, target, port))
	}
	return strings.Join(parts, ", ")
}

func allowRules(sb *sdk.Sandbox) []ruleOutput {
	allow, _ := rulesFor(sb)
	return allow
}

func denyRules(sb *sdk.Sandbox) []ruleOutput {
	_, deny := rulesFor(sb)
	return deny
}
