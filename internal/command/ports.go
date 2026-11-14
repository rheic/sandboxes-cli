package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

const (
	loopbackHost = "127.0.0.1"
	tcpProtocol  = "tcp"
	udpProtocol  = "udp"
	tcp4Protocol = "tcp4"
	udp4Protocol = "udp4"
	tcp6Protocol = "tcp6"
	udp6Protocol = "udp6"
)

type portOutput struct {
	HostIP      string `json:"host_ip" yaml:"host_ip"`
	HostPort    uint16 `json:"host_port" yaml:"host_port"`
	SandboxPort uint16 `json:"sandbox_port" yaml:"sandbox_port"`
	Protocol    string `json:"protocol" yaml:"protocol"`
}

func parsePublishSpec(value string) (sdk.Port, error) {
	return parsePortSpec(value, true)
}

func parsePortSpec(value string, allocateHost bool) (sdk.Port, error) {
	protocol, hostIP, family, err := parsePortProtocol(value)
	if err != nil {
		return sdk.Port{}, err
	}
	value, _, _ = strings.Cut(value, "/")
	if strings.HasPrefix(value, "[") {
		return parseBracketedPortSpec(value, protocol, family, allocateHost)
	}
	parts := strings.Split(value, ":")
	if len(parts) == 1 {
		return ephemeralPort(parts[0], protocol, hostIP, allocateHost)
	}
	if len(parts) == 2 {
		return explicitPort(parts[0], parts[1], protocol, hostIP)
	}
	if len(parts) == 3 {
		hostIP, err = normalizePortHostIP(parts[0], family)
		if err != nil {
			return sdk.Port{}, err
		}
		return explicitPort(parts[1], parts[2], protocol, hostIP)
	}
	return sdk.Port{}, errors.New("port spec must be [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6]")
}

func parsePortProtocol(value string) (protocol, hostIP, family string, err error) {
	protocol = tcpProtocol
	hostIP = loopbackHost
	if _, after, found := strings.Cut(value, "/"); found {
		switch after {
		case tcpProtocol:
		case udpProtocol:
			protocol = udpProtocol
		case tcp4Protocol, udp4Protocol:
			family = "4"
			if after == udp4Protocol {
				protocol = udpProtocol
			}
		case tcp6Protocol, udp6Protocol:
			family = "6"
			hostIP = "::1"
			if after == udp6Protocol {
				protocol = udpProtocol
			}
		default:
			return "", "", "", errors.New("port protocol must be tcp, udp, tcp4, udp4, tcp6 or udp6")
		}
	}
	return protocol, hostIP, family, nil
}

func parseBracketedPortSpec(value, protocol, family string, allocateHost bool) (sdk.Port, error) {
	end := strings.Index(value, "]")
	if end < 0 || end+1 >= len(value) || value[end+1] != ':' {
		return sdk.Port{}, errors.New("IPv6 host IP must use [ADDR]:HOST:GUEST or [ADDR]:GUEST")
	}
	hostIP, err := normalizePortHostIP(value[1:end], family)
	if err != nil {
		return sdk.Port{}, err
	}
	rest := strings.Split(value[end+2:], ":")
	if len(rest) == 1 {
		return ephemeralPort(rest[0], protocol, hostIP, allocateHost)
	}
	if len(rest) == 2 {
		return explicitPort(rest[0], rest[1], protocol, hostIP)
	}
	return sdk.Port{}, errors.New("port spec must be [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6]")
}

func normalizePortHostIP(value, family string) (string, error) {
	ip := net.ParseIP(value)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("host IP must be loopback (127.0.0.1 or ::1)")
	}
	if family == "" {
		return ip.String(), nil
	}
	ipFamily := "4"
	if ip.To4() == nil {
		ipFamily = "6"
	}
	if family != ipFamily {
		return "", errors.New("host IP family does not match port protocol")
	}
	return ip.String(), nil
}

func explicitPort(hostValue, guestValue, protocol, hostIP string) (sdk.Port, error) {
	if hostValue == "" || guestValue == "" {
		return sdk.Port{}, errors.New("host and guest ports must be non-empty")
	}
	host, err := strconv.ParseUint(hostValue, 10, 16)
	if err != nil || host == 0 {
		return sdk.Port{}, errors.New("host port must be 1..65535")
	}
	guest, err := strconv.ParseUint(guestValue, 10, 16)
	if err != nil || guest == 0 {
		return sdk.Port{}, errors.New("guest port must be 1..65535")
	}
	return sdk.Port{Host: uint16(host), Guest: uint16(guest), Protocol: protocol, HostIP: hostIP}, nil
}

func ephemeralPort(value, protocol, hostIP string, allocateHost bool) (sdk.Port, error) {
	guest, err := strconv.ParseUint(value, 10, 16)
	if err != nil || guest == 0 {
		return sdk.Port{}, errors.New("guest port must be 1..65535")
	}
	if !allocateHost {
		return sdk.Port{Guest: uint16(guest), Protocol: protocol, HostIP: hostIP}, nil
	}
	host, err := allocateHostPort(protocol, hostIP)
	if err != nil {
		return sdk.Port{}, err
	}
	return sdk.Port{Host: host, Guest: uint16(guest), Protocol: protocol, HostIP: hostIP}, nil
}

func allocateHostPort(protocol, hostIP string) (uint16, error) {
	network := tcp4Protocol
	address := net.JoinHostPort(hostIP, "0")
	if hostIP == "::1" {
		network = tcp6Protocol
	}
	var port int
	var err error
	if protocol == udpProtocol {
		port, err = allocateUDPPort(network, address)
	} else {
		port, err = allocateTCPPort(network, address)
	}
	if err != nil {
		return 0, err
	}
	if port <= 0 || port > 65535 {
		return 0, errors.New("allocated host port is out of range")
	}
	return uint16(port), nil
}

func allocateUDPPort(network, address string) (int, error) {
	if network == tcp6Protocol {
		network = udp6Protocol
	} else {
		network = udp4Protocol
	}
	packet, err := net.ListenPacket(network, address)
	if err != nil {
		return 0, fmt.Errorf("allocate host port: %w", err)
	}
	port := packet.LocalAddr().(*net.UDPAddr).Port
	if err := packet.Close(); err != nil {
		return 0, fmt.Errorf("release allocated host port: %w", err)
	}
	return port, nil
}

func allocateTCPPort(network, address string) (int, error) {
	listener, err := net.Listen(network, address)
	if err != nil {
		return 0, fmt.Errorf("allocate host port: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return 0, fmt.Errorf("release allocated host port: %w", err)
	}
	return port, nil
}

func resolvePorts(values []string) ([]sdk.Port, error) {
	return resolvePortSpecs(values, true)
}

func resolvePortSpecs(values []string, allocateHost bool) ([]sdk.Port, error) {
	if len(values) > 32 {
		return nil, errors.New("at most 32 published ports are supported")
	}
	ports := make([]sdk.Port, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		port, err := parsePortSpec(value, allocateHost)
		if err != nil {
			return nil, err
		}
		key := port.Protocol + ":" + port.HostIP + ":" + strconv.Itoa(int(port.Host))
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate host port %s:%d/%s", port.HostIP, port.Host, port.Protocol)
		}
		seen[key] = struct{}{}
		ports = append(ports, port)
	}
	return ports, nil
}

func portsFor(sb *sdk.Sandbox) []portOutput {
	out := make([]portOutput, 0, len(sb.Ports))
	for i := range sb.Ports {
		hostIP := portHostIP(sb.Ports[i])
		out = append(out, portOutput{
			HostIP: hostIP, HostPort: sb.Ports[i].Host,
			SandboxPort: sb.Ports[i].Guest, Protocol: displayPortProtocol(sb.Ports[i].Protocol, hostIP),
		})
	}
	return out
}

func portHostIP(port sdk.Port) string {
	if port.HostIP == "" {
		return "127.0.0.1"
	}
	return port.HostIP
}

func displayPortProtocol(protocol, hostIP string) string {
	base := tcpProtocol
	if protocol == udpProtocol || protocol == "udp4" || protocol == "udp6" {
		base = udpProtocol
	}
	family := "4"
	if protocol == "tcp6" || protocol == "udp6" {
		family = "6"
	} else if ip := net.ParseIP(hostIP); ip != nil && ip.To4() == nil {
		family = "6"
	}
	return base + family
}

func (r *Runner) ports(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("ports", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	var publishFlags, unpublishFlags stringListFlag
	fs.Var(&publishFlags, "publish", "publish [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6] (repeatable)")
	fs.Var(&unpublishFlags, "unpublish", "unpublish [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6] (repeatable)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx ports [--publish [[HOST_IP:]HOST_PORT:]GUEST[/PROTO]] [--unpublish [[HOST_IP:]HOST_PORT:]GUEST[/PROTO]] [--format table|json|yaml] SANDBOX")
		return 2
	}
	if len(publishFlags) > 0 || len(unpublishFlags) > 0 {
		return r.portsMutate(ctx, fs.Arg(0), publishFlags, unpublishFlags)
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	id, err := findExecSandbox(ctx, client, fs.Arg(0))
	if err != nil {
		r.error(err)
		return 1
	}
	sb, err := client.Sandboxes().Get(ctx, id)
	if err != nil {
		r.error(err)
		return 1
	}
	if err := renderPortList(r.Out, selected, portsFor(sb)); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func (r *Runner) portsMutate(ctx context.Context, sandbox string, publishFlags, unpublishFlags []string) int {
	published, err := resolvePorts(publishFlags)
	if err != nil {
		r.error(err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	id, err := findExecSandbox(ctx, client, sandbox)
	if err != nil {
		r.error(err)
		return 1
	}
	sb, err := client.Sandboxes().Get(ctx, id)
	if err != nil {
		r.error(err)
		return 1
	}
	unpublished, err := resolveUnpublishPorts(sb.Ports, unpublishFlags)
	if err != nil {
		r.error(err)
		return 1
	}
	ports, err := applyPortChanges(sb.Ports, published, unpublished)
	if err != nil {
		r.error(err)
		return 1
	}
	updated, err := sdk.Ports(client).UpdatePorts(ctx, id, ports)
	if err != nil {
		r.error(err)
		return 1
	}
	r.printPublishedPorts(updated.Ports, published)
	r.printUnpublishedPorts(unpublished)
	if len(published) == 0 && len(unpublished) == 0 {
		_, _ = fmt.Fprintf(r.Out, "updated ports for %s (%d)\n", updated.Name, len(updated.Ports))
	}
	return 0
}

func (r *Runner) printPublishedPorts(actual, requested []sdk.Port) {
	for _, want := range requested {
		hostIP, host := resolvedPublishedPort(actual, want)
		_, _ = fmt.Fprintf(r.Out, "Published %s -> %d/%s\n", hostPortEndpoint(hostIP, host), want.Guest, displayPortProtocol(want.Protocol, hostIP))
	}
}

func hostPortEndpoint(hostIP string, host uint16) string {
	return net.JoinHostPort(hostIP, strconv.Itoa(int(host)))
}

func resolvedPublishedPort(actual []sdk.Port, requested sdk.Port) (string, uint16) {
	hostIP, host := portHostIP(requested), requested.Host
	for _, current := range actual {
		if current.Guest == requested.Guest && current.Protocol == requested.Protocol && portHostIP(current) == hostIP {
			host = current.Host
			if current.HostIP != "" {
				hostIP = current.HostIP
			}
			break
		}
	}
	return hostIP, host
}

func (r *Runner) printUnpublishedPorts(requested []sdk.Port) {
	for _, port := range requested {
		_, _ = fmt.Fprintf(r.Out, "Unpublish requested for port %s -> %d\n", hostPortEndpoint(portHostIP(port), port.Host), port.Guest)
	}
}

func resolveUnpublishPorts(existing []sdk.Port, values []string) ([]sdk.Port, error) {
	out := make([]sdk.Port, 0, len(values))
	for _, value := range values {
		requested, err := parsePortSpec(value, false)
		if err != nil {
			return nil, err
		}
		if requested.Host != 0 {
			out = append(out, requested)
			continue
		}
		var match *sdk.Port
		for i := range existing {
			if existing[i].Guest != requested.Guest || existing[i].Protocol != requested.Protocol || portHostIP(existing[i]) != portHostIP(requested) {
				continue
			}
			if match != nil {
				return nil, fmt.Errorf("guest port %d/%s has multiple host mappings; specify HOST_IP:HOST_PORT:GUEST", requested.Guest, requested.Protocol)
			}
			match = &existing[i]
		}
		if match == nil {
			return nil, fmt.Errorf("port %s:%d/%s is not published", portHostIP(requested), requested.Guest, requested.Protocol)
		}
		requested.Host = match.Host
		out = append(out, requested)
	}
	return out, nil
}

func applyPortChanges(existing, published, unpublished []sdk.Port) ([]sdk.Port, error) {
	ports := append([]sdk.Port(nil), existing...)
	for _, requested := range published {
		if portEndpointExists(ports, requested) {
			return nil, fmt.Errorf("host port %s:%d/%s is already published", portHostIP(requested), requested.Host, requested.Protocol)
		}
		ports = append(ports, requested)
	}
	for _, requested := range unpublished {
		next, removed := removePublishedPort(ports, requested)
		if !removed {
			return nil, fmt.Errorf("port %s:%d:%d is not published", portHostIP(requested), requested.Host, requested.Guest)
		}
		ports = next
	}
	return ports, nil
}

func portEndpointExists(ports []sdk.Port, candidate sdk.Port) bool {
	for _, current := range ports {
		if samePortEndpoint(current, candidate) {
			return true
		}
	}
	return false
}

func samePortEndpoint(a, b sdk.Port) bool {
	return a.Host == b.Host && a.Protocol == b.Protocol && portHostIP(a) == portHostIP(b)
}

func removePublishedPort(ports []sdk.Port, candidate sdk.Port) ([]sdk.Port, bool) {
	for i, current := range ports {
		if current.Host == candidate.Host && current.Guest == candidate.Guest && current.Protocol == candidate.Protocol && portHostIP(current) == portHostIP(candidate) {
			next := append([]sdk.Port(nil), ports[:i]...)
			return append(next, ports[i+1:]...), true
		}
	}
	return ports, false
}

func renderPortList(out io.Writer, format string, ports []portOutput) error {
	switch format {
	case listFormatTable:
		if len(ports) == 0 {
			_, err := fmt.Fprintln(out, "No published ports")
			return err
		}
		return writePortTable(out, ports)
	case listFormatYAML:
		data, err := yaml.Marshal(ports)
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(ports)
	}
}

func writePortTable(out io.Writer, ports []portOutput) error {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "HOST IP\tHOST PORT\tSANDBOX PORT\tPROTOCOL")
	for _, port := range ports {
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%s\n", port.HostIP, port.HostPort, port.SandboxPort, port.Protocol)
	}
	return tw.Flush()
}
