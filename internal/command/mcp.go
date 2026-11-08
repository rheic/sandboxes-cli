package command

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	sdk "github.com/rheic/sandboxes-go-sdk"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

type mcpArgsFlag []string

const mcpFormatYAML = "yaml"

func (f *mcpArgsFlag) String() string { return strings.Join(*f, ",") }
func (f *mcpArgsFlag) Set(value string) error {
	reader := csv.NewReader(strings.NewReader(value))
	reader.FieldsPerRecord = -1
	values, err := reader.Read()
	if err != nil {
		return err
	}
	*f = append(*f, values...)
	return nil
}

func (r *Runner) mcp(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == helpCommand || args[0] == helpShort || args[0] == helpFlag {
		_, _ = fmt.Fprintln(r.Out, "usage: rsbx mcp <ls|add|call|rm> [flags]")
		_, _ = fmt.Fprintln(r.Out, "commands: ls, add, call, rm")
		return 0
	}
	switch args[0] {
	case "ls":
		return r.mcpList(ctx, args[1:])
	case "add":
		return r.mcpAdd(ctx, args[1:])
	case "call":
		return r.mcpCall(ctx, args[1:])
	case "rm":
		return r.mcpRemove(ctx, args[1:])
	default:
		_, _ = fmt.Fprintf(r.Err, "rsbx mcp: unknown command %q\n", args[0])
		return 2
	}
}

func (r *Runner) mcpList(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("mcp ls", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	jsonOutput := fs.Bool("json", false, "write JSON")
	quiet := fs.Bool("quiet", false, "print server names only")
	format := fs.String("format", "", "output format: table or json")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"--format": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("mcp ls", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx mcp ls [flags]")
		return 2
	}
	if *format != "" {
		if *format != "table" && *format != "json" && *format != mcpFormatYAML {
			_, _ = fmt.Fprintln(r.Err, "mcp ls: --format must be table, json, or yaml")
			return 2
		}
		*jsonOutput = *jsonOutput || *format == "json"
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	servers, err := sdk.MCP(client).List(ctx, "")
	if err != nil {
		r.error(err)
		return 1
	}
	if err := writeMCPList(r.Out, servers, *format, *jsonOutput, *quiet); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func writeMCPList(out io.Writer, servers []sdk.MCPServer, format string, jsonOutput, quiet bool) error {
	if jsonOutput || format == mcpFormatYAML {
		rows := mcpServerRows(servers)
		var output []byte
		var err error
		if format == mcpFormatYAML && !jsonOutput {
			output, err = yaml.Marshal(rows)
		} else {
			output, err = json.Marshal(rows)
		}
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(output))
		return err
	}
	for _, server := range servers {
		var err error
		if quiet {
			_, err = fmt.Fprintln(out, server.Name)
		} else {
			_, err = fmt.Fprintf(out, "%-24s %-12s %-18s %s\n", server.Name, server.Gateway, server.Transport, mcpUsability(server))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) mcpAdd(ctx context.Context, args []string) int {
	var serverArgs, headerArgs, secretHeaderArgs mcpArgsFlag
	fs := flag.NewFlagSet("mcp add", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	command := fs.String("command", "", "absolute or PATH-resolved local stdio executable")
	directory := fs.String("dir", "", "working directory")
	remoteURL := fs.String("url", "", "remote streamable-HTTPS MCP endpoint (mutually exclusive with --command)")
	fs.Var(&serverArgs, "args", "comma-separated MCP executable arguments (repeatable)")
	fs.Var(&headerArgs, "header", "static non-secret remote header as Name:Value")
	fs.Var(&secretHeaderArgs, "secret-header", "host-vault remote header as Name:Value with ${placeholder}")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage: rsbx mcp add NAME %s EXECUTABLE [--args ARG] [--dir PATH]\n", commandFlag)
		_, _ = fmt.Fprintln(fs.Output(), "       rsbx mcp add NAME --url https://HOST/mcp [--header Name:Value] [--secret-header Name:${PLACEHOLDER}]")
		_, _ = fmt.Fprintln(fs.Output(), "Runs the registered stdio server on the host after daemon approval. Remote servers are limited to the daemon's allowed hosts. --header is for non-secret values; store credentials with rsbx secret set mcp:NAME:PLACEHOLDER and pass the reference with --secret-header.")
	}
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{commandFlag: true, "--dir": true, mcpArgsFlagName: true, "--url": true, "--header": true, "--secret-header": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("mcp add", err)
	}
	if fs.NArg() != 1 || (*command == "" && *remoteURL == "") || (*command != "" && *remoteURL != "") {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx mcp add NAME (--command EXECUTABLE [--args ARG] [--dir PATH] | --url https://HOST/mcp [--header Name:Value] [--secret-header Name:${PLACEHOLDER}])")
		return 2
	}
	if *remoteURL == "" && (len(headerArgs)+len(secretHeaderArgs) > 0) {
		r.error(errors.New("MCP headers are supported only for remote servers"))
		return 2
	}
	if err := requireMCPApprovalTerminal(r.In); err != nil {
		r.error(err)
		return 1
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if *remoteURL != "" {
		return r.mcpAddRemote(ctx, client, fs.Arg(0), *remoteURL, headerArgs, secretHeaderArgs)
	}
	return r.mcpAddStdio(ctx, client, fs.Arg(0), *command, *directory, serverArgs)
}

func (r *Runner) mcpAddRemote(ctx context.Context, client sdk.Client, name, rawURL string, headerArgs, secretHeaderArgs []string) int {
	headers, err := parseMCPHeaders(headerArgs)
	if err != nil {
		r.error(err)
		return 2
	}
	secretHeaders, err := parseMCPSecretHeaders(secretHeaderArgs)
	if err != nil {
		r.error(err)
		return 2
	}
	if mcpHeaderSetsOverlap(headers, secretHeaders) {
		r.error(errors.New("MCP header names must be unique, ignoring case"))
		return 2
	}
	if err := r.registerMCPRemoteServer(ctx, client, name, rawURL, headers, secretHeaders); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func mcpHeaderSetsOverlap(static, secret map[string]string) bool {
	for name := range static {
		for secretName := range secret {
			if strings.EqualFold(name, secretName) {
				return true
			}
		}
	}
	return false
}

func (r *Runner) mcpAddStdio(ctx context.Context, client sdk.Client, name, command, directory string, args []string) int {
	resolved, resolvedDir, err := prepareMCPCommand(command, directory)
	if err != nil {
		r.error(err)
		return 2
	}
	if err := r.registerMCPServer(ctx, client, name, resolved, args, resolvedDir); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

// parseMCPHeaders parses repeatable Name:Value flags into a header map.
func parseMCPHeaders(values []string) (map[string]string, error) {
	headers := make(map[string]string, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		name, headerValue, ok := strings.Cut(value, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("invalid MCP header %q, want Name:Value", value)
		}
		if strings.ContainsAny(name, "\r\n") || strings.ContainsAny(headerValue, "\r\n") {
			return nil, errors.New("MCP headers must not contain control characters")
		}
		canonicalName := strings.ToLower(name)
		if _, exists := seen[canonicalName]; exists {
			return nil, errors.New("MCP header names must be unique, ignoring case")
		}
		seen[canonicalName] = struct{}{}
		headerValue = strings.TrimSpace(headerValue)
		refs, err := mcpHeaderPlaceholderNames(headerValue)
		if err != nil {
			return nil, err
		}
		if sensitiveMCPHeaderName(name) {
			return nil, errors.New("credential-bearing MCP headers must use --secret-header")
		}
		if len(refs) > 0 || strings.Contains(headerValue, "}") {
			return nil, errors.New("MCP header placeholders must use --secret-header")
		}
		headers[name] = headerValue
	}
	return headers, nil
}

func sensitiveMCPHeaderName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, marker := range []string{"auth", "cookie", "token", "secret", "credential", "password", "-key", "_key", "apikey"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return strings.HasSuffix(name, "key")
}

func parseMCPSecretHeaders(values []string) (map[string]string, error) {
	headers := make(map[string]string, len(values))
	for _, value := range values {
		name, headerValue, ok := strings.Cut(value, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" || strings.ContainsAny(name, "\r\n") || strings.ContainsAny(headerValue, "\r\n") {
			return nil, errors.New("invalid secret MCP header, want Name:Value")
		}
		headerValue = strings.TrimSpace(headerValue)
		refs, err := mcpHeaderPlaceholderNames(headerValue)
		if err != nil || len(refs) == 0 {
			return nil, errors.New("secret MCP headers must contain valid host-vault ${placeholder} references")
		}
		canonicalName := strings.ToLower(name)
		for oldName := range headers {
			if strings.EqualFold(oldName, canonicalName) {
				return nil, errors.New("MCP header names must be unique, ignoring case")
			}
		}
		headers[name] = headerValue
	}
	return headers, nil
}

func mcpHeaderPlaceholderNames(value string) ([]string, error) {
	var names []string
	for offset := 0; ; {
		start := strings.Index(value[offset:], "${")
		if start < 0 {
			if strings.Contains(value[offset:], "}") {
				return nil, errors.New("invalid MCP header placeholder")
			}
			return names, nil
		}
		start += offset
		if strings.Contains(value[offset:start], "}") {
			return nil, errors.New("invalid MCP header placeholder")
		}
		end := strings.IndexByte(value[start+2:], '}')
		if end < 0 {
			return nil, errors.New("invalid MCP header placeholder")
		}
		end += start + 2
		name := value[start+2 : end]
		if !validMCPSecretPart(name, false) {
			return nil, errors.New("invalid MCP header placeholder")
		}
		names = append(names, name)
		offset = end + 1
	}
}

func (r *Runner) registerMCPRemoteServer(ctx context.Context, client sdk.Client, name, rawURL string, headers, secretHeaders map[string]string) error {
	service := sdk.MCP(client)
	registration, err := service.Register(ctx, sdk.MCPServerConfig{Name: name, URL: rawURL, Headers: headers, SecretHeaders: secretHeaders})
	if err != nil {
		return err
	}
	if registration == nil || !registration.ApprovalRequired || registration.ApprovalID == "" {
		return errors.New("daemon returned an invalid MCP registration challenge")
	}
	_, _ = fmt.Fprintf(r.Out, "MCP server %q requires host approval (challenge %s).\n", name, registration.ApprovalID)
	return nil
}

func prepareMCPCommand(command, directory string) (string, string, error) {
	resolved, err := exec.LookPath(command)
	if err != nil {
		return "", "", fmt.Errorf("resolve MCP command: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", "", err
	}
	if directory == "" {
		directory, err = os.Getwd()
		if err != nil {
			return "", "", err
		}
	}
	if !filepath.IsAbs(directory) {
		directory, err = filepath.Abs(directory)
	}
	return resolved, directory, err
}

func (r *Runner) registerMCPServer(ctx context.Context, client sdk.Client, name, command string, args []string, directory string) error {
	service := sdk.MCP(client)
	registration, err := service.Register(ctx, sdk.MCPServerConfig{Name: name, Command: command, Arguments: append([]string(nil), args...), WorkingDirectory: directory})
	if err != nil {
		return err
	}
	if registration == nil || !registration.ApprovalRequired || registration.ApprovalID == "" {
		return errors.New("daemon returned an invalid MCP registration challenge")
	}
	message := mcpRegistrationApprovalMessage(name, command, args, directory)
	approved, err := r.confirmMCPApproval(message)
	if err != nil {
		return err
	}
	if !approved {
		_, _ = fmt.Fprintln(r.Out, "MCP registration canceled")
		return nil
	}
	server, err := service.ApproveRegistration(ctx, registration.ApprovalID)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.Out, "Registered MCP server %s\n", server.Name)
	return err
}

func mcpRegistrationApprovalMessage(name, command string, args []string, directory string) string {
	return fmt.Sprintf("Register host MCP server %q\n  command: %s\n  argument count: %d (values hidden; do not configure secrets here)\n  directory: %s", name, command, len(args), directory)
}

func (r *Runner) mcpCall(ctx context.Context, args []string) int {
	var raw string
	fs := flag.NewFlagSet("mcp call", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	fs.StringVar(&raw, strings.TrimPrefix(mcpArgsFlagName, "--"), "{}", "JSON object passed to the tool")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), "Usage: rsbx mcp call SANDBOX SERVER TOOL [--args JSON]")
		_, _ = fmt.Fprintln(fs.Output(), "Requests daemon-trusted approval before invoking the host MCP server. Argument values are hidden in the prompt; do not pass secrets.")
	}
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{mcpArgsFlagName: true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("mcp call", err)
	}
	if fs.NArg() != 3 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx mcp call SANDBOX SERVER TOOL [--args JSON]")
		return 2
	}
	object, err := validateMCPCallArguments(raw)
	if err != nil {
		_, _ = fmt.Fprintln(r.Err, err)
		return 2
	}
	if err := requireMCPApprovalTerminal(r.In); err != nil {
		r.error(err)
		return 1
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	service := sdk.MCP(client)
	result, err := service.Call(ctx, fs.Arg(0), fs.Arg(1), fs.Arg(2), json.RawMessage(raw))
	if err == nil {
		_, _ = fmt.Fprintln(r.Out, string(result))
		return 0
	}
	var challenge *sdk.MCPApprovalRequiredError
	if !errors.As(err, &challenge) {
		r.error(err)
		return 1
	}
	message := mcpCallApprovalMessage(fs.Arg(1), fs.Arg(2), fs.Arg(0), object)
	approved, confirmErr := r.confirmMCPApproval(message)
	if confirmErr != nil {
		r.error(confirmErr)
		return 1
	}
	if !approved {
		_, _ = fmt.Fprintln(r.Out, "MCP tool call canceled")
		return 0
	}
	result, err = service.ApproveCall(ctx, challenge.ApprovalID)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintln(r.Out, string(result))
	return 0
}

func validateMCPCallArguments(raw string) (map[string]json.RawMessage, error) {
	if len(raw) > 16<<10 {
		return nil, errors.New("mcp call: approval display is limited to 16 KiB of arguments")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &object); err != nil || object == nil {
		return nil, errors.New("mcp call: --args must be a JSON object")
	}
	return object, nil
}

func mcpCallApprovalMessage(server, tool, sandbox string, arguments map[string]json.RawMessage) string {
	return fmt.Sprintf("Request trusted host approval to run MCP tool %s.%s in sandbox %s?\n  argument fields: %d (values hidden)", server, tool, sandbox, len(arguments))
}

func (r *Runner) mcpRemove(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("mcp rm", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	force := fs.Bool("force", false, "skip confirmation")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("mcp rm", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx mcp rm [--force] NAME")
		return 2
	}
	if !*force {
		confirmed, err := r.confirmMCPApproval("Remove MCP server registration " + fs.Arg(0) + "?")
		if err != nil {
			r.error(err)
			return 1
		}
		if !confirmed {
			_, _ = fmt.Fprintln(r.Out, "MCP removal canceled")
			return 0
		}
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	removed, err := sdk.MCP(client).Remove(ctx, fs.Arg(0))
	if err != nil {
		r.error(err)
		return 1
	}
	if removed {
		_, _ = fmt.Fprintf(r.Out, "Removed MCP server %s\n", fs.Arg(0))
	} else {
		_, _ = fmt.Fprintf(r.Out, "MCP server %s not found\n", fs.Arg(0))
	}
	return 0
}

func (r *Runner) confirmMCPApproval(message string) (bool, error) {
	if err := requireMCPApprovalTerminal(r.In); err != nil {
		return false, err
	}
	if _, err := fmt.Fprintf(r.Err, "%s\nApprove? [y/N] ", message); err != nil {
		return false, err
	}
	var answer string
	if _, err := fmt.Fscanln(r.In, &answer); err != nil {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == answerShortYes || answer == answerYes, nil
}

// requireMCPApprovalTerminal is replaceable in tests; production requires a
// real interactive terminal before any host-side MCP action.
var requireMCPApprovalTerminal = func(input io.Reader) error {
	file, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return errors.New("MCP approval requires an interactive terminal; no host action was approved")
	}
	return nil
}

type mcpServerRow struct {
	Name                          string `json:"name" yaml:"name"`
	Gateway                       string `json:"gateway" yaml:"gateway"`
	Transport                     string `json:"transport" yaml:"transport"`
	Loaded                        bool   `json:"loaded" yaml:"loaded"`
	Usable                        bool   `json:"usable" yaml:"usable"`
	AuthRequired                  bool   `json:"auth_required" yaml:"auth_required"`
	AuthConfigured                bool   `json:"auth_configured" yaml:"auth_configured"`
	HasCustomHeaders              bool   `json:"has_custom_headers" yaml:"has_custom_headers"`
	CustomHeadersSupported        bool   `json:"custom_headers_supported" yaml:"custom_headers_supported"`
	CustomHeaderSecretsConfigured bool   `json:"custom_header_secrets_configured" yaml:"custom_header_secrets_configured"`
}

func mcpServerRows(servers []sdk.MCPServer) []mcpServerRow {
	out := make([]mcpServerRow, 0, len(servers))
	for _, s := range servers {
		out = append(out, mcpServerRow{s.Name, s.Gateway, s.Transport, s.Loaded, s.Usable, s.AuthRequired, s.AuthConfigured, s.HasCustomHeaders, s.CustomHeadersSupported, s.CustomHeaderSecretsConfigured})
	}
	return out
}
func mcpUsability(server sdk.MCPServer) string {
	if !server.Usable {
		return "unusable"
	}
	if server.AuthRequired && !server.AuthConfigured {
		return "auth required"
	}
	return "usable"
}
