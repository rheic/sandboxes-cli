package command

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/term"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

const (
	runUsage = `usage: rsbx run [flags] [AGENT] [PATH...] [-- AGENT_ARGS...]

Create a local sandbox, start it, and attach to an agent. This command uses the
local Rheic daemon; cloud sandboxes and remote/OCI kits are not supported here.
The default workspace is the current directory. Pass additional workspace paths
after PATH; append :ro to make a workspace read-only. A single-file read-only
workspace is supported. Agent arguments after -- are passed to the agent.

Without --name, the sandbox name is <agent>-<workspace-basename>. An existing
sandbox with that name is reused: on a terminal, rsbx asks first; without a
terminal, it reuses automatically. --new always creates a fresh sandbox.
With --name, rsbx reuses and restarts that sandbox unless --new is also set.
With --detach, rsbx creates or starts the sandbox, prints its ID, and exits.
--rm removes the sandbox after the attached agent session exits.
--clone uses a read-only host Git source and a private in-guest clone. The
source must be the root of a Git repository with a .git directory.

Agents:
  kimi                      available (Rheic extension)
  claude, copilot, cursor, devin, docker-agent, droid, gemini, kiro, opencode
  codex, shell              preview (launchable; auth and live VM behavior not fully validated)
  dsh                       preview extension

Flags:
      --name NAME   sandbox name; reuse and restart it when it already exists
      --new         always create a new sandbox instead of reusing the named one
      --clone       run on a private in-guest clone of the host Git repository
  -d, --detach      create and start without attaching
      --image REF                 image reference override for a new sandbox
  -t, --template REF              container image for a new sandbox (alias for --image)
      --kit FILE                  apply a local kit definition
      --deny-write PATH           mount PATH read-only (repeatable)
  -p, --publish PORT_SPEC         publish a guest TCP/UDP port on host loopback
                                  repeatable; accepts [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6]
      --allow-network CIDR[:PORT] allow egress CIDR rule (repeatable; optional udp: prefix)
      --deny-network CIDR[:PORT]  deny egress CIDR rule (repeatable; optional udp: prefix)
      --policy-profile PROFILE    deny-all, balanced, or opt-in sbx-compat
      --docker                    run the dedicated Docker profile
      --cpus N                    CPUs for a new sandbox (0 selects the daemon default)
  -m, --memory SIZE               memory limit for a new sandbox, such as 512m or 2g
  -e, --env KEY=VALUE             environment override for the agent session (repeatable)
      --env-file FILE             read environment overrides from a file (repeatable)
      --rm                        remove the sandbox after the agent session exits
  -h, --help                      help for run

Examples:
  rsbx run shell
  rsbx run codex ./project /path/to/docs:ro
  rsbx run shell -- --version
  rsbx run --name dev-shell --detach shell
  rsbx run --new --name clean-shell --detach shell
`

	shellAgent        = "shell"
	shellPath         = "/bin/sh"
	helpCommand       = "help"
	helpFlag          = "--help"
	helpShort         = "-h"
	detachFlag        = "--detach"
	detachShort       = "-d"
	nameFlag          = "--name"
	newFlag           = "--new"
	imageFlag         = "--image"
	templateShort     = "-t"
	templateFlag      = "--template"
	kitFlag           = "--kit"
	denyWriteFlag     = "--deny-write"
	publishShort      = "-p"
	publishFlag       = "--publish"
	policyProfileFlag = "--policy-profile"
	dockerFlag        = "--docker"
	allowFlag         = "--allow-network"
	denyFlag          = "--deny-network"
	cpusFlag          = "--cpus"
	memoryFlag        = "--memory"
	memoryShort       = "-m"
	envFlag           = "--env"
	envShort          = "-e"
	envFileFlag       = "--env-file"
	removeFlag        = "--rm"

	formatFlag        = "--format"
	limitFlag         = "--limit"
	jsonFlag          = "--json"
	workdirFlag       = "--workdir"
	forceFlag         = "--force"
	globalFlag        = "--global"
	registryFlag      = "--registry"
	globalScopeLabel  = "(global)"
	userFlag          = "--user"
	commandFlag       = "--command"
	mcpCommand        = "mcp"
	mcpArgsFlagName   = "--args"
	quietLongFlag     = "--quiet"
	sandboxFlag       = "--sandbox"
	graceFlag         = "--grace"
	usernameFlag      = "--username"
	networkKeyword    = "network"
	sandboxPrefix     = "sandbox"
	startCommand      = "start"
	stopCommand       = "stop"
	secretCommand     = "secret"
	policyCommand     = "policy"
	completionCommand = "completion"
)

var errRunAgentRequired = errors.New("agent is required when --name is not set")

type runResources struct {
	cpus    uint32
	memory  uint32
	env     []string
	profile string
	ports   []sdk.Port
	allow   []sdk.NetworkRule
	deny    []sdk.NetworkRule
}

type runOptions struct {
	name             string
	new              bool
	image            string
	publish          []string
	allow            []string
	deny             []string
	profile          string
	privileged       bool
	kit              string
	denyWrite        []string
	cpus             uint
	memory           string
	env              []string
	oauthCredentials []sdk.OAuthCredential
	envFiles         []string
	detach           bool
	remove           bool
	clone            bool
	cloneSourcePath  string
	help             bool
}

// run creates or reuses a sandbox, starts it, and attaches an agent session.
func (r *Runner) run(ctx context.Context, args []string) int {
	head, agentArgs := splitAgentArgs(args)
	opts, positionals, err := parseRunArgs(head)
	if err != nil {
		if flagErr, ok := asUnknownRunFlag(err); ok {
			_, _ = fmt.Fprintf(r.Err, "error: unknown flag: --%s\n  try: rsbx run --help\n", strings.TrimLeft(flagErr.flag, "-"))
			return 1
		}
		_, _ = fmt.Fprintf(r.Err, "rsbx run: %v\n", err)
		_, _ = fmt.Fprint(r.Err, runUsage)
		return 2
	}
	if opts.help {
		_, _ = fmt.Fprint(r.Out, runUsage)
		return 0
	}
	agent, workspacePaths, workspacesExplicit, err := parseRunPositionals(positionals)
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx run: %v\n", err)
		return 2
	}
	workspacePaths, workspacesExplicit, err = prepareRunKitOptions(ctx, &opts, &agent, workspacePaths, workspacesExplicit)
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx run: %v\n", err)
		return 2
	}
	if err := prepareRunCloneSource(ctx, &opts, workspacePaths); err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx run: %v\n", err)
		return 2
	}
	if err := validateRunRequest(opts, agent); err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx run: %v\n", err)
		if errors.Is(err, errRunAgentRequired) {
			_, _ = fmt.Fprint(r.Err, runUsage)
		}
		return 2
	}
	applyAgentDefaults(agent, &opts.image, &opts.privileged)
	if len(opts.publish) == 0 {
		opts.publish = agentDefaultPorts(agent)
	}
	resources, err := prepareRunResources(opts)
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx run: %v\n", err)
		return 2
	}

	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	resources.env, err = prepareAgentCredentials(ctx, client, agent, opts.name, resources.env)
	if err != nil {
		r.error(err)
		return 1
	}

	sandbox, created, workspaces, err := r.reuseOrCreateSandbox(ctx, client, opts, agent, workspacePaths, workspacesExplicit, resources)
	if err != nil {
		r.error(err)
		return 1
	}
	return r.runAttached(ctx, client, opts, sandbox, created, agent, workspaces, workspacesExplicit, agentArgs, resources)
}

func resolveRunCloneSource(ctx context.Context, clone bool, paths []string) (string, error) {
	if !clone {
		return "", nil
	}
	workspaces, err := resolveWorkspaces(paths, true)
	if err != nil {
		return "", err
	}
	if len(workspaces) != 1 {
		return "", errors.New("--clone requires exactly one Git workspace path")
	}
	workspace, err := cloneWorkspaceForMount(ctx, workspaces[0])
	if err != nil {
		return "", err
	}
	return workspace.Path, nil
}

func prepareRunCloneSource(ctx context.Context, opts *runOptions, paths []string) error {
	path, err := resolveRunCloneSource(ctx, opts.clone, paths)
	if err != nil {
		return err
	}
	opts.cloneSourcePath = path
	return nil
}

func prepareRunKitOptions(ctx context.Context, opts *runOptions, agent *string, workspacePaths []string, workspacesExplicit bool) ([]string, bool, error) {
	if opts.kit != "" {
		if err := applyKit(ctx, opts.kit, agent, &opts.image, &opts.profile, &workspacePaths, &opts.env, &opts.oauthCredentials); err != nil {
			return nil, false, err
		}
		workspacesExplicit = true
	}
	for _, target := range opts.denyWrite {
		workspacePaths = append(workspacePaths, target+":ro")
		workspacesExplicit = true
	}
	return workspacePaths, workspacesExplicit, nil
}

func usesOpenAIOAuthReference(env []string) bool {
	for _, entry := range env {
		if entry == openAIOAuthEnvRef {
			return true
		}
	}
	return false
}

func ensureOpenAIOAuthLogin(ctx context.Context, client sdk.Client, env []string) error {
	if !usesOpenAIOAuthReference(env) {
		return nil
	}
	present, err := sdk.AccountStatus(client).Status(ctx, "openai")
	if err != nil {
		return fmt.Errorf("check OpenAI OAuth credentials: %w", err)
	}
	if present {
		return nil
	}
	if err := sdk.Accounts(client).Login(ctx, "openai"); err != nil {
		return fmt.Errorf("sign in to OpenAI before launching the kit: %w", err)
	}
	return nil
}

func prepareAgentCredentials(ctx context.Context, client sdk.Client, agent, sandboxName string, env []string) ([]string, error) {
	if usesOpenAIOAuthReference(env) {
		if err := ensureOpenAIOAuthLogin(ctx, client, env); err != nil {
			return nil, err
		}
		return env, nil
	}
	if agent == "opencode" || agent == "docker-agent" {
		return prepareMultiProviderCredentials(ctx, client, sandboxName, env)
	}
	if profile, ok := agentHostProxyProfile(agent); ok {
		return prepareFixedAgentCredentials(ctx, client, sandboxName, env, profile)
	}
	service, variable := agentCredentialContract(agent)
	if service == "" || hasEnvironmentKey(env, variable) || hasEnvironmentKey(env, agentCredentialBaseURL(agent)) {
		return env, nil
	}
	found, err := hasStoredAgentCredential(ctx, client, service, sandboxName)
	if err != nil {
		return nil, err
	}
	if found {
		return append(env, variable+"=${proxy:"+service+"}"), nil
	}
	if agent != codexAgentName {
		return env, nil
	}
	return prepareCodexOAuth(ctx, client, env)
}

type proxyRouteMarker struct {
	environment string
	service     string
}

type agentProxyProfile struct {
	service       string
	credentialEnv string
	conflicts     []string
	additional    []proxyRouteMarker
}

func agentHostProxyProfile(agent string) (agentProxyProfile, bool) {
	switch agent {
	case copilotAgentName:
		return agentProxyProfile{
			service: githubService, credentialEnv: ghTokenEnv, conflicts: []string{ghTokenEnv, githubTokenEnv},
			additional: []proxyRouteMarker{
				{environment: "RHEIC_PROXY_GITHUB_WEB", service: "github-web"},
				{environment: "RHEIC_PROXY_GITHUB_RAW", service: "github-raw"},
				{environment: "RHEIC_PROXY_GITHUB_GIST", service: "github-gist"},
				{environment: "RHEIC_PROXY_GITHUB_COPILOT", service: "github-copilot"},
				{environment: "RHEIC_PROXY_GITHUB_COPILOT_API", service: "github-copilot-api"},
			},
		}, true
	case "cursor":
		return agentProxyProfile{
			service: cursorService, credentialEnv: cursorAPIKeyEnv, conflicts: []string{cursorAPIKeyEnv},
			additional: []proxyRouteMarker{
				{environment: "RHEIC_PROXY_CURSOR_API3", service: "cursor-api3"},
				{environment: "RHEIC_PROXY_CURSOR_REPO42", service: "cursor-repo42"},
				{environment: "RHEIC_PROXY_CURSOR_WEB", service: "cursor-web"},
			},
		}, true
	case "droid":
		return agentProxyProfile{
			service: droidService, credentialEnv: factoryAPIKeyEnv, conflicts: []string{factoryAPIKeyEnv, droidAPIKeyEnv},
			additional: []proxyRouteMarker{
				{environment: "RHEIC_PROXY_DROID_APP", service: "droid-app"},
				{environment: "RHEIC_PROXY_DROID_RELAY", service: "droid-relay"},
			},
		}, true
	default:
		return agentProxyProfile{}, false
	}
}

func prepareFixedAgentCredentials(ctx context.Context, client sdk.Client, sandboxName string, env []string, profile agentProxyProfile) ([]string, error) {
	for _, key := range profile.conflicts {
		if hasEnvironmentKey(env, key) {
			return env, nil
		}
	}
	found, err := hasStoredAgentCredential(ctx, client, profile.service, sandboxName)
	if err != nil {
		return nil, err
	}
	if !found {
		return env, nil
	}
	env = append(env, profile.credentialEnv+"=${proxy:"+profile.service+"}")
	for _, marker := range profile.additional {
		env = append(env, marker.environment+"=${proxy:"+marker.service+"}")
	}
	return env, nil
}

type agentProviderCredential struct {
	service  string
	variable string
	baseURL  string
}

var multiProviderCredentials = []agentProviderCredential{
	{service: anthropicServiceName, variable: anthropicAPIKeyEnv, baseURL: anthropicBaseURLEnv},
	{service: googleService, variable: geminiAPIKeyEnv, baseURL: googleGeminiBaseURL},
	{service: openAIService, variable: openAIAPIKeyEnv, baseURL: openAIBaseURLEnv},
	{service: groqService, variable: "GROQ_API_KEY", baseURL: "GROQ_BASE_URL"},
	{service: mistralService, variable: "MISTRAL_API_KEY", baseURL: "MISTRAL_BASE_URL"},
	{service: openrouterService, variable: "OPENROUTER_API_KEY", baseURL: "OPENROUTER_BASE_URL"},
	{service: xaiService, variable: "XAI_API_KEY", baseURL: "XAI_BASE_URL"},
}

func prepareMultiProviderCredentials(ctx context.Context, client sdk.Client, sandboxName string, env []string) ([]string, error) {
	secrets, err := sdk.Secrets(client).List(ctx)
	if err != nil {
		return nil, fmt.Errorf("check stored multi-provider credentials: %w", err)
	}
	for _, provider := range multiProviderCredentials {
		if hasEnvironmentKey(env, provider.variable) || hasEnvironmentKey(env, provider.baseURL) {
			continue
		}
		for _, secret := range secrets {
			if secret.Service == provider.service && serviceSecretMatchesSandbox(secret, sandboxName) {
				env = append(env, provider.variable+"=${proxy:"+provider.service+"}")
				break
			}
		}
	}
	return env, nil
}

func serviceSecretMatchesSandbox(secret sdk.ServiceSecret, sandboxName string) bool {
	return secret.Scope == sdk.SecretScopeGlobal ||
		secret.Scope == sdk.SecretScopeSandbox && sandboxName != "" && secret.SandboxName == sandboxName
}

func hasStoredAgentCredential(ctx context.Context, client sdk.Client, service, sandboxName string) (bool, error) {
	secrets, err := sdk.Secrets(client).List(ctx)
	if err != nil {
		return false, fmt.Errorf("check stored %s credentials: %w", service, err)
	}
	for _, secret := range secrets {
		if secret.Service == service && (secret.Scope == sdk.SecretScopeGlobal || secret.Scope == sdk.SecretScopeSandbox && secret.SandboxName == sandboxName && sandboxName != "") {
			return true, nil
		}
	}
	return false, nil
}

func prepareCodexOAuth(ctx context.Context, client sdk.Client, env []string) ([]string, error) {
	present, err := sdk.AccountStatus(client).Status(ctx, "openai")
	if err != nil {
		return nil, fmt.Errorf("check OpenAI OAuth credentials: %w", err)
	}
	if !present {
		if err := sdk.Accounts(client).Login(ctx, "openai"); err != nil {
			return nil, fmt.Errorf("sign in to OpenAI before launching Codex: %w", err)
		}
	}
	return append(env, openAIOAuthEnvRef), nil
}

func agentCredentialContract(agent string) (service, variable string) {
	switch agent {
	case claudeAgentName:
		return anthropicServiceName, anthropicAPIKeyEnv
	case codexAgentName:
		return openAIService, openAIAPIKeyEnv
	case "gemini":
		return googleService, geminiAPIKeyEnv
	default:
		return "", ""
	}
}

func agentCredentialBaseURL(agent string) string {
	switch agent {
	case claudeAgentName:
		return anthropicBaseURLEnv
	case codexAgentName:
		return openAIBaseURLEnv
	case "gemini":
		return googleGeminiBaseURL
	default:
		return ""
	}
}

func hasEnvironmentKey(env []string, target string) bool {
	for _, entry := range env {
		key, _, found := strings.Cut(entry, "=")
		if found && key == target {
			return true
		}
	}
	return false
}

//nolint:gocognit,gocyclo,cyclop,nestif,gocritic,funlen // attach/terminal/detach semantics form one transaction.
func (r *Runner) runAttached(ctx context.Context, client sdk.Client, opts runOptions, sandbox *sdk.Sandbox, created bool, agent string, workspaces []sdk.Workspace, workspacesExplicit bool, agentArgs []string, resources runResources) int {
	if sandbox == nil || sandbox.ID == "" {
		r.error(errors.New("sandbox creation returned no sandbox"))
		return 1
	}
	if !created {
		if opts.clone && sandbox.Clone == nil {
			r.error(errors.New("sandbox does not have clone mode enabled; refusing to start the agent"))
			return 1
		}
		if opts.clone {
			if err := checkReusedCloneSource(sandbox, opts.cloneSourcePath); err != nil {
				r.error(err)
				return 1
			}
		}
		if err := checkReusedRun(sandbox, workspaces, workspacesExplicit, opts.clone); err != nil {
			r.error(err)
			return 1
		}
		r.warnReusedResources(sandbox, opts, resources)
	}
	if err := ensureSandboxRunning(ctx, client, sandbox); err != nil {
		r.error(err)
		return 1
	}
	cloneWorkdir := ""
	if opts.clone && sandbox.Clone == nil {
		err := errors.New("daemon did not return clone metadata; refusing to start the agent")
		r.error(err)
		if created {
			if cleanupErr := r.removeRunSandbox(ctx, client, sandbox); cleanupErr != nil {
				r.error(fmt.Errorf("remove unsupported clone sandbox: %w", cleanupErr))
			}
		}
		return 1
	}
	if sandbox.Clone != nil {
		fresh, err := client.Sandboxes().Get(ctx, sandbox.ID)
		if err != nil {
			r.error(err)
			return 1
		}
		cloneWorkdir, err = r.activateCloneSandbox(ctx, fresh, "")
		if err != nil {
			r.error(err)
			if created {
				if cleanupErr := r.removeRunSandbox(ctx, client, sandbox); cleanupErr != nil {
					r.error(fmt.Errorf("remove unsupported clone sandbox: %w", cleanupErr))
				}
			}
			return 1
		}
		sandbox = fresh
	}
	if opts.detach {
		if argv := agentDetachCommand(agent); len(argv) > 0 {
			code, err := sdk.ExecService(client).Exec(ctx, sdk.ExecRequest{
				SandboxID: sandbox.ID, Argv: argv, Workdir: cloneWorkdir, Env: resources.env, Stdout: r.Out, Stderr: r.Err,
			})
			if err != nil {
				r.error(fmt.Errorf("start detached agent: %w", err))
				return 1
			}
			if code != 0 {
				r.error(fmt.Errorf("start detached agent: exit status %d", code))
				return 1
			}
		}
		_, _ = fmt.Fprintln(r.Out, sandbox.ID)
		return 0
	}
	if agent == "" {
		agent = shellAgent
	}
	interactive, tty := runTerminal(r.In)
	closeOnEOF := true
	if !interactive && !tty {
		// The Docker sbx baseline stays attached with a non-terminal stdin
		// (for example /dev/null) instead of exiting on immediate EOF. Only
		// real files switch to that model; in-memory readers keep the
		// synchronous close so scripted use stays deterministic.
		if file, ok := r.In.(*os.File); ok {
			interactive = true
			closeOnEOF = fileClosesOnEOF(file)
		}
	}
	code := r.execSessionMode(ctx, client, sandbox.ID, runArgv(agent, agentArgs), execOptions{workdir: cloneWorkdir, env: resources.env}, interactive, tty, closeOnEOF)
	if opts.remove {
		if err := r.removeRunSandbox(ctx, client, sandbox); err != nil {
			r.error(err)
			return 1
		}
	}
	return code
}

func checkReusedCloneSource(sandbox *sdk.Sandbox, requested string) error {
	if sandbox == nil || sandbox.Clone == nil || requested == "" {
		return errors.New("sandbox clone source does not match the requested Git workspace; refusing to start the agent")
	}
	source, err := canonicalCloneSourcePath(cloneSourceWorkspaceFromSandbox(sandbox))
	if err != nil || source == "" || source != requested {
		return errors.New("sandbox clone source does not match the requested Git workspace; refusing to start the agent")
	}
	return nil
}

// fileClosesOnEOF reports whether a non-terminal stdin should close the
// session input at EOF: pipes and regular files are finite, character devices
// such as /dev/null are not.
func fileClosesOnEOF(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return true
	}
	return info.Mode().IsRegular() || info.Mode()&os.ModeNamedPipe != 0
}

func (r *Runner) removeRunSandbox(ctx context.Context, client sdk.Client, sandbox *sdk.Sandbox) error {
	current, err := client.Sandboxes().Get(ctx, sandbox.ID)
	if err != nil {
		return err
	}
	op, err := client.Sandboxes().Delete(ctx, sandbox.ID, sdk.DeleteOptions{Force: true})
	if err != nil {
		return err
	}
	if op != nil && op.State == sdk.StateFailed {
		return fmt.Errorf("remove sandbox %s failed: %s", sandbox.Name, op.Error)
	}
	return removeCloneRemoteForSandbox(ctx, current, r.gitConfigCommand())
}

//nolint:gocritic // runOptions is an immutable value object.
func prepareRunResources(opts runOptions) (runResources, error) {
	if opts.remove && opts.detach {
		return runResources{}, errors.New("--rm cannot be combined with --detach")
	}
	cpus, err := validateCPUs(opts.cpus)
	if err != nil {
		return runResources{}, err
	}
	memoryMiB, err := parseMemoryMiB(opts.memory)
	if err != nil {
		return runResources{}, err
	}
	ports, err := resolvePorts(opts.publish)
	if err != nil {
		return runResources{}, err
	}
	allow, err := resolveNetworkRules(opts.allow)
	if err != nil {
		return runResources{}, err
	}
	deny, err := resolveNetworkRules(opts.deny)
	if err != nil {
		return runResources{}, err
	}
	env, err := buildExecEnv(opts.env, opts.envFiles)
	if err != nil {
		return runResources{}, err
	}
	if err := validateOAuthProxyEnvironment(env); err != nil {
		return runResources{}, err
	}
	return runResources{cpus: cpus, memory: memoryMiB, env: env, profile: opts.profile, ports: ports, allow: allow, deny: deny}, nil
}

//nolint:gocritic // runOptions is an immutable value object.
func (r *Runner) warnReusedResources(sandbox *sdk.Sandbox, opts runOptions, resources runResources) {
	if resources.cpus != 0 || resources.memory != 0 {
		_, _ = fmt.Fprintf(r.Err, "warning: sandbox %s keeps its existing CPU/memory; sizing flags apply only to new sandboxes\n", sandbox.Name)
	}
	if len(opts.publish) > 0 {
		_, _ = fmt.Fprintf(r.Err, "warning: sandbox %s keeps its existing published ports; --publish applies only to new sandboxes\n", sandbox.Name)
	}
	if len(opts.allow) > 0 || len(opts.deny) > 0 || opts.profile != "" {
		_, _ = fmt.Fprintf(r.Err, "warning: sandbox %s keeps its existing network policy; policy flags apply only to new sandboxes\n", sandbox.Name)
	}
}

func splitAgentArgs(args []string) ([]string, []string) {
	for i, arg := range args {
		if arg == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func parseRunArgs(args []string) (runOptions, []string, error) {
	var opts runOptions
	positionals := make([]string, 0, 2)
	for i := 0; i < len(args); i++ {
		consumed, err := parseRunFlag(args, i, &opts)
		if err != nil {
			return opts, nil, err
		}
		if consumed == 0 {
			positionals = append(positionals, args[i])
			continue
		}
		i += consumed - 1
	}
	return opts, positionals, nil
}

func parseRunFlag(args []string, index int, opts *runOptions) (int, error) {
	arg := args[index]
	if consumed, handled, err := parseRunValueFlag(args, index, arg, opts); handled {
		return consumed, err
	}
	if consumed, handled, err := parseRunAssignmentFlag(arg, opts); handled {
		return consumed, err
	}
	if strings.HasPrefix(arg, "-") && arg != "-" {
		return 0, unknownRunFlagError{flag: arg}
	}
	return 0, nil
}

// unknownRunFlagError marks rejected run flags so the handler can print the
// shared unknown-flag contract instead of the full run usage block.
type unknownRunFlagError struct{ flag string }

func (e unknownRunFlagError) Error() string { return "unknown flag " + strconv.Quote(e.flag) }

func asUnknownRunFlag(err error) (unknownRunFlagError, bool) {
	var flagErr unknownRunFlagError
	if errors.As(err, &flagErr) {
		return flagErr, true
	}
	return unknownRunFlagError{}, false
}

func parseRunValueFlag(args []string, index int, arg string, opts *runOptions) (int, bool, error) {
	switch arg {
	case helpShort, helpFlag:
		opts.help = true
		return 1, true, nil
	case detachShort, detachFlag:
		opts.detach = true
		return 1, true, nil
	case removeFlag:
		opts.remove = true
		return 1, true, nil
	case "--clone":
		opts.clone = true
		return 1, true, nil
	case newFlag:
		opts.new = true
		return 1, true, nil
	}
	return parseRunValuedFlag(args, index, arg, opts)
}

func parseRunValuedFlag(args []string, index int, arg string, opts *runOptions) (int, bool, error) {
	switch arg {
	case nameFlag:
		consumed, err := parseRunValue(args, index, nameFlag, &opts.name)
		return consumed, true, err
	case imageFlag:
		consumed, err := parseRunValue(args, index, imageFlag, &opts.image)
		return consumed, true, err
	case templateShort, templateFlag:
		consumed, err := parseRunValue(args, index, templateFlag, &opts.image)
		return consumed, true, err
	case kitFlag:
		consumed, err := parseRunValue(args, index, kitFlag, &opts.kit)
		return consumed, true, err
	case denyWriteFlag:
		consumed, err := parseRunListValue(args, index, denyWriteFlag, &opts.denyWrite)
		return consumed, true, err
	case publishShort, publishFlag:
		consumed, err := parseRunListValue(args, index, publishFlag, &opts.publish)
		return consumed, true, err
	case allowFlag:
		consumed, err := parseRunListValue(args, index, allowFlag, &opts.allow)
		return consumed, true, err
	case policyProfileFlag:
		consumed, err := parseRunValue(args, index, policyProfileFlag, &opts.profile)
		return consumed, true, err
	case denyFlag:
		consumed, err := parseRunListValue(args, index, denyFlag, &opts.deny)
		return consumed, true, err
	case cpusFlag:
		consumed, err := parseRunUintValue(args, index, cpusFlag, &opts.cpus)
		return consumed, true, err
	case memoryShort, memoryFlag:
		consumed, err := parseRunValue(args, index, memoryFlag, &opts.memory)
		return consumed, true, err
	case envShort, envFlag:
		consumed, err := parseRunListValue(args, index, envFlag, &opts.env)
		return consumed, true, err
	case envFileFlag:
		consumed, err := parseRunListValue(args, index, envFileFlag, &opts.envFiles)
		return consumed, true, err
	default:
		return 0, false, nil
	}
}

func parseRunAssignmentFlag(arg string, opts *runOptions) (int, bool, error) {
	if value, ok := strings.CutPrefix(arg, nameFlag+"="); ok {
		consumed, err := setRunValue(nameFlag, value, &opts.name)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, imageFlag+"="); ok {
		consumed, err := setRunValue(imageFlag, value, &opts.image)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, templateFlag+"="); ok {
		consumed, err := setRunValue(templateFlag, value, &opts.image)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, kitFlag+"="); ok {
		consumed, err := setRunValue(kitFlag, value, &opts.kit)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, denyWriteFlag+"="); ok {
		consumed, err := appendRunListValue(denyWriteFlag, value, &opts.denyWrite)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, publishFlag+"="); ok {
		consumed, err := appendRunListValue(publishFlag, value, &opts.publish)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, allowFlag+"="); ok {
		consumed, err := appendRunListValue(allowFlag, value, &opts.allow)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, denyFlag+"="); ok {
		consumed, err := appendRunListValue(denyFlag, value, &opts.deny)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, cpusFlag+"="); ok {
		consumed, err := setRunUintValue(cpusFlag, value, &opts.cpus)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, memoryFlag+"="); ok {
		consumed, err := setRunValue(memoryFlag, value, &opts.memory)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, envFlag+"="); ok {
		consumed, err := appendRunListValue(envFlag, value, &opts.env)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, envFileFlag+"="); ok {
		consumed, err := appendRunListValue(envFileFlag, value, &opts.envFiles)
		return consumed, true, err
	}
	return 0, false, nil
}

func parseRunUintValue(args []string, index int, name string, target *uint) (int, error) {
	if index+1 >= len(args) {
		return 0, fmt.Errorf("%s requires a value", name)
	}
	if _, err := setRunUintValue(name, args[index+1], target); err != nil {
		return 0, err
	}
	return 2, nil
}

func setRunUintValue(name, value string, target *uint) (int, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s requires a non-negative integer", name)
	}
	*target = uint(parsed)
	return 1, nil
}

func parseRunListValue(args []string, index int, name string, target *[]string) (int, error) {
	if index+1 >= len(args) {
		return 0, fmt.Errorf("%s requires a non-empty value", name)
	}
	if _, err := appendRunListValue(name, args[index+1], target); err != nil {
		return 0, err
	}
	return 2, nil
}

func appendRunListValue(name, value string, target *[]string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("%s requires a non-empty value", name)
	}
	*target = append(*target, value)
	return 1, nil
}

func parseRunValue(args []string, index int, name string, target *string) (int, error) {
	if index+1 >= len(args) {
		return 0, fmt.Errorf("%s requires a non-empty value", name)
	}
	if _, err := setRunValue(name, args[index+1], target); err != nil {
		return 0, err
	}
	return 2, nil
}

func setRunValue(name, value string, target *string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("%s requires a non-empty value", name)
	}
	*target = value
	return 1, nil
}

func parseRunPositionals(positionals []string) (agent string, paths []string, explicit bool, err error) {
	if len(positionals) > 17 {
		return "", nil, false, errors.New("at most 16 workspaces are supported")
	}
	if len(positionals) == 0 {
		return "", nil, false, nil
	}
	agent = positionals[0]
	paths = positionals[1:]
	return agent, paths, len(paths) > 0, nil
}

//nolint:gocritic // runOptions is an immutable value object.
func validateRunRequest(opts runOptions, agent string) error {
	if agent != "" {
		return validateRunAgent(agent)
	}
	if opts.name == "" {
		return errRunAgentRequired
	}
	return nil
}

func validateRunAgent(name string) error {
	return validateAgent(name)
}

func isAgentName(value string) bool {
	registry, err := agentRegistry()
	if err != nil {
		return false
	}
	_, ok := registry.Lookup(value)
	return ok
}

func runArgv(name string, agentArgs []string) []string {
	defaults := agentCommandArgs(name)
	if len(agentArgs) == 0 {
		return defaults
	}
	if strings.HasPrefix(agentArgs[0], "-") {
		return append(defaults, agentArgs...)
	}
	return append([]string(nil), agentArgs...)
}

func runTerminal(input any) (interactive, tty bool) {
	file, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return false, false
	}
	return true, true
}

func checkReusedRun(sandbox *sdk.Sandbox, requested []sdk.Workspace, explicit, clone bool) error {
	if !explicit {
		return nil
	}
	return checkReusedWorkspaceMode(sandbox, requested, clone)
}

func checkReusedWorkspace(sandbox *sdk.Sandbox, requested []sdk.Workspace) error {
	return checkReusedWorkspaceMode(sandbox, requested, false)
}

func checkReusedWorkspaceMode(sandbox *sdk.Sandbox, requested []sdk.Workspace, clone bool) error {
	if len(requested) == 0 {
		return nil
	}
	existing := sandbox.Workspaces
	if len(existing) == 0 && sandbox.Workspace != "" {
		existing = []sdk.Workspace{{Path: sandbox.Workspace}}
	}
	if len(existing) != len(requested) || strings.Join(workspacePaths(existing), "\x00") != strings.Join(workspacePaths(requested), "\x00") {
		return fmt.Errorf("sandbox %s already uses workspaces %v; refusing to ignore %v", sandbox.Name, workspacePaths(existing), workspacePaths(requested))
	}
	for i := range existing {
		if !clone && existing[i].ReadOnly != requested[i].ReadOnly {
			return fmt.Errorf("sandbox %s already uses workspace modes %v; refusing to ignore %v", sandbox.Name, existing, requested)
		}
	}
	return nil
}

//nolint:gocritic // runOptions is an immutable value object.
func (r *Runner) reuseOrCreateSandbox(ctx context.Context, client sdk.Client, opts runOptions, agent string, paths []string, explicit bool, resources runResources) (*sdk.Sandbox, bool, []sdk.Workspace, error) {
	if opts.name != "" {
		reused, requested, found, err := r.reuseNamedRunSandbox(ctx, client, opts, paths, explicit)
		if err != nil || found {
			return reused, false, requested, err
		}
	} else if !opts.new {
		reused, found, err := r.findDerivedReuse(ctx, client, agent, paths)
		if err != nil || found {
			return reused, false, nil, err
		}
	}
	workspaces, err := resolveWorkspaces(paths, true)
	if err != nil {
		return nil, false, nil, err
	}
	created, owned, err := r.createRunSandbox(ctx, client, opts, agent, paths, workspaces, resources)
	return created, owned, workspaces, err
}

// reuseNamedRunSandbox reuses an existing sandbox selected by --name unless
// --new asks for a fresh one.
//
//nolint:gocritic // runOptions is an immutable value object.
func (r *Runner) reuseNamedRunSandbox(ctx context.Context, client sdk.Client, opts runOptions, paths []string, explicit bool) (*sdk.Sandbox, []sdk.Workspace, bool, error) {
	existing, requested, found, err := r.findRunReuse(ctx, client, opts.name, paths, explicit)
	if err != nil {
		return nil, nil, false, err
	}
	if found && !opts.new {
		return existing, requested, true, nil
	}
	return nil, nil, false, nil
}

// findDerivedReuse implements the Docker sbx baseline naming: a run without
// --name targets <agent>-<workspace-basename>. On a terminal the CLI asks
// before reusing it; without a terminal the existing sandbox is reused so
// scripts stay deterministic.
func (r *Runner) findDerivedReuse(ctx context.Context, client sdk.Client, agent string, paths []string) (*sdk.Sandbox, bool, error) {
	base := workspaceNameBase(paths)
	if base == "" {
		return nil, false, nil
	}
	prefix := agent
	if prefix == "" {
		prefix = sandboxPrefix
	}
	name := prefix + "-" + base
	if !validRunName(name) {
		return nil, false, nil
	}
	existing, found, err := lookupSandboxByName(ctx, client, name)
	if err != nil || !found {
		return nil, false, err
	}
	reuse, err := r.confirmRunReuse(existing)
	if err != nil {
		return nil, false, err
	}
	if !reuse {
		return nil, false, nil
	}
	return existing, true, nil
}

// confirmRunReuse prompts on a terminal; non-terminal input deterministically
// reuses the derived sandbox, matching the Docker sbx baseline attach model.
func (r *Runner) confirmRunReuse(sandbox *sdk.Sandbox) (bool, error) {
	file, ok := r.In.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return true, nil
	}
	if _, err := fmt.Fprintf(r.Err, "Reuse sandbox %s (%s, created %s)? [y/N] ", sandbox.Name, sandbox.State, formatAge(sandbox.CreatedAt)); err != nil {
		return false, fmt.Errorf("write reuse prompt: %w", err)
	}
	answer, err := bufio.NewReader(r.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read reuse confirmation: %w", err)
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == answerShortYes || answer == answerYes, nil
}

// workspaceNameBase derives a DNS-safe sandbox name base from the first
// workspace path, like the Docker sbx baseline shell-<workspace-basename>.
func workspaceNameBase(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	absolute, err := filepath.Abs(paths[0])
	if err != nil {
		return ""
	}
	return sanitizeNameBase(absolute)
}

// sanitizeNameBase maps a path basename to the DNS-safe sandbox name alphabet.
func sanitizeNameBase(absolute string) string {
	base := strings.ToLower(filepath.Base(absolute))
	var b strings.Builder
	b.Grow(len(base))
	for _, c := range base {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
			b.WriteRune(c)
		default:
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-.")
	if len(name) > 48 {
		name = strings.Trim(name[:48], "-.")
	}
	return name
}

func (r *Runner) findRunReuse(ctx context.Context, client sdk.Client, name string, paths []string, explicit bool) (*sdk.Sandbox, []sdk.Workspace, bool, error) {
	existing, found, err := lookupSandboxByName(ctx, client, name)
	if err != nil {
		return nil, nil, false, err
	}
	if !found {
		return nil, nil, false, nil
	}
	if !explicit {
		return existing, nil, true, nil
	}
	requested, err := resolveWorkspaces(paths, false)
	if err != nil {
		return nil, nil, false, err
	}
	return existing, requested, true, nil
}

//nolint:gocritic // runOptions is an immutable value object.
func (r *Runner) createRunSandbox(ctx context.Context, client sdk.Client, opts runOptions, agent string, paths []string, workspaces []sdk.Workspace, resources runResources) (*sdk.Sandbox, bool, error) {
	name, err := runSandboxName(ctx, client, opts.name, agent, workspaceNameBase(paths))
	if err != nil {
		return nil, false, err
	}
	workspace := ""
	if len(workspaces) > 0 {
		workspace = workspaces[0].Path
	}
	var cloneOptions *sdk.CloneOptions
	if opts.clone {
		if len(workspaces) != 1 {
			return nil, false, errors.New("--clone requires exactly one Git workspace path")
		}
		workspaces[0], err = cloneWorkspaceForMount(ctx, workspaces[0])
		if err != nil {
			return nil, false, err
		}
		workspace = workspaces[0].Path
		cloneOptions = &sdk.CloneOptions{SourceWorkspacePath: workspaces[0].Path}
	}
	op, err := client.Sandboxes().Create(ctx, sdk.CreateRequest{
		Name:             name,
		Image:            opts.image,
		Workspace:        workspace,
		Workspaces:       workspaces,
		Ports:            resources.ports,
		Allow:            resources.allow,
		Deny:             resources.deny,
		Agent:            agent,
		Detached:         opts.detach,
		CPUs:             resources.cpus,
		MemoryMiB:        resources.memory,
		PolicyProfile:    resources.profile,
		Privileged:       opts.privileged,
		Env:              envMap(resources.env),
		OAuthCredentials: opts.oauthCredentials,
		Clone:            cloneOptions,
	})
	if err != nil {
		return r.recoverRunCreate(ctx, client, opts, err)
	}
	if op == nil || op.SandboxID == "" {
		created, found, err := lookupSandboxByName(ctx, client, name)
		if err != nil {
			return nil, false, err
		}
		if !found {
			return nil, false, errors.New("sandbox creation returned no sandbox ID")
		}
		return created, false, nil
	}
	created, err := client.Sandboxes().Get(ctx, op.SandboxID)
	if err != nil {
		return nil, false, err
	}
	return created, op.Kind == "create", nil
}

//nolint:gocritic // runOptions is an immutable value object.
func (r *Runner) recoverRunCreate(ctx context.Context, client sdk.Client, opts runOptions, createErr error) (*sdk.Sandbox, bool, error) {
	if opts.name != "" && !opts.new {
		// A concurrent creator may have won the name; reuse only a sandbox
		// that the daemon now reports for the requested name.
		if existing, found, lookupErr := lookupSandboxByName(ctx, client, opts.name); lookupErr == nil && found {
			return existing, false, nil
		}
	}
	return nil, false, createErr
}

func ensureSandboxRunning(ctx context.Context, client sdk.Client, sandbox *sdk.Sandbox) error {
	switch sandbox.State {
	case sdk.StateRunning:
		return nil
	case sdk.StateStopped:
		op, err := client.Sandboxes().Start(ctx, sandbox.ID)
		if err != nil {
			return err
		}
		if op != nil && op.State == sdk.StateFailed {
			return fmt.Errorf("start sandbox %s failed: %s", sandbox.Name, op.Error)
		}
		return nil
	default:
		return fmt.Errorf("sandbox %s is %s; cannot attach", sandbox.Name, sandbox.State)
	}
}

func lookupSandboxByName(ctx context.Context, client sdk.Client, name string) (*sdk.Sandbox, bool, error) {
	seen := make(map[string]struct{})
	token := ""
	for pages := 0; pages < 10000; pages++ {
		page, err := client.Sandboxes().List(ctx, sdk.ListOptions{PageSize: 100, PageToken: token})
		if err != nil {
			return nil, false, err
		}
		for i := range page.Items {
			item := &page.Items[i]
			if item.Name == name || item.ID == name {
				return item, true, nil
			}
		}
		if page.NextPageToken == "" {
			return nil, false, nil
		}
		if _, exists := seen[page.NextPageToken]; exists {
			return nil, false, errors.New("invalid sandbox pagination")
		}
		seen[page.NextPageToken] = struct{}{}
		token = page.NextPageToken
	}
	return nil, false, errors.New("too many sandbox pages")
}

func runSandboxName(ctx context.Context, client sdk.Client, requested, agent, base string) (string, error) {
	if requested != "" {
		if !validRunName(requested) {
			return "", fmt.Errorf("invalid sandbox name %q", requested)
		}
		return requested, nil
	}
	if base != "" {
		name, err := derivedRunName(ctx, client, agent, base)
		if err != nil {
			return "", err
		}
		if name != "" {
			return name, nil
		}
	}
	return newRunName(ctx, client, agent)
}

// derivedRunName returns the Docker sbx baseline <agent>-<workspace> name when
// it is still free, or an empty string when it is taken or invalid.
func derivedRunName(ctx context.Context, client sdk.Client, agent, base string) (string, error) {
	prefix := agent
	if prefix == "" {
		prefix = sandboxPrefix
	}
	name := prefix + "-" + base
	if !validRunName(name) {
		return "", nil
	}
	_, found, err := lookupSandboxByName(ctx, client, name)
	if err != nil {
		return "", err
	}
	if found {
		return "", nil
	}
	return name, nil
}

func newRunName(ctx context.Context, client sdk.Client, agent string) (string, error) {
	prefix := agent
	if prefix == "" {
		prefix = sandboxPrefix
	}
	for attempt := 0; attempt < 5; attempt++ {
		var nonce [4]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", fmt.Errorf("generate sandbox name: %w", err)
		}
		name := prefix + "-" + hex.EncodeToString(nonce[:])
		_, found, err := lookupSandboxByName(ctx, client, name)
		if err != nil {
			return "", err
		}
		if !found {
			return name, nil
		}
	}
	return "", errors.New("could not allocate a unique sandbox name")
}

func validRunName(name string) bool {
	if name == "" || len(name) > 63 || name == "." || name == ".." {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			(c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}
