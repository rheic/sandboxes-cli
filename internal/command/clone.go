package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

const (
	cloneSourceGuestPath   = "/run/sandbox/source"
	cloneGitConfigMaxBytes = 1 << 20
)

var cloneRepositorySlugPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type gitConfigCommand func(context.Context, string, ...string) (string, error)

func (r *Runner) gitConfigCommand() gitConfigCommand {
	if r.gitConfig != nil {
		return r.gitConfig
	}
	return runGitConfig
}

func runGitConfig(ctx context.Context, configPath string, args ...string) (string, error) {
	commandArgs := make([]string, 0, len(args)+4)
	commandArgs = append(commandArgs, "config", "--no-includes", "--file", configPath)
	commandArgs = append(commandArgs, args...)
	//nolint:gosec // fixed Git executable with structured config arguments, never shell text.
	cmd := exec.CommandContext(ctx, "git", commandArgs...)
	cmd.Env = safeGitEnvironment()
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(output), "\n"), nil
}

func cloneWorkspaceForMount(ctx context.Context, workspace sdk.Workspace) (sdk.Workspace, error) {
	root, err := filepath.Abs(workspace.Path)
	if err != nil {
		return sdk.Workspace{}, fmt.Errorf("resolve clone source workspace: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return sdk.Workspace{}, fmt.Errorf("resolve clone source workspace: %w", err)
	}
	root = filepath.Clean(root)
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		if err == nil {
			err = errors.New("not a directory")
		}
		return sdk.Workspace{}, fmt.Errorf("clone source workspace: %w", err)
	}
	gitPath := filepath.Join(root, ".git")
	gitInfo, err := os.Lstat(gitPath)
	if err != nil {
		return sdk.Workspace{}, errors.New("clone mode requires a Git repository with a .git directory at the workspace root")
	}
	if gitInfo.Mode()&os.ModeSymlink != 0 || !gitInfo.IsDir() {
		return sdk.Workspace{}, errors.New("clone mode requires a repository root with a .git directory; linked worktrees with a .git file are unsupported")
	}
	//nolint:gosec // fixed Git executable; root is passed as a single argv value.
	cmd := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "--show-toplevel")
	cmd.Env = safeGitEnvironment()
	output, err := cmd.Output()
	if err != nil {
		return sdk.Workspace{}, errors.New("clone source is not a valid Git worktree root")
	}
	gitRoot := strings.TrimSpace(string(output))
	gitRoot, err = filepath.Abs(gitRoot)
	if err != nil || filepath.Clean(gitRoot) != root {
		return sdk.Workspace{}, errors.New("clone source path must be the Git repository root")
	}
	configPath := filepath.Join(gitPath, "config")
	configInfo, err := os.Lstat(configPath)
	if err != nil || !configInfo.Mode().IsRegular() {
		return sdk.Workspace{}, errors.New("clone source has no regular .git/config file")
	}
	return sdk.Workspace{Path: root, ReadOnly: true, GuestPath: cloneSourceGuestPath}, nil
}

func validateCloneInfo(sb *sdk.Sandbox) (string, string, error) {
	if sb == nil || sb.Clone == nil {
		return "", "", errors.New("daemon did not return clone metadata; refusing to continue without clone isolation")
	}
	clone := sb.Clone
	expectedRemote := "sandbox-" + sb.Name
	if clone.RemoteName != expectedRemote || !validCloneRemoteName(clone.RemoteName) {
		return "", "", errors.New("daemon returned an invalid clone remote name")
	}
	if err := validateCloneGuestWorkdir(clone.GuestWorkdir); err != nil {
		return "", "", err
	}
	url, err := cloneEndpointURL(clone.GitEndpoint)
	if err != nil {
		return "", "", err
	}
	return clone.GuestWorkdir, url, nil
}

func validateCloneGuestWorkdir(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return errors.New("daemon returned an invalid clone guest workdir")
	}
	return nil
}

func cloneEndpointURL(endpoint *sdk.GitEndpoint) (string, error) {
	if endpoint == nil {
		return "", errors.New("daemon did not publish a clone Git endpoint; refusing to continue")
	}
	if endpoint.HostIP != loopbackHost || net.ParseIP(endpoint.HostIP) == nil || endpoint.Port == 0 || endpoint.Port > 65535 || !cloneRepositorySlugPattern.MatchString(endpoint.Repository) || endpoint.Repository == "." || endpoint.Repository == ".." {
		return "", errors.New("daemon returned an unsafe clone Git endpoint")
	}
	url := "git://" + net.JoinHostPort(endpoint.HostIP, strconv.FormatUint(uint64(endpoint.Port), 10)) + "/" + endpoint.Repository
	return url, nil
}

func (r *Runner) activateCloneSandbox(ctx context.Context, sb *sdk.Sandbox, source string) (string, error) {
	workdir, url, err := validateCloneInfo(sb)
	if err != nil {
		return "", err
	}
	if source == "" {
		source = cloneSourceWorkspaceFromSandbox(sb)
	}
	if source == "" {
		return "", errors.New("daemon clone response has no host source workspace")
	}
	workspace, err := cloneWorkspaceForMount(ctx, sdk.Workspace{Path: source})
	if err != nil {
		return "", err
	}
	if err := reconcileCloneRemote(ctx, workspace.Path, sb.Clone.RemoteName, sb.ID, url, r.gitConfigCommand()); err != nil {
		return "", err
	}
	return workdir, nil
}

func cloneSourceWorkspaceFromSandbox(sb *sdk.Sandbox) string {
	if sb == nil {
		return ""
	}
	for _, workspace := range sb.Workspaces {
		if workspace.GuestPath == cloneSourceGuestPath {
			return workspace.Path
		}
	}
	if sb.Workspace != "" {
		return sb.Workspace
	}
	if len(sb.Workspaces) == 1 {
		return sb.Workspaces[0].Path
	}
	return ""
}

func canonicalCloneSourcePath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve clone source path: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve clone source path: %w", err)
	}
	return filepath.Clean(canonical), nil
}

func (r *Runner) reconcileCloneLifecycle(ctx context.Context, client sdk.Client, id string, active bool) error {
	sb, err := client.Sandboxes().Get(ctx, id)
	if err != nil {
		return err
	}
	if sb.Clone == nil {
		return nil
	}
	if active {
		_, err := r.activateCloneSandbox(ctx, sb, "")
		return err
	}
	// Keep the remote while stopped. Its loopback endpoint is refreshed after
	// the next successful start/reattach, and user edits remain untouched.
	return nil
}

func removeCloneRemoteForSandbox(ctx context.Context, sb *sdk.Sandbox, run gitConfigCommand) error {
	if sb == nil || sb.Clone == nil {
		return nil
	}
	remote := sb.Clone.RemoteName
	if remote != "sandbox-"+sb.Name || !validCloneRemoteName(remote) {
		return errors.New("daemon returned an invalid clone remote name")
	}
	workspacePath := cloneSourceWorkspaceFromSandbox(sb)
	if workspacePath == "" {
		return errors.New("daemon clone response has no host source workspace")
	}
	workspace, err := cloneWorkspaceForMount(ctx, sdk.Workspace{Path: workspacePath})
	if err != nil {
		return err
	}
	return removeCloneRemote(ctx, workspace.Path, remote, sb.ID, run)
}

func cleanupCloneSandbox(ctx context.Context, client sdk.Client, op *sdk.Operation, sandbox *sdk.Sandbox, run gitConfigCommand) error {
	if op == nil || op.Kind != "create" {
		return errors.New("cannot clean up clone sandbox because create operation did not prove ownership")
	}
	id := opSandboxID(op)
	if id == "" {
		return errors.New("cannot clean up clone sandbox because create operation did not prove ownership")
	}
	deleteOp, err := client.Sandboxes().Delete(ctx, id, sdk.DeleteOptions{Force: true})
	if err != nil {
		return fmt.Errorf("delete partially activated clone sandbox %s: %w", id, err)
	}
	if deleteOp != nil && deleteOp.State == sdk.StateFailed {
		return fmt.Errorf("delete partially activated clone sandbox %s failed: %s", id, deleteOp.Error)
	}
	if sandbox != nil {
		if sandbox.ID != id {
			return errors.New("deleted clone sandbox ID did not match the operation-owned sandbox")
		}
		return removeCloneRemoteForSandbox(ctx, sandbox, run)
	}
	return nil
}

func safeGitEnvironment() []string {
	env := make([]string, 0, len(os.Environ())+3)
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if strings.HasPrefix(strings.ToUpper(key), "GIT_") {
			continue
		}
		env = append(env, item)
	}
	return append(env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_TERMINAL_PROMPT=0")
}

func opSandboxID(op *sdk.Operation) string {
	if op == nil {
		return ""
	}
	return op.SandboxID
}

func validCloneRemoteName(value string) bool {
	if !strings.HasPrefix(value, "sandbox-") || len(value) > 200 || value == "sandbox-" {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && char != '-' && char != '_' && char != '.' {
			return false
		}
	}
	return !strings.HasSuffix(value, ".") && !strings.Contains(value, "..")
}

func cloneConfigKey(remote, key string) string {
	return "remote." + remote + "." + key
}

func gitConfigGet(ctx context.Context, configPath, key string, run gitConfigCommand) (string, bool, error) {
	output, err := run(ctx, configPath, "--get-all", key)
	if err == nil {
		values := strings.Split(output, "\n")
		if len(values) != 1 {
			return "", false, fmt.Errorf("local Git config key %q has duplicate values; preserving it", key)
		}
		return values[0], true, nil
	}
	var exitErr interface{ ExitCode() int }
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return "", false, nil
	}
	return "", false, fmt.Errorf("read local Git config: %w", err)
}

func gitRemoteExists(ctx context.Context, configPath, remote string, run gitConfigCommand) (bool, error) {
	output, err := run(ctx, configPath, "--get-regexp", `^remote\.`+regexp.QuoteMeta(remote)+`\.`)
	if err == nil {
		allowed := map[string]bool{
			cloneConfigKey(remote, "url"):              true,
			cloneConfigKey(remote, "rheic-managed-by"): true,
			cloneConfigKey(remote, "rheic-last-url"):   true,
		}
		for _, line := range strings.Split(output, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || !allowed[fields[0]] {
				return true, fmt.Errorf("git remote %q has user configuration; preserving it", remote)
			}
		}
		return true, nil
	}
	var exitErr interface{ ExitCode() int }
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("inspect local Git remote: %w", err)
}

func setGitConfig(ctx context.Context, configPath, key, value string, run gitConfigCommand) error {
	if _, err := run(ctx, configPath, "--replace-all", key, value); err != nil {
		return fmt.Errorf("update local Git remote: %w", err)
	}
	return nil
}

func unsetGitConfig(ctx context.Context, configPath, key string, run gitConfigCommand) error {
	if _, err := run(ctx, configPath, "--unset-all", key); err != nil {
		return fmt.Errorf("remove local Git remote metadata: %w", err)
	}
	return nil
}

func reconcileCloneRemote(ctx context.Context, workspace, remote, sandboxID, url string, run gitConfigCommand) error {
	configPath, gitDirInfo, err := cloneGitConfigPath(workspace)
	if err != nil {
		return err
	}
	return withGitConfigLock(configPath, gitDirInfo, func(lockedConfig string) error {
		return reconcileCloneRemoteLocked(ctx, lockedConfig, remote, sandboxID, url, run)
	})
}

func reconcileCloneRemoteLocked(ctx context.Context, configPath, remote, sandboxID, url string, run gitConfigCommand) error {
	exists, err := gitRemoteExists(ctx, configPath, remote, run)
	if err != nil {
		return err
	}
	if !exists {
		return createCloneRemote(ctx, configPath, remote, sandboxID, url, run)
	}
	return updateCloneRemote(ctx, configPath, remote, sandboxID, url, run)
}

func createCloneRemote(ctx context.Context, configPath, remote, sandboxID, url string, run gitConfigCommand) error {
	if err := setGitConfig(ctx, configPath, cloneConfigKey(remote, "rheic-managed-by"), sandboxID, run); err != nil {
		return err
	}
	if err := setGitConfig(ctx, configPath, cloneConfigKey(remote, "rheic-last-url"), url, run); err != nil {
		return err
	}
	return setGitConfig(ctx, configPath, cloneConfigKey(remote, "url"), url, run)
}

func updateCloneRemote(ctx context.Context, configPath, remote, sandboxID, url string, run gitConfigCommand) error {
	ownership, err := loadCloneRemoteOwnership(ctx, configPath, remote, run)
	if err != nil {
		return err
	}
	if !ownership.hasOwner || ownership.owner != sandboxID || !ownership.hasLastURL || (ownership.hasURL && ownership.currentURL != ownership.lastURL) || (!ownership.hasURL && ownership.lastURL != "") {
		return fmt.Errorf("git remote %q is not owned by this sandbox or was changed; preserving it", remote)
	}
	if ownership.currentURL != url || !ownership.hasURL {
		if err := setGitConfig(ctx, configPath, cloneConfigKey(remote, "url"), url, run); err != nil {
			return err
		}
		if err := setGitConfig(ctx, configPath, cloneConfigKey(remote, "rheic-last-url"), url, run); err != nil {
			return err
		}
	}
	return nil
}

func removeCloneRemote(ctx context.Context, workspace, remote, sandboxID string, run gitConfigCommand) error {
	configPath, gitDirInfo, err := cloneGitConfigPath(workspace)
	if err != nil {
		return err
	}
	return withGitConfigLock(configPath, gitDirInfo, func(lockedConfig string) error {
		return removeCloneRemoteLocked(ctx, lockedConfig, remote, sandboxID, run)
	})
}

func removeCloneRemoteLocked(ctx context.Context, configPath, remote, sandboxID string, run gitConfigCommand) error {
	exists, err := gitRemoteExists(ctx, configPath, remote, run)
	if err != nil || !exists {
		return err
	}
	ownership, err := loadCloneRemoteOwnership(ctx, configPath, remote, run)
	if err != nil {
		return err
	}
	if !ownership.hasOwner || ownership.owner != sandboxID || (ownership.hasURL && (!ownership.hasLastURL || ownership.currentURL != ownership.lastURL)) {
		return fmt.Errorf("git remote %q was changed or is not owned by this sandbox; preserving it", remote)
	}
	if ownership.hasURL {
		if err := unsetGitConfig(ctx, configPath, cloneConfigKey(remote, "url"), run); err != nil {
			return err
		}
	}
	if ownership.hasLastURL {
		if err := unsetGitConfig(ctx, configPath, cloneConfigKey(remote, "rheic-last-url"), run); err != nil {
			return err
		}
	}
	return unsetGitConfig(ctx, configPath, cloneConfigKey(remote, "rheic-managed-by"), run)
}

type cloneRemoteOwnership struct {
	owner      string
	lastURL    string
	currentURL string
	hasOwner   bool
	hasLastURL bool
	hasURL     bool
}

func loadCloneRemoteOwnership(ctx context.Context, configPath, remote string, run gitConfigCommand) (cloneRemoteOwnership, error) {
	owner, hasOwner, err := gitConfigGet(ctx, configPath, cloneConfigKey(remote, "rheic-managed-by"), run)
	if err != nil {
		return cloneRemoteOwnership{}, err
	}
	lastURL, hasLastURL, err := gitConfigGet(ctx, configPath, cloneConfigKey(remote, "rheic-last-url"), run)
	if err != nil {
		return cloneRemoteOwnership{}, err
	}
	currentURL, hasURL, err := gitConfigGet(ctx, configPath, cloneConfigKey(remote, "url"), run)
	if err != nil {
		return cloneRemoteOwnership{}, err
	}
	return cloneRemoteOwnership{owner: owner, hasOwner: hasOwner, lastURL: lastURL, hasLastURL: hasLastURL, currentURL: currentURL, hasURL: hasURL}, nil
}

func withGitConfigLock(configPath string, expectedGitDir os.FileInfo, mutate func(string) error) error {
	workspacePath := filepath.Dir(filepath.Dir(configPath))
	workspaceRoot, err := os.OpenRoot(workspacePath)
	if err != nil {
		return fmt.Errorf("open clone workspace root: %w", err)
	}
	defer func() { _ = workspaceRoot.Close() }()
	currentGitDir, err := workspaceRoot.Lstat(".git")
	if err != nil {
		return fmt.Errorf("inspect clone Git directory: %w", err)
	}
	if currentGitDir.Mode()&os.ModeSymlink != 0 || !os.SameFile(expectedGitDir, currentGitDir) {
		return errors.New("clone Git config directory changed during remote validation; preserving it")
	}
	gitDir, err := workspaceRoot.OpenRoot(".git")
	if err != nil {
		return fmt.Errorf("open local Git config directory: %w", err)
	}
	defer func() { _ = gitDir.Close() }()
	openedGitDir, err := gitDir.Stat(".")
	if err != nil || !os.SameFile(expectedGitDir, openedGitDir) {
		return errors.New("clone Git config directory changed during remote validation; preserving it")
	}
	info, err := gitDir.Lstat("config")
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("clone Git config is not a regular file")
	}
	lock, lockInfo, err := acquireGitConfigLock(gitDir, info.Mode().Perm())
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = lock.Close()
		if !committed {
			removeOwnedGitConfigLock(gitDir, lockInfo)
		}
	}()
	return mutateAndCommitGitConfig(workspaceRoot, gitDir, expectedGitDir, info, lock, lockInfo, &committed, mutate)
}

func mutateAndCommitGitConfig(workspaceRoot, gitDir *os.Root, expectedGitDir, configInfo os.FileInfo, lock *os.File, lockInfo os.FileInfo, committed *bool, mutate func(string) error) error {
	originalBytes, err := readRootGitConfig(gitDir, "config")
	if err != nil {
		return err
	}
	temporaryPath, cleanup, err := createTemporaryGitConfig("", originalBytes)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := mutate(temporaryPath); err != nil {
		return err
	}
	updatedBytes, err := readGitConfigFile(temporaryPath)
	if err != nil {
		return err
	}
	if err := writeGitConfigLock(lock, configInfo.Mode().Perm(), updatedBytes); err != nil {
		return err
	}
	return commitGitConfigUpdate(workspaceRoot, gitDir, expectedGitDir, configInfo, originalBytes, lockInfo, committed)
}

func commitGitConfigUpdate(workspaceRoot, gitDir *os.Root, expectedGitDir, configInfo os.FileInfo, originalBytes []byte, lockInfo os.FileInfo, committed *bool) error {
	lockPathInfo, err := gitDir.Lstat("config.lock")
	if err != nil || !os.SameFile(lockInfo, lockPathInfo) {
		return errors.New("local Git config lock was replaced during clone remote update; preserving it")
	}
	currentGitDir, err := workspaceRoot.Lstat(".git")
	if err != nil || currentGitDir.Mode()&os.ModeSymlink != 0 || !os.SameFile(expectedGitDir, currentGitDir) {
		return errors.New("clone Git config directory changed during remote update; preserving it")
	}
	currentConfig, err := gitDir.Lstat("config")
	if err != nil || currentConfig.Mode()&os.ModeSymlink != 0 || !os.SameFile(configInfo, currentConfig) {
		return errors.New("local Git config file was replaced during clone remote update; preserving it")
	}
	if err := verifyUnchangedRootGitConfig(gitDir, configInfo, originalBytes); err != nil {
		return err
	}
	if err := gitDir.Rename("config.lock", "config"); err != nil {
		return fmt.Errorf("commit local Git config update: %w", err)
	}
	*committed = true
	return syncGitConfigDirectory(gitDir)
}

func acquireGitConfigLock(gitDir *os.Root, mode os.FileMode) (*os.File, os.FileInfo, error) {
	lock, err := gitDir.OpenFile("config.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return nil, nil, fmt.Errorf("lock local Git config: %w", err)
	}
	info, err := lock.Stat()
	if err != nil {
		_ = lock.Close()
		_ = gitDir.Remove("config.lock")
		return nil, nil, fmt.Errorf("inspect local Git config lock: %w", err)
	}
	return lock, info, nil
}

func removeOwnedGitConfigLock(gitDir *os.Root, owned os.FileInfo) {
	if current, err := gitDir.Lstat("config.lock"); err == nil && os.SameFile(owned, current) {
		_ = gitDir.Remove("config.lock")
	}
}

//nolint:gosec // path comes only from os.CreateTemp in the current user's temporary directory.
func readGitConfigFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read local Git config: %w", err)
	}
	defer func() { _ = file.Close() }()
	contents, err := io.ReadAll(io.LimitReader(file, cloneGitConfigMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read local Git config: %w", err)
	}
	if len(contents) > cloneGitConfigMaxBytes {
		return nil, errors.New("local Git config exceeds the 1 MiB clone safety limit")
	}
	return contents, nil
}

func readRootGitConfig(root *os.Root, name string) ([]byte, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("read local Git config: %w", err)
	}
	defer func() { _ = file.Close() }()
	contents, err := io.ReadAll(io.LimitReader(file, cloneGitConfigMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read local Git config: %w", err)
	}
	if len(contents) > cloneGitConfigMaxBytes {
		return nil, errors.New("local Git config exceeds the 1 MiB clone safety limit")
	}
	return contents, nil
}

func createTemporaryGitConfig(directory string, contents []byte) (string, func(), error) {
	temporary, err := os.CreateTemp(directory, ".rheic-config-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temporary Git config: %w", err)
	}
	path := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(path)
		_ = os.Remove(path + ".lock")
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("restrict temporary Git config permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("copy local Git config: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("sync temporary Git config: %w", err)
	}
	if err := temporary.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("close temporary Git config: %w", err)
	}
	return path, cleanup, nil
}

func verifyUnchangedRootGitConfig(root *os.Root, beforeInfo os.FileInfo, before []byte) error {
	info, err := root.Lstat("config")
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(beforeInfo, info) {
		return errors.New("local Git config file was replaced during clone remote update; preserving it")
	}
	after, err := readRootGitConfig(root, "config")
	if err != nil {
		return fmt.Errorf("recheck local Git config before commit: %w", err)
	}
	if !bytes.Equal(before, after) {
		return errors.New("local Git config changed during clone remote update; preserving it")
	}
	return nil
}

func writeGitConfigLock(lock *os.File, mode os.FileMode, contents []byte) error {
	if err := lock.Truncate(0); err != nil {
		return fmt.Errorf("prepare local Git config lock: %w", err)
	}
	if _, err := lock.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek local Git config lock: %w", err)
	}
	if _, err := lock.Write(contents); err != nil {
		return fmt.Errorf("write local Git config lock: %w", err)
	}
	if err := lock.Chmod(mode); err != nil {
		return fmt.Errorf("preserve local Git config permissions: %w", err)
	}
	if err := lock.Sync(); err != nil {
		return fmt.Errorf("sync local Git config lock: %w", err)
	}
	return nil
}

func syncGitConfigDirectory(directory *os.Root) error {
	directoryFile, err := directory.Open(".")
	if err != nil {
		return fmt.Errorf("open local Git config directory for sync: %w", err)
	}
	if err := directoryFile.Sync(); err != nil {
		_ = directoryFile.Close()
		return fmt.Errorf("sync local Git config directory: %w", err)
	}
	if err := directoryFile.Close(); err != nil {
		return fmt.Errorf("close local Git config directory: %w", err)
	}
	return nil
}

func cloneGitConfigPath(workspace string) (string, os.FileInfo, error) {
	workspacePath, err := filepath.Abs(workspace)
	if err != nil {
		return "", nil, err
	}
	workspaceRoot, err := os.OpenRoot(filepath.Clean(workspacePath))
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = workspaceRoot.Close() }()
	gitDirInfo, err := workspaceRoot.Lstat(".git")
	if err != nil || gitDirInfo.Mode()&os.ModeSymlink != 0 || !gitDirInfo.IsDir() {
		return "", nil, errors.New("clone Git remote requires a repository root with a .git directory")
	}
	gitDir, err := workspaceRoot.OpenRoot(".git")
	if err != nil {
		return "", nil, errors.New("clone Git remote requires a repository root with a .git directory")
	}
	defer func() { _ = gitDir.Close() }()
	openedGitDir, err := gitDir.Stat(".")
	if err != nil || !os.SameFile(gitDirInfo, openedGitDir) {
		return "", nil, errors.New("clone Git directory changed during remote validation")
	}
	configInfo, err := gitDir.Lstat("config")
	if err != nil || configInfo.Mode()&os.ModeSymlink != 0 || !configInfo.Mode().IsRegular() {
		return "", nil, errors.New("clone Git remote requires a regular .git/config file")
	}
	gitPath := filepath.Join(filepath.Clean(workspacePath), ".git")
	return filepath.Join(gitPath, "config"), gitDirInfo, nil
}
