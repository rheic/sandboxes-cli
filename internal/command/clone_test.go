package command

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func TestValidateCloneInfo(t *testing.T) {
	t.Parallel()
	sb := &sdk.Sandbox{
		ID: "id-1", Name: "demo",
		Clone: &sdk.CloneInfo{
			RemoteName: "sandbox-demo", GuestWorkdir: "/workspace/demo",
			GitEndpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 4321, Repository: "demo.git"},
		},
	}
	workdir, url, err := validateCloneInfo(sb)
	if err != nil || workdir != "/workspace/demo" || url != "git://127.0.0.1:4321/demo.git" {
		t.Fatalf("validateCloneInfo() = %q, %q, %v", workdir, url, err)
	}
	badCases := []*sdk.Sandbox{
		{ID: "x", Name: "demo"},
		{ID: "x", Name: "demo", Clone: &sdk.CloneInfo{RemoteName: "origin", GuestWorkdir: "/workspace", GitEndpoint: sb.Clone.GitEndpoint}},
		{ID: "x", Name: "demo", Clone: &sdk.CloneInfo{RemoteName: "sandbox-demo", GuestWorkdir: "/workspace/../etc", GitEndpoint: sb.Clone.GitEndpoint}},
		{ID: "x", Name: "demo", Clone: &sdk.CloneInfo{RemoteName: "sandbox-demo", GuestWorkdir: "/workspace", GitEndpoint: &sdk.GitEndpoint{HostIP: "0.0.0.0", Port: 1, Repository: "repo"}}},
		{ID: "x", Name: "demo", Clone: &sdk.CloneInfo{RemoteName: "sandbox-demo", GuestWorkdir: "/workspace", GitEndpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 0, Repository: "repo"}}},
		{ID: "x", Name: "demo", Clone: &sdk.CloneInfo{RemoteName: "sandbox-demo", GuestWorkdir: "/workspace", GitEndpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 1, Repository: "../repo"}}},
	}
	for i, bad := range badCases {
		if _, _, err := validateCloneInfo(bad); err == nil {
			t.Errorf("case %d unexpectedly validated", i)
		}
	}
}

func TestReusedCloneRequiresMatchingSource(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	canonical, err := canonicalCloneSourcePath(root)
	if err != nil {
		t.Fatal(err)
	}
	sandbox := &sdk.Sandbox{
		ID: "id-1", Name: "demo", Workspace: canonical,
		Clone: &sdk.CloneInfo{RemoteName: "sandbox-demo", GuestWorkdir: "/workspace/demo"},
	}
	if err := checkReusedCloneSource(sandbox, canonical); err != nil {
		t.Fatalf("matching source rejected: %v", err)
	}
	if err := checkReusedCloneSource(sandbox, canonical+"-other"); err == nil {
		t.Fatal("mismatched source accepted")
	}
}

func TestCloneWorkspaceRejectsWorktreeGitFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: /tmp/elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cloneWorkspaceForMount(context.Background(), sdk.Workspace{Path: root}); err == nil || !strings.Contains(err.Error(), ".git directory") {
		t.Fatalf("expected .git file rejection, got %v", err)
	}
}

func TestSafeGitEnvironmentDropsInheritedGitOverrides(t *testing.T) {
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "remote.origin.url")
	t.Setenv("GIT_CONFIG_VALUE_0", "https://attacker.invalid/repo")
	t.Setenv("GIT_DIR", "/tmp/attacker.git")
	for _, item := range safeGitEnvironment() {
		key, _, _ := strings.Cut(item, "=")
		if strings.HasPrefix(strings.ToUpper(key), "GIT_") && key != "GIT_CONFIG_NOSYSTEM" && key != "GIT_CONFIG_GLOBAL" && key != "GIT_TERMINAL_PROMPT" {
			t.Errorf("unsafe inherited Git environment variable remains: %s", key)
		}
	}
}

func TestReconcileCloneRemoteOwnershipAndDuplicateProtection(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	cfg := filepath.Join(root, ".git", "config")
	ctx := context.Background()
	remote := "sandbox-demo"
	first := "git://127.0.0.1:1234/demo.git"
	second := "git://127.0.0.1:5678/demo.git"
	if err := reconcileCloneRemote(ctx, root, remote, "sandbox-id", first, runGitConfig); err != nil {
		t.Fatal(err)
	}
	if err := reconcileCloneRemote(ctx, root, remote, "sandbox-id", second, runGitConfig); err != nil {
		t.Fatal(err)
	}
	if err := gitConfigSet(t, cfg, "--add", "remote.sandbox-demo.url", "git://user-edit.invalid/demo.git"); err != nil {
		t.Fatal(err)
	}
	if err := reconcileCloneRemote(ctx, root, remote, "sandbox-id", first, runGitConfig); err == nil {
		t.Fatal("duplicate URL values were not reported as conflict")
	}
	values := gitConfigValues(t, cfg, "remote.sandbox-demo.url")
	if len(values) != 2 || values[0] != second || values[1] != "git://user-edit.invalid/demo.git" {
		t.Fatalf("duplicate/user URL values changed: %#v", values)
	}
}

func TestRemoveCloneRemotePreservesUserAddedOptions(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	cfg := filepath.Join(root, ".git", "config")
	ctx := context.Background()
	if err := reconcileCloneRemote(ctx, root, "sandbox-demo", "sandbox-id", "git://127.0.0.1:1234/demo.git", runGitConfig); err != nil {
		t.Fatal(err)
	}
	if err := gitConfigSet(t, cfg, "--add", "remote.sandbox-demo.fetch", "+refs/heads/*:refs/remotes/sandbox-demo/*"); err != nil {
		t.Fatal(err)
	}
	if err := removeCloneRemote(ctx, root, "sandbox-demo", "sandbox-id", runGitConfig); err == nil {
		t.Fatal("removal should preserve and report a user-extended section")
	}
	if got := gitConfigValues(t, cfg, "remote.sandbox-demo.fetch"); len(got) != 1 {
		t.Fatalf("user fetch option was removed: %#v", got)
	}
	if got := gitConfigValues(t, cfg, "remote.sandbox-demo.url"); len(got) != 1 {
		t.Fatalf("owned remote URL should remain on conflict: %#v", got)
	}
}

func TestReconcileCloneRemoteSerializesConcurrentGitConfigWriter(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	configPath := filepath.Join(root, ".git", "config")
	ctx := context.Background()
	concurrentAttempted := false
	var concurrentErr error
	run := func(ctx context.Context, path string, args ...string) (string, error) {
		if !concurrentAttempted {
			concurrentAttempted = true
			commandArgs := []string{"config", "--file", configPath, "--replace-all", "remote.sandbox-demo.url", "git://user-edit.invalid/demo.git"}
			command := exec.CommandContext(ctx, "git", commandArgs...)
			output, err := command.CombinedOutput()
			if err != nil {
				concurrentErr = &testCommandError{err: err, output: string(output)}
			} else {
				concurrentErr = errors.New("concurrent Git config writer unexpectedly succeeded")
			}
		}
		return runGitConfig(ctx, path, args...)
	}
	if err := reconcileCloneRemote(ctx, root, "sandbox-demo", "sandbox-id", "git://127.0.0.1:4321/demo.git", run); err != nil {
		t.Fatal(err)
	}
	if concurrentErr == nil {
		t.Fatal("concurrent Git config writer was not blocked by the config lock")
	}
	values := gitConfigValues(t, configPath, "remote.sandbox-demo.url")
	if len(values) != 1 || values[0] != "git://127.0.0.1:4321/demo.git" {
		t.Fatalf("unexpected remote after serialized update: %#v", values)
	}
}

func TestGitConfigLockRejectsReplacedLockPath(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	configPath := filepath.Join(root, ".git", "config")
	gitDir, err := os.Lstat(filepath.Join(root, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := configPath + ".lock"
	replacement := []byte("attacker lock replacement")
	err = withGitConfigLock(configPath, gitDir, func(string) error {
		if err := os.Remove(lockPath); err != nil {
			return err
		}
		return os.WriteFile(lockPath, replacement, 0o600)
	})
	if err == nil || !strings.Contains(err.Error(), "lock was replaced") {
		t.Fatalf("expected lock replacement conflict, got %v", err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("replacement lock was committed over the original Git config")
	}
	got, err := os.ReadFile(lockPath)
	if err != nil || !bytes.Equal(got, replacement) {
		t.Fatalf("foreign replacement lock was removed or changed: %q, %v", got, err)
	}
}

func TestGitConfigLockMutationFailureLeavesConfigUntouched(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	configPath := filepath.Join(root, ".git", "config")
	gitDir, err := os.Lstat(filepath.Join(root, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("synthetic mutation failure")
	err = withGitConfigLock(configPath, gitDir, func(string) error { return wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected injected failure, got %v", err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed config mutation changed the original file")
	}
	if _, err := os.Lstat(configPath + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned config lock was not cleaned up: %v", err)
	}
}

func TestGitConfigLockRejectsReplacedGitDirectory(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	configPath := filepath.Join(root, ".git", "config")
	gitDir, err := os.Lstat(filepath.Join(root, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	err = withGitConfigLock(configPath, gitDir, func(string) error {
		oldPath := filepath.Join(root, ".git-original")
		if err := os.Rename(filepath.Join(root, ".git"), oldPath); err != nil {
			return err
		}
		if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(root, ".git", "config"), []byte("replacement directory"), 0o600)
	})
	if err == nil || !strings.Contains(err.Error(), "directory changed") {
		t.Fatalf("expected Git directory replacement conflict, got %v", err)
	}
	after, err := os.ReadFile(filepath.Join(root, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("replaced Git directory unexpectedly contains the original config")
	}
}

func initCloneTestRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	cmd := exec.Command("git", "-C", root, "init", "-q")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	return root
}

func gitConfigSet(t *testing.T, config string, args ...string) error {
	t.Helper()
	commandArgs := append([]string{"config", "--file", config}, args...)
	cmd := exec.Command("git", commandArgs...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return &testCommandError{err: err, output: string(output)}
	}
	return nil
}

func gitConfigValues(t *testing.T, config, key string) []string {
	t.Helper()
	cmd := exec.Command("git", "config", "--file", config, "--get-all", key)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("git config --get-all %s: %v", key, err)
	}
	return strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
}

type testCommandError struct {
	err    error
	output string
}

func (e *testCommandError) Error() string { return e.err.Error() + ": " + e.output }
func (e *testCommandError) Unwrap() error { return e.err }
func (e *testCommandError) ExitCode() int {
	var exit *exec.ExitError
	if errors.As(e.err, &exit) {
		return exit.ExitCode()
	}
	return -1
}
