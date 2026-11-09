package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"

	"github.com/rheic/sandboxes-cli/internal/version"
)

type diagnoseVersionService struct{ err error }

func (s diagnoseVersionService) Get(context.Context) (sdk.VersionInfo, error) {
	if s.err != nil {
		return sdk.VersionInfo{}, s.err
	}
	return sdk.VersionInfo{Version: version.Version, APIVersion: "0.0.16"}, nil
}

type diagnoseSandbox struct {
	fakeSandbox
	items []sdk.Sandbox
	err   error
}

func (s diagnoseSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	if s.err != nil {
		return nil, s.err
	}
	return &sdk.Page[sdk.Sandbox]{Items: s.items}, nil
}

func diagnoseRunner(t *testing.T, socket string, sandbox sdk.SandboxService, statuses sdk.AccountStatusService, versionErr error) (*Runner, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, Socket: socket, NewClient: func(string) (sdk.Client, error) {
		return fakeClient{sandbox: sandbox, accountStatuses: statuses, versions: diagnoseVersionService{err: versionErr}}, nil
	}}
	return runner, &out
}

func findDiagnoseCheck(t *testing.T, report diagnoseReport, name string) diagnoseCheck {
	t.Helper()
	for _, section := range report.Sections {
		for _, check := range section.Checks {
			if check.Name == name {
				return check
			}
		}
	}
	t.Fatalf("check %q not found in %#v", name, report)
	return diagnoseCheck{}
}

func TestDiagnoseSectionsMatchBaselineShape(t *testing.T) {
	originalVirtualizationSupport := hostVirtualizationSupport
	t.Cleanup(func() { hostVirtualizationSupport = originalVirtualizationSupport })
	hostVirtualizationSupport = func() (bool, string) { return true, "test hypervisor present" }

	socket := filepath.Join(t.TempDir(), "sandboxd.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runner, out := diagnoseRunner(t, socket, diagnoseSandbox{}, fakeAccountStatus{statuses: map[string]bool{"docker": true}}, nil)
	if code := runner.Run(context.Background(), []string{"diagnose", "--json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var report diagnoseReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("json %q: %v", out.String(), err)
	}
	wantTitles := []string{"INSTALLATION", "PLATFORM", "STORAGE", "CONNECTION"}
	if len(report.Sections) != len(wantTitles) {
		t.Fatalf("sections=%#v", report.Sections)
	}
	total := 0
	for i, section := range report.Sections {
		if section.Title != wantTitles[i] {
			t.Fatalf("section %d = %q, want %q", i, section.Title, wantTitles[i])
		}
		total += len(section.Checks)
	}
	if total != 18 {
		t.Fatalf("checks=%d, want 18 like the sbx baseline", total)
	}
	if check := findDiagnoseCheck(t, report, "Authentication"); check.Status != diagnosePass {
		t.Fatalf("authentication = %#v", check)
	}
	if check := findDiagnoseCheck(t, report, "Version match"); check.Status != diagnosePass {
		t.Fatalf("version match = %#v", check)
	}
	if check := findDiagnoseCheck(t, report, "Socket"); check.Status != diagnosePass {
		t.Fatalf("socket = %#v", check)
	}
	if check := findDiagnoseCheck(t, report, "ZFS offset sync"); check.Status != diagnoseSkip {
		t.Fatalf("zfs = %#v", check)
	}
}

func TestDiagnoseFailsWhenDaemonUnreachable(t *testing.T) {
	runner, out := diagnoseRunner(t, filepath.Join(t.TempDir(), "missing.sock"), diagnoseSandbox{err: errors.New("dial failed")}, nil, errors.New("dial failed"))
	if code := runner.Run(context.Background(), []string{"diagnose"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	for _, expected := range []string{"INSTALLATION", "CONNECTION", "✗ Version match", "daemon unreachable", "skipped"} {
		if !strings.Contains(out.String(), expected) {
			t.Errorf("output lacks %q: %s", expected, out.String())
		}
	}
}

func TestDiagnoseFailsWhenNotSignedIn(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "sandboxd.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runner, out := diagnoseRunner(t, socket, diagnoseSandbox{}, fakeAccountStatus{statuses: map[string]bool{"docker": false}}, nil)
	if code := runner.Run(context.Background(), []string{"diagnose", "--format", "table"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "✗ Authentication") || !strings.Contains(out.String(), "rsbx login") {
		t.Fatalf("authentication failure not reported: %s", out.String())
	}
}

func TestDiagnoseUsesInjectableProcessCount(t *testing.T) {
	original := hostProcessCount
	t.Cleanup(func() { hostProcessCount = original })
	hostProcessCount = func() (int, int, error) { return 2, 1, nil }
	check := checkHostProcesses()
	if check.Status != diagnosePass || check.Detail != "2 rheicd, 1 containerd-shim-nerdbox-v1" {
		t.Fatalf("check = %#v", check)
	}
	hostProcessCount = func() (int, int, error) { return 0, 0, errors.New("pgrep missing") }
	check = checkHostProcesses()
	if check.Status != diagnoseSkip {
		t.Fatalf("check = %#v", check)
	}
}

func TestDiagnoseStateDirDerivesFromSocket(t *testing.T) {
	if dir := diagnoseStateDir(filepath.Join("state", "sandboxesd.sock")); dir != "state" {
		t.Fatalf("state dir = %q", dir)
	}
	if dir := diagnoseStateDir(""); !strings.HasSuffix(dir, ".sandboxes") {
		t.Fatalf("default state dir = %q", dir)
	}
}
