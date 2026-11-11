package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	sdk "github.com/rheic/sandboxes-go-sdk"

	"github.com/rheic/sandboxes-cli/internal/version"
)

const (
	diagnosePass  = "pass"
	diagnoseFail  = "fail"
	diagnoseWarn  = "warn"
	diagnoseSkip  = "skip"
	diagnoseUsage = "usage: rsbx diagnose [--format table|json|yaml|github-issue] [--json]"
)

type diagnoseCheck struct {
	Name   string `json:"name" yaml:"name"`
	Status string `json:"status" yaml:"status"`
	Detail string `json:"detail,omitempty" yaml:"detail,omitempty"`
}

type diagnoseSection struct {
	Title  string          `json:"title" yaml:"title"`
	Checks []diagnoseCheck `json:"checks" yaml:"checks"`
}

type diagnoseReport struct {
	Sections []diagnoseSection `json:"sections" yaml:"sections"`
}

func (r *Runner) diagnose(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintln(r.Out, diagnoseUsage)
			return 0
		}
		return r.flagParseFailure("diagnose", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, diagnoseUsage)
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	report := r.collectDiagnoseReport(ctx)
	switch selected {
	case listFormatJSON:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			r.error(err)
			return 1
		}
	case listFormatYAML:
		data, err := yaml.Marshal(report)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
	default:
		r.writeDiagnoseText(report)
	}
	for _, section := range report.Sections {
		for _, check := range section.Checks {
			if check.Status == diagnoseFail {
				return 1
			}
		}
	}
	return 0
}

// collectDiagnoseReport mirrors the sbx diagnose structure: four sections of
// individually graded checks. Host-side checks never fail closed on optional
// tooling; only daemon connectivity and version agreement are failures.
func (r *Runner) collectDiagnoseReport(ctx context.Context) diagnoseReport {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	installation := diagnoseSection{Title: "INSTALLATION"}
	installation.Checks = append(installation.Checks,
		r.checkCLIBinary(),
		diagnoseCheck{Name: "Binary version", Status: diagnosePass, Detail: "v" + version.Version},
		checkHostProcesses(),
		diagnoseCheck{Name: "Daemon diagnostics", Status: diagnoseSkip, Detail: "diagnostic bundle upload is not implemented"})

	platform := diagnoseSection{Title: "PLATFORM"}
	platform.Checks = append(platform.Checks,
		checkVirtualization(),
		checkFilesystemTool("mkfs.erofs"),
		checkFilesystemTool("mkfs.ext4"))

	storage := diagnoseSection{Title: "STORAGE"}
	storage.Checks = append(storage.Checks,
		r.checkStorageDirectories(),
		r.checkStoragePermissions(),
		checkDiskSpace(diagnoseStateDir(r.Socket)),
		diagnoseCheck{Name: "ZFS offset sync", Status: diagnoseSkip, Detail: "state directory is not on ZFS"})

	connection := diagnoseSection{Title: "CONNECTION"}
	connection.Checks = append(connection.Checks, r.checkDaemonHealth(checkCtx))
	connection.Checks = append(connection.Checks, r.checkDaemon(checkCtx)...)

	return diagnoseReport{Sections: []diagnoseSection{installation, platform, storage, connection}}
}

func (r *Runner) checkCLIBinary() diagnoseCheck {
	check := diagnoseCheck{Name: "CLI binary"}
	binary, err := os.Executable()
	if err != nil || binary == "" {
		check.Status = diagnoseFail
		check.Detail = "not found"
		return check
	}
	check.Status = diagnosePass
	check.Detail = binary
	return check
}

// checkHostProcesses counts daemon and shim processes when pgrep is available.
var hostProcessCount = countHostProcesses

func checkHostProcesses() diagnoseCheck {
	check := diagnoseCheck{Name: "Host processes"}
	daemons, shims, err := hostProcessCount()
	if err != nil {
		check.Status = diagnoseSkip
		check.Detail = err.Error()
		return check
	}
	check.Status = diagnosePass
	check.Detail = fmt.Sprintf("%d rheicd, %d containerd-shim-nerdbox-v1", daemons, shims)
	return check
}

func checkVirtualization() diagnoseCheck {
	check := diagnoseCheck{Name: "Virtualization"}
	supported, detail := hostVirtualizationSupport()
	switch {
	case supported:
		check.Status = diagnosePass
	case detail == "":
		check.Status = diagnoseSkip
	default:
		check.Status = diagnoseFail
	}
	check.Detail = detail
	return check
}

var hostVirtualizationSupport = virtualizationSupport

func checkFilesystemTool(name string) diagnoseCheck {
	check := diagnoseCheck{Name: name}
	path, err := lookPath(name)
	if err != nil || path == "" {
		check.Status = diagnoseWarn
		check.Detail = "not found on PATH; filesystem images are built inside the pinned runtime container"
		return check
	}
	check.Status = diagnosePass
	check.Detail = path
	return check
}

func (r *Runner) checkStorageDirectories() diagnoseCheck {
	check := diagnoseCheck{Name: "Storage directories"}
	stateDir := diagnoseStateDir(r.Socket)
	paths := []string{stateDir, filepath.Dir(r.Socket)}
	missing := make([]string, 0, len(paths))
	for _, path := range paths {
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			missing = append(missing, path)
		}
	}
	if len(missing) != 0 {
		check.Status = diagnoseWarn
		check.Detail = "missing: " + joinComma(missing)
		return check
	}
	check.Status = diagnosePass
	check.Detail = fmt.Sprintf("all %d paths present", len(paths))
	return check
}

func (r *Runner) checkStoragePermissions() diagnoseCheck {
	check := diagnoseCheck{Name: "Directory permissions"}
	stateDir := diagnoseStateDir(r.Socket)
	probe, err := os.MkdirTemp(stateDir, ".diagnose-perm-*")
	if err != nil {
		check.Status = diagnoseFail
		check.Detail = "state directory is not writable: " + err.Error()
		return check
	}
	_ = os.Remove(probe)
	check.Status = diagnosePass
	check.Detail = "state directory is writable"
	return check
}

// checkDaemon grades the connection section against the local daemon. It
// always appends the same check count so the report shape is stable whether
// or not the daemon answers.
func (r *Runner) checkDaemon(ctx context.Context) []diagnoseCheck {
	checks := []diagnoseCheck{
		{Name: "Version match"},
		{Name: "Socket"},
		{Name: "SSH client config"},
		{Name: "Authentication"},
		{Name: "Global network policy"},
		{Name: "TLS trust store"},
	}
	client, err := r.client()
	if err != nil {
		return markDaemonUnreachable(checks, err)
	}
	defer func() { _ = client.Close() }()
	info, err := sdk.Version(client).Get(ctx)
	if err != nil {
		return markDaemonUnreachable(checks, err)
	}
	checks[0].Status = diagnosePass
	checks[0].Detail = "v" + info.Version
	if "v"+info.Version == "v"+version.Version {
		checks[0].Detail = "match (v" + info.Version + ")"
	} else {
		checks[0].Status = diagnoseWarn
		checks[0].Detail = fmt.Sprintf("client v%s, server v%s", version.Version, info.Version)
	}
	if _, err := os.Stat(r.Socket); err == nil {
		checks[1].Status = diagnosePass
		checks[1].Detail = "responsive"
	} else {
		checks[1].Status = diagnoseFail
		checks[1].Detail = "missing at " + r.Socket
	}
	checks[2] = checkSSHClientConfig()
	checks[3] = r.checkAuthentication(ctx, client)
	checks[4] = r.checkGlobalPolicy(ctx, client)
	checks[5] = checkTLSTrustStore()
	return checks
}

// checkDaemonHealth grades daemon reachability separately so the connection
// section carries the same check count as the sbx baseline.
func (r *Runner) checkDaemonHealth(ctx context.Context) diagnoseCheck {
	check := diagnoseCheck{Name: "Daemon"}
	client, err := r.client()
	if err != nil {
		check.Status = diagnoseFail
		check.Detail = err.Error()
		return check
	}
	defer func() { _ = client.Close() }()
	info, err := sdk.Version(client).Get(ctx)
	if err != nil {
		check.Status = diagnoseFail
		check.Detail = err.Error()
		return check
	}
	check.Status = diagnosePass
	check.Detail = "healthy (v" + info.Version + ")"
	return check
}

func markDaemonUnreachable(checks []diagnoseCheck, err error) []diagnoseCheck {
	checks[0].Status = diagnoseFail
	checks[0].Detail = "daemon unreachable: " + err.Error()
	checks[1].Status = diagnoseFail
	checks[1].Detail = "not responsive"
	for i := 2; i < len(checks); i++ {
		checks[i].Status = diagnoseSkip
		checks[i].Detail = "daemon unreachable"
	}
	return checks
}

func checkSSHClientConfig() diagnoseCheck {
	check := diagnoseCheck{Name: "SSH client config"}
	home, err := os.UserHomeDir()
	if err != nil {
		check.Status = diagnoseSkip
		return check
	}
	data, err := os.ReadFile(filepath.Join(home, ".ssh", "config")) // #nosec G304 -- fixed host path, read-only diagnostic
	if errors.Is(err, os.ErrNotExist) {
		check.Status = diagnosePass
		check.Detail = "not configured"
		return check
	}
	if err != nil {
		check.Status = diagnoseWarn
		check.Detail = "cannot read ~/.ssh/config"
		return check
	}
	if containsRheicSSHConfig(string(data)) {
		check.Status = diagnosePass
		check.Detail = "rsbx managed entries present"
		return check
	}
	check.Status = diagnosePass
	check.Detail = "not configured"
	return check
}

func (r *Runner) checkAuthentication(ctx context.Context, client sdk.Client) diagnoseCheck {
	check := diagnoseCheck{Name: "Authentication"}
	status := sdk.AccountStatus(client)
	present, err := status.Status(ctx, "docker")
	if err != nil {
		check.Status = diagnoseSkip
		check.Detail = "credential status unavailable: " + err.Error()
		return check
	}
	if !present {
		check.Status = diagnoseFail
		check.Detail = "not signed in; try: rsbx login"
		return check
	}
	check.Status = diagnosePass
	detail, err := status.StatusDetail(ctx, "docker")
	if err == nil && detail.RefreshPresent {
		if detail.RefreshCoordinated {
			check.Detail = "signed in; token refresh coordinated"
		} else {
			check.Detail = "signed in; manual re-login required after token expiry"
		}
		return check
	}
	check.Detail = "signed in"
	return check
}

func (r *Runner) checkGlobalPolicy(ctx context.Context, client sdk.Client) diagnoseCheck {
	check := diagnoseCheck{Name: "Global network policy"}
	_, _, err := globalPolicyForList(ctx, client)
	if err != nil {
		check.Status = diagnoseWarn
		check.Detail = err.Error()
		return check
	}
	check.Status = diagnosePass
	check.Detail = "initialized"
	return check
}

func checkTLSTrustStore() diagnoseCheck {
	check := diagnoseCheck{Name: "TLS trust store"}
	for _, key := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if value := os.Getenv(key); value != "" {
			check.Status = diagnoseWarn
			check.Detail = key + " is set to " + value + " in this shell"
			return check
		}
	}
	check.Status = diagnosePass
	check.Detail = "not overridden in this shell"
	return check
}

func diagnoseStateDir(socket string) string {
	if socket != "" {
		if dir := filepath.Dir(socket); dir != "." && dir != string(filepath.Separator) {
			return dir
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".sandboxes")
}

func joinComma(values []string) string {
	out := ""
	for i, value := range values {
		if i > 0 {
			out += ", "
		}
		out += value
	}
	return out
}

func (r *Runner) writeDiagnoseText(report diagnoseReport) {
	passed, failed, warned, skipped := 0, 0, 0, 0
	for _, section := range report.Sections {
		_, _ = fmt.Fprintln(r.Out, section.Title)
		for _, check := range section.Checks {
			marker := "?"
			switch check.Status {
			case diagnosePass:
				marker = "✓"
				passed++
			case diagnoseFail:
				marker = "✗"
				failed++
			case diagnoseWarn:
				marker = "!"
				warned++
			case diagnoseSkip:
				marker = "⊘"
				skipped++
			}
			_, _ = fmt.Fprintf(r.Out, "  %s %s", marker, check.Name)
			if check.Detail != "" {
				_, _ = fmt.Fprintf(r.Out, " — %s", check.Detail)
			}
			_, _ = fmt.Fprintln(r.Out)
		}
		_, _ = fmt.Fprintln(r.Out)
	}
	_, _ = fmt.Fprintf(r.Out, "%d passed · %d failed · %d warning · %d skipped\n", passed, failed, warned, skipped)
}
