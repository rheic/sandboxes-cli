package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

const attachUsage = `Usage: rsbx attach [--shell] SANDBOX

Attach to a sandbox, starting it first if it is stopped. The sandbox's agent
command is used unless --shell is set.
`

// attach starts a stopped sandbox and opens an interactive agent session.
func (r *Runner) attach(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("attach", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	shell := fs.Bool("shell", false, "open /bin/sh instead of the agent command")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(r.Out, attachUsage)
			return 0
		}
		return r.flagParseFailure("attach", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprint(r.Err, attachUsage)
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
	if err := ensureSandboxRunning(ctx, client, sb); err != nil {
		r.error(err)
		return 1
	}
	workdir := ""
	if sb.Clone != nil {
		fresh, err := client.Sandboxes().Get(ctx, id)
		if err != nil {
			r.error(err)
			return 1
		}
		workdir, err = r.activateCloneSandbox(ctx, fresh, "")
		if err != nil {
			r.error(err)
			return 1
		}
		sb = fresh
	}
	argv := agentCommandArgs(sb.Agent)
	if *shell || sb.Agent == "" {
		argv = []string{shellPath}
	}
	interactive := true
	tty := false
	if file, ok := r.In.(*os.File); ok {
		tty = term.IsTerminal(int(file.Fd()))
	}
	closeOnEOF := true
	return r.execSessionMode(ctx, client, id, argv, execOptions{workdir: workdir}, interactive, tty, closeOnEOF)
}
