package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gdamore/tcell/v3"
	sdk "github.com/rheic/sandboxes-go-sdk"
)

const tuiUsage = `usage: rsbx tui [--refresh DURATION]

Open the RHEIC sandbox dashboard.

Keys:
  ↑/↓ or j/k  select a sandbox
  n            new sandbox (create flow)
  s / x        start / stop the selected sandbox
  d            remove the selected sandbox (asks first)
  a            attach hint for the selected sandbox
  r            refresh now
  q or Esc     quit
`

const (
	dashboardMinWidth   = 64
	dashboardMinHeight  = 20
	dashboardPageSize   = 100
	dashboardStateLabel = "STATE"
	sandboxStateRunning = "running"
	sandboxStateStopped = "stopped"
)

var (
	brandBackground = tcell.NewRGBColor(8, 13, 32)
	brandPrimary    = tcell.NewRGBColor(38, 82, 245)   // #2652F5
	brandAccent     = tcell.NewRGBColor(72, 122, 255)  // #487AFF
	brandWarm       = tcell.NewRGBColor(255, 111, 53)  // #FF6F35
	brandLavender   = tcell.NewRGBColor(235, 241, 255) // #EBF1FF
	brandMuted      = tcell.NewRGBColor(156, 174, 219)
)

type dashboardScreen interface {
	Init() error
	Fini()
	Size() (int, int)
	Clear()
	SetStyle(tcell.Style)
	PutStrStyled(x, y int, text string, style tcell.Style)
	Show()
	EventQ() chan tcell.Event
	Sync()
	SetTitle(string)
}

type dashboardModel struct {
	items         []sdk.Sandbox
	selected      int
	updated       time.Time
	err           string
	mode          dashboardMode
	form          createFormModel
	pendingCreate sdk.CreateRequest
	notice        string
}

func (r *Runner) tui(ctx context.Context, args []string) int {
	refreshEvery, help, err := parseTUIOptions(args)
	if help {
		_, _ = fmt.Fprint(r.Out, tuiUsage)
		return 0
	}
	if parseErr, ok := asFlagParseError(err); ok {
		return r.flagParseFailure("tui", parseErr.err)
	}
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx tui: %v\n", err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()

	screen, err := tcell.NewScreen()
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx tui: terminal unavailable: %v\n", err)
		return 1
	}
	if err := screen.Init(); err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx tui: terminal initialization failed: %v\n", err)
		return 1
	}
	return runDashboard(ctx, screen, client, refreshEvery)
}

func parseTUIOptions(args []string) (time.Duration, bool, error) {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	refresh := fs.Duration("refresh", 5*time.Second, "dashboard refresh interval")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, true, nil
		}
		return 0, false, flagParseError{err: err}
	}
	if fs.NArg() != 0 {
		return 0, false, errors.New("unexpected argument")
	}
	if *refresh < time.Second || *refresh > time.Minute {
		return 0, false, errors.New("--refresh must be between 1s and 1m")
	}
	return *refresh, false, nil
}

func runDashboard(ctx context.Context, screen dashboardScreen, client sdk.Client, refreshEvery time.Duration) int {
	defer screen.Fini()
	screen.SetTitle("RHEIC | Sandboxes")
	model := &dashboardModel{}
	refreshDashboard(ctx, client, model)
	drawDashboard(screen, model)

	done := make(chan struct{})
	events := make(chan tcell.Event, 1)
	go forwardDashboardEvents(done, dashboardScreenStopQ(screen), screen.EventQ(), events)
	defer close(done)

	ticker := time.NewTicker(refreshEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-ticker.C:
			refreshAndDrawDashboard(ctx, screen, client, model)
		case ev, ok := <-events:
			if handleDashboardEvent(ev, ok, screen, client, ctx, model) {
				return 0
			}
		}
	}
}

func dashboardScreenStopQ(screen dashboardScreen) <-chan struct{} {
	stopper, ok := screen.(interface{ StopQ() <-chan struct{} })
	if !ok {
		return nil
	}
	return stopper.StopQ()
}

func forwardDashboardEvents(done, screenStopped <-chan struct{}, eventQueue <-chan tcell.Event, events chan<- tcell.Event) {
	defer close(events)
	for {
		select {
		case <-done:
			return
		case <-screenStopped:
			return
		case event, ok := <-eventQueue:
			if !ok {
				return
			}
			select {
			case events <- event:
			case <-done:
				return
			case <-screenStopped:
				return
			}
		}
	}
}

func refreshAndDrawDashboard(ctx context.Context, screen dashboardScreen, client sdk.Client, model *dashboardModel) {
	refreshDashboard(ctx, client, model)
	drawDashboard(screen, model)
}

func handleDashboardEvent(ev tcell.Event, ok bool, screen dashboardScreen, client sdk.Client, ctx context.Context, model *dashboardModel) bool {
	if !ok {
		return true
	}
	switch event := ev.(type) {
	case *tcell.EventResize:
		screen.Sync()
		drawDashboard(screen, model)
	case *tcell.EventKey:
		if dashboardKey(event, model, ctx, client) {
			return true
		}
		drawDashboard(screen, model)
	}
	return false
}

func dashboardKey(event *tcell.EventKey, model *dashboardModel, ctx context.Context, client sdk.Client) bool {
	switch model.mode {
	case modeCreate:
		if dashboardKeyInCreate(event, model) {
			model.mode = modeList
			if model.pendingCreate.Name != "" {
				submitCreate(ctx, client, model)
				model.pendingCreate = sdk.CreateRequest{}
			}
		}
		return false
	case modeConfirmDelete:
		return dashboardKeyConfirmDelete(event, model, ctx, client)
	}
	return dashboardKeyList(event, model, ctx, client)
}

// dashboardKeyConfirmDelete handles the delete confirmation prompt.
func dashboardKeyConfirmDelete(event *tcell.EventKey, model *dashboardModel, ctx context.Context, client sdk.Client) bool {
	if event.Key() == tcell.KeyEscape || event.Str() == "n" || event.Str() == "N" {
		model.mode = modeList
		model.notice = "delete canceled"
		return false
	}
	if event.Str() == "y" || event.Str() == "Y" {
		model.mode = modeList
		dashboardAction(ctx, client, model, "rm")
	}
	return false
}

// dashboardKeyList handles keys in the sandbox list mode and reports whether
// the dashboard should quit.
func dashboardKeyList(event *tcell.EventKey, model *dashboardModel, ctx context.Context, client sdk.Client) bool {
	switch {
	case event.Key() == tcell.KeyEscape || event.Str() == "q" || event.Str() == "Q":
		return true
	case event.Key() == tcell.KeyUp || event.Str() == "k":
		if model.selected > 0 {
			model.selected--
		}
	case event.Key() == tcell.KeyDown || event.Str() == "j":
		if model.selected+1 < len(model.items) {
			model.selected++
		}
	case event.Str() == "r" || event.Str() == "R":
		refreshDashboard(ctx, client, model)
	default:
		return dashboardKeyAction(event, model, ctx, client)
	}
	return false
}

// dashboardKeyAction handles single-letter list actions (new, start, stop,
// remove, attach hint).
func dashboardKeyAction(event *tcell.EventKey, model *dashboardModel, ctx context.Context, client sdk.Client) bool {
	switch event.Str() {
	case "n", "N":
		model.mode = modeCreate
		model.form = newCreateFormModel()
	case "s", "S":
		dashboardAction(ctx, client, model, "start")
	case "x", "X":
		dashboardAction(ctx, client, model, "stop")
	case "d", "D":
		if len(model.items) > 0 {
			model.mode = modeConfirmDelete
		}
	case "a", "A":
		if len(model.items) > 0 {
			model.notice = "attach: run rsbx attach " + model.items[model.selected].Name + " from a shell"
		}
	}
	return false
}

func refreshDashboard(ctx context.Context, client sdk.Client, model *dashboardModel) {
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	items, err := collectSandboxes(callCtx, client, dashboardPageSize)
	if err != nil {
		model.err = err.Error()
		return
	}
	model.items = items
	model.err = ""
	model.updated = time.Now()
	if model.selected >= len(items) {
		model.selected = max(0, len(items)-1)
	}
}

func drawDashboard(screen dashboardScreen, model *dashboardModel) {
	width, height := screen.Size()
	background := tcell.StyleDefault.Foreground(brandLavender).Background(brandBackground)
	primary := tcell.StyleDefault.Foreground(brandLavender).Background(brandBackground)
	muted := tcell.StyleDefault.Foreground(brandMuted).Background(brandBackground)
	accent := tcell.StyleDefault.Foreground(brandAccent).Background(brandBackground).Bold(true)
	warm := tcell.StyleDefault.Foreground(brandWarm).Background(brandBackground)
	selected := tcell.StyleDefault.Foreground(brandLavender).Background(brandPrimary).Bold(true)
	screen.SetStyle(background)
	screen.Clear()
	if width < dashboardMinWidth || height < dashboardMinHeight {
		drawText(screen, 2, 1, "RHEIC", accent, width-4)
		drawText(screen, 2, 3, "Resize terminal to at least 64 x 20", muted, width-4)
		screen.Show()
		return
	}

	drawBrand(screen, primary, accent, width)
	drawText(screen, 2, 9, strings.Repeat("─", width-4), tcell.StyleDefault.Foreground(brandPrimary).Background(brandBackground), width-4)

	leftWidth := width * 3 / 5
	if leftWidth < 42 {
		leftWidth = 42
	}
	detailX := leftWidth + 3
	drawText(screen, 3, 11, "SANDBOXES", muted, leftWidth-4)
	drawText(screen, 3, 12, "NAME", accent, 22)
	drawText(screen, 27, 12, dashboardStateLabel, accent, 12)
	drawText(screen, 40, 12, "AGENT", accent, leftWidth-43)
	for y := 13; y < height-3; y++ {
		drawText(screen, 3, y, strings.Repeat(" ", leftWidth-4), primary, leftWidth-4)
		index := y - 13
		if index >= len(model.items) {
			continue
		}
		item := model.items[index]
		style := primary
		marker := " "
		if index == model.selected {
			style = selected
			marker = "›"
		}
		drawText(screen, 2, y, marker, accent, 1)
		drawText(screen, 3, y, clipCell(item.Name, 22), style, 22)
		drawText(screen, 27, y, clipCell(item.State, 12), style, 12)
		drawText(screen, 40, y, clipCell(item.Agent, leftWidth-43), style, leftWidth-43)
	}

	if detailX < width-22 {
		drawText(screen, detailX, 11, "SELECTED SANDBOX", muted, width-detailX-2)
		if len(model.items) > 0 {
			drawDashboardDetails(screen, &model.items[model.selected], detailX, width, height, primary, accent, muted, warm)
		} else if model.err == "" {
			drawText(screen, detailX, 13, "No sandboxes yet", primary, width-detailX-2)
			drawText(screen, detailX, 15, "Start one with rsbx run", muted, width-detailX-2)
		}
	}
	drawDashboardFooter(screen, model, width, height, accent, muted, warm)
	screen.Show()
}

// drawDashboardFooter renders the status, notice, mode overlay and key hints.
func drawDashboardFooter(screen dashboardScreen, model *dashboardModel, width, height int, accent, muted, warm tcell.Style) {
	if model.err != "" {
		drawText(screen, 3, height-3, "DAEMON  "+clipCell(model.err, width-13), warm, width-6)
	} else {
		status := fmt.Sprintf("%d SANDBOXES", len(model.items))
		if !model.updated.IsZero() {
			status += "   UPDATED " + model.updated.Format("15:04:05")
		}
		drawText(screen, 3, height-3, status, muted, width-6)
	}
	if model.notice != "" {
		drawText(screen, 3, height-5, clipCell(model.notice, width-6), warm, width-6)
	}
	switch model.mode {
	case modeCreate:
		drawCreateForm(screen, model.form, width, height,
			tcell.StyleDefault.Foreground(brandLavender).Background(brandBackground),
			accent, muted, warm)
	case modeConfirmDelete:
		if len(model.items) > 0 {
			prompt := "Remove " + model.items[model.selected].Name + "? Sandbox files on the host are kept. [y/N]"
			drawText(screen, 3, height-5, clipCell(prompt, width-6), warm.Bold(true), width-6)
		}
	}
	drawText(screen, 3, height-2, "↑/↓ or j/k  move   n  new   s/x  start/stop   d  remove   a  attach   r  refresh   q  quit", accent, width-6)
}

// drawCreateForm renders the create-flow landing form.
func drawCreateForm(screen dashboardScreen, form createFormModel, width, height int, primary, accent, muted, warm tcell.Style) {
	boxWidth := min(width-8, 64)
	boxX := (width - boxWidth) / 2
	if boxX < 2 {
		boxX = 2
	}
	for y := 6; y < height-6; y++ {
		drawText(screen, boxX, y, strings.Repeat(" ", boxWidth), primary, boxWidth)
	}
	drawText(screen, boxX+2, 7, "NEW SANDBOX", accent, boxWidth-4)
	for i, label := range createFormFields {
		y := 9 + i*2
		style := muted
		if i == form.focus {
			style = accent.Bold(true)
		}
		drawText(screen, boxX+2, y, label, style, 16)
		drawText(screen, boxX+20, y, clipCell(form.values[i], boxWidth-22), primary, boxWidth-22)
	}
	if form.err != "" {
		drawText(screen, boxX+2, height-8, clipCell(form.err, boxWidth-4), warm, boxWidth-4)
	}
	drawText(screen, boxX+2, height-7, "Tab/↑↓ move · Enter create · Esc cancel", muted, boxWidth-4)
}

func drawBrand(screen dashboardScreen, primary, accent tcell.Style, width int) {
	logoStyle := tcell.StyleDefault.Foreground(brandPrimary).Background(brandBackground)
	mask := []string{
		"                         #####  ",
		"                     #######    ",
		"                   ########     ",
		"                 #########      ",
		"          ################      ",
		"     ########################   ",
		"  ####### ####################  ",
		" ################### ## # ##### ",
		"   ##            ##############  ",
		"      ##            ############",
		"                     #  #######  ",
		"                         ######  ",
		"           ####         ######   ",
		"            #######   ######     ",
		"              ###########        ",
		"              ####               ",
	}
	for y := 0; y < len(mask); y += 2 {
		for x := 0; x < len(mask[y]); x++ {
			top := mask[y][x] == '#'
			bottom := y+1 < len(mask) && x < len(mask[y+1]) && mask[y+1][x] == '#'
			glyph := ' '
			switch {
			case top && bottom:
				glyph = '█'
			case top:
				glyph = '▀'
			case bottom:
				glyph = '▄'
			}
			screen.PutStrStyled(2+x, y/2, string(glyph), logoStyle)
		}
	}
	drawText(screen, 38, 1, "RHEIC", primary.Bold(true), width-40)
	drawText(screen, 38, 3, "LOCAL SANDBOXES", accent, width-40)
}

func drawDashboardDetails(screen dashboardScreen, item *sdk.Sandbox, x, width, height int, primary, accent, muted, warm tcell.Style) {
	available := width - x - 2
	rows := []struct{ label, value string }{
		{"NAME", item.Name},
		{dashboardStateLabel, item.State},
		{"AGENT", item.Agent},
		{"IMAGE", item.Image},
		{"ID", item.ID},
		{"WORKSPACE", item.Workspace},
	}
	for i, row := range rows {
		y := 13 + i*2
		if y >= height-5 {
			break
		}
		drawText(screen, x, y, row.label, muted, available)
		style := primary
		if row.label == dashboardStateLabel && item.State != sandboxStateRunning && item.State != sandboxStateStopped {
			style = warm
		} else if row.label == dashboardStateLabel {
			style = accent
		}
		drawText(screen, x, y+1, clipCell(row.value, available), style, available)
	}
}

func drawText(screen dashboardScreen, x, y int, text string, style tcell.Style, maxWidth int) {
	if x < 0 || y < 0 || maxWidth <= 0 {
		return
	}
	text = clipCell(text, maxWidth)
	screen.PutStrStyled(x, y, text, style)
}

func clipCell(text string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(text)
	if len(runes) <= width {
		return text
	}
	if width == 1 {
		return "…"
	}
	return string(runes[:width-1]) + "…"
}
