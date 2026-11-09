package command

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v3"
	sdk "github.com/rheic/sandboxes-go-sdk"
)

type dashboardTestScreen struct {
	width, height int
	cells         map[[2]int]rune
	events        chan tcell.Event
	stopped       chan struct{}
}

func newDashboardTestScreen(width, height int) *dashboardTestScreen {
	return &dashboardTestScreen{
		width: width, height: height, cells: make(map[[2]int]rune),
		events: make(chan tcell.Event, 1), stopped: make(chan struct{}),
	}
}

func (*dashboardTestScreen) Init() error                { return nil }
func (s *dashboardTestScreen) Fini()                    { close(s.stopped) }
func (*dashboardTestScreen) Clear()                     {}
func (*dashboardTestScreen) SetStyle(tcell.Style)       {}
func (*dashboardTestScreen) Show()                      {}
func (*dashboardTestScreen) Sync()                      {}
func (*dashboardTestScreen) SetTitle(string)            {}
func (s *dashboardTestScreen) Size() (int, int)         { return s.width, s.height }
func (s *dashboardTestScreen) EventQ() chan tcell.Event { return s.events }
func (s *dashboardTestScreen) StopQ() <-chan struct{}   { return s.stopped }
func (s *dashboardTestScreen) PutStrStyled(x, y int, text string, _ tcell.Style) {
	for i, r := range []rune(text) {
		if x+i < s.width && y < s.height {
			s.cells[[2]int{x + i, y}] = r
		}
	}
}
func (s *dashboardTestScreen) row(y int) string {
	var b strings.Builder
	for x := 0; x < s.width; x++ {
		if r, ok := s.cells[[2]int{x, y}]; ok {
			b.WriteRune(r)
		} else {
			b.WriteRune(' ')
		}
	}
	return b.String()
}
func (s *dashboardTestScreen) text() string {
	rows := make([]string, s.height)
	for y := range rows {
		rows[y] = s.row(y)
	}
	return strings.Join(rows, "\n")
}

func TestDrawDashboardShowsRHEICBrandAndSandbox(t *testing.T) {
	screen := newDashboardTestScreen(100, 24)
	drawDashboard(screen, &dashboardModel{
		items: []sdk.Sandbox{{Name: "brand-check", ID: "sbx_test", State: "running", Agent: "shell", Image: "alpine:latest", Workspace: "/workspace"}},
	})

	output := screen.text()
	for _, want := range []string{"RHEIC", "LOCAL SANDBOXES", "SANDBOXES", "brand-check", "running", "↑/↓ or j/k", "█"} {
		if !strings.Contains(output, want) {
			t.Errorf("dashboard does not contain %q", want)
		}
	}
}

func TestDrawDashboardHandlesSmallTerminal(t *testing.T) {
	screen := newDashboardTestScreen(32, 10)
	drawDashboard(screen, &dashboardModel{})
	if output := screen.text(); !strings.Contains(output, "Resize terminal") {
		t.Fatalf("small terminal message missing from %q", output)
	}
}

func TestParseTUIOptions(t *testing.T) {
	got, help, err := parseTUIOptions([]string{"--refresh", "10s"})
	if err != nil || help || got != 10*time.Second {
		t.Fatalf("parseTUIOptions() = (%s, %v, %v)", got, help, err)
	}
	if _, _, err := parseTUIOptions([]string{"--refresh", "500ms"}); err == nil {
		t.Fatal("refresh interval below lower bound was accepted")
	}
	if _, help, err := parseTUIOptions([]string{"--help"}); err != nil || !help {
		t.Fatalf("help = (%v, %v)", help, err)
	}
}

func TestTUIHelpDoesNotConnectToDaemon(t *testing.T) {
	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr)
	if code := runner.Run(context.Background(), []string{"tui", "--help"}); code != 0 {
		t.Fatalf("Run(tui --help) = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "RHEIC sandbox dashboard") {
		t.Fatalf("dashboard help missing: %q", stdout.String())
	}
}

func TestDashboardKeyNavigationAndQuit(t *testing.T) {
	model := dashboardModel{items: []sdk.Sandbox{{Name: "one"}, {Name: "two"}}}
	if dashboardKey(tcell.NewEventKey(tcell.KeyDown, "", tcell.ModNone), &model, context.Background(), nil) || model.selected != 1 {
		t.Fatal("down key did not select the next sandbox")
	}
	if dashboardKey(tcell.NewEventKey(tcell.KeyUp, "", tcell.ModNone), &model, context.Background(), nil) || model.selected != 0 {
		t.Fatal("up key did not select the previous sandbox")
	}
	if !dashboardKey(tcell.NewEventKey(tcell.KeyRune, "q", tcell.ModNone), &model, context.Background(), nil) {
		t.Fatal("q key did not quit the dashboard")
	}
}

func TestForwardDashboardEventsStopsWhenDashboardOrScreenStops(t *testing.T) {
	for _, test := range []struct {
		name       string
		stopScreen bool
	}{
		{name: "dashboard quit"},
		{name: "screen fini", stopScreen: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			done := make(chan struct{})
			screenStopped := make(chan struct{})
			queue := make(chan tcell.Event)
			events := make(chan tcell.Event)
			go forwardDashboardEvents(done, screenStopped, queue, events)

			if test.stopScreen {
				close(screenStopped)
			} else {
				close(done)
			}

			select {
			case _, ok := <-events:
				if ok {
					t.Fatal("event forwarder stayed open after shutdown")
				}
			case <-time.After(time.Second):
				t.Fatal("event forwarder did not stop")
			}
		})
	}
}
