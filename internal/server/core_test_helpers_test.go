package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/rockclaver/rootmote-agent/internal/docker"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
)

func startTestServerWith(t *testing.T, cfg Config) (wsURL string, stop func()) {
	t.Helper()
	srv := New(cfg)
	ln, err := srv.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx, ln)
		close(done)
	}()
	stop = func() {
		cancel()
		<-done
	}
	return "ws://" + ln.Addr().String() + "/ws", stop
}

func dockerRoundTripConfig(t *testing.T, cfg Config, kind string, payload []byte) Frame {
	t.Helper()
	wsURL, stop := startTestServerWith(t, cfg)
	t.Cleanup(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(websocket.StatusNormalClosure, "") })
	req, _ := json.Marshal(Frame{ID: "1", Kind: kind, Payload: payload})
	if err := c.Write(ctx, websocket.MessageText, req); err != nil {
		t.Fatal(err)
	}
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var resp Frame
	_ = json.Unmarshal(data, &resp)
	return resp
}

type fakeDockerClient struct {
	v               docker.VersionInfo
	err             error
	containers      []docker.ContainerSummary
	detail          docker.ContainerDetail
	images          []docker.ImageSummary
	imageDetail     docker.ImageDetail
	volumes         []docker.VolumeSummary
	networks        []docker.NetworkSummary
	daemon          docker.DaemonInfo
	logs            []docker.LogEntry
	streamLogs      []docker.LogEntry
	streamErr       error
	blockStream     bool
	streamStarted   chan struct{}
	streamCancelled chan struct{}

	statsSample      docker.StatsSample
	statsErr         error
	statsStream      []docker.StatsSample
	statsStreamErr   error
	statsBlockStream bool
	statsStarted     chan struct{}
	statsCancelled   chan struct{}

	actionCalls *[]string
	actionErr   error
}

func (f fakeDockerClient) Version(context.Context) (docker.VersionInfo, error) {
	return f.v, f.err
}

func (f fakeDockerClient) Containers(context.Context) ([]docker.ContainerSummary, error) {
	return f.containers, f.err
}

func (f fakeDockerClient) Container(context.Context, string) (docker.ContainerDetail, error) {
	return f.detail, f.err
}

func (f fakeDockerClient) Images(context.Context) ([]docker.ImageSummary, error) {
	return f.images, f.err
}

func (f fakeDockerClient) Image(context.Context, string) (docker.ImageDetail, error) {
	return f.imageDetail, f.err
}

func (f fakeDockerClient) Volumes(context.Context) ([]docker.VolumeSummary, error) {
	return f.volumes, f.err
}

func (f fakeDockerClient) Networks(context.Context) ([]docker.NetworkSummary, error) {
	return f.networks, f.err
}

func (f fakeDockerClient) Info(context.Context) (docker.DaemonInfo, error) {
	return f.daemon, f.err
}

func (f fakeDockerClient) ContainerLogs(context.Context, string, int) ([]docker.LogEntry, error) {
	return f.logs, f.err
}

func (f fakeDockerClient) ContainerLogStream(ctx context.Context, id string, since time.Time, emit func(docker.LogEntry)) error {
	if f.blockStream {
		if f.streamStarted != nil {
			close(f.streamStarted)
		}
		<-ctx.Done()
		if f.streamCancelled != nil {
			close(f.streamCancelled)
		}
		return ctx.Err()
	}
	for _, entry := range f.streamLogs {
		emit(entry)
	}
	return f.streamErr
}

func (f fakeDockerClient) ContainerStats(context.Context, string) (docker.StatsSample, error) {
	return f.statsSample, f.statsErr
}

func (f fakeDockerClient) ContainerStatsStream(ctx context.Context, id string, emit func(docker.StatsSample)) error {
	if f.statsBlockStream {
		if f.statsStarted != nil {
			close(f.statsStarted)
		}
		<-ctx.Done()
		if f.statsCancelled != nil {
			close(f.statsCancelled)
		}
		return ctx.Err()
	}
	for _, s := range f.statsStream {
		emit(s)
	}
	return f.statsStreamErr
}

func (f fakeDockerClient) ContainerAction(_ context.Context, id string, action docker.ContainerAction) error {
	if f.actionCalls != nil {
		*f.actionCalls = append(*f.actionCalls, id+":"+string(action))
	}
	if f.actionErr != nil {
		return f.actionErr
	}
	return f.err
}

func (f fakeDockerClient) PruneImages(context.Context) (docker.PruneResult, error) {
	return docker.PruneResult{}, f.err
}

func (f fakeDockerClient) PruneBuildCache(context.Context) (docker.PruneResult, error) {
	return docker.PruneResult{}, f.err
}

type fakeSystemdClient struct {
	units     []systemd.Unit
	details   map[string]systemd.UnitDetail
	available error
	actions   []string
	actionErr error
}

func (f *fakeSystemdClient) Available(_ context.Context) error { return f.available }
func (f *fakeSystemdClient) Status(_ context.Context) systemd.Status {
	if f.available != nil {
		return systemd.Status{
			Available:          false,
			UnavailableReason:  "test_unavailable",
			UnavailableMessage: f.available.Error(),
		}
	}
	return systemd.Status{Available: true}
}
func (f *fakeSystemdClient) List(_ context.Context) ([]systemd.Unit, error) {
	return append([]systemd.Unit(nil), f.units...), nil
}
func (f *fakeSystemdClient) Get(_ context.Context, name string) (systemd.UnitDetail, error) {
	if d, ok := f.details[name]; ok {
		return d, nil
	}
	return systemd.UnitDetail{}, errors.New("not found")
}
func (f *fakeSystemdClient) Action(_ context.Context, name string, action systemd.Action) error {
	f.actions = append(f.actions, name+":"+string(action))
	return f.actionErr
}

func systemdRoundTrip(t *testing.T, cfg Config, kind string, payload []byte) Frame {
	t.Helper()
	return dockerRoundTripConfig(t, cfg, kind, payload)
}
func readFrame(t *testing.T, ctx context.Context, c *websocket.Conn, id string) Frame {
	t.Helper()
	for {
		_, raw, err := c.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var frame Frame
		if err := json.Unmarshal(raw, &frame); err != nil {
			t.Fatal(err)
		}
		if frame.ID == id {
			return frame
		}
	}
}

func mustWriteFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeProcFixture(t *testing.T, root string, pid int, comm, uid, cmdline string, utime, stime, start, rss int) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	fields := []string{"S", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", fmt.Sprintf("%d", utime), fmt.Sprintf("%d", stime), "0", "0", "20", "0", "1", "0", fmt.Sprintf("%d", start), "0", fmt.Sprintf("%d", rss)}
	mustWriteFile(t, filepath.Join(dir, "stat"), fmt.Sprintf("%d (%s) %s\n", pid, comm, strings.Join(fields, " ")))
	mustWriteFile(t, filepath.Join(dir, "status"), "Name:\t"+comm+"\nUid:\t"+uid+"\t"+uid+"\t"+uid+"\t"+uid+"\n")
	mustWriteFile(t, filepath.Join(dir, "cmdline"), cmdline)
	mustWriteFile(t, filepath.Join(dir, "statm"), "100 "+fmt.Sprintf("%d", rss)+" 0 0 0 0 0\n")
	mustWriteFile(t, filepath.Join(dir, "comm"), comm+"\n")
}
