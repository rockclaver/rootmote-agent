package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// fakeClient is a hand-rolled Client used by every Manager.Status test below.
// Each case exercises a distinct unavailable reason so the AC mapping is
// covered end-to-end.
type fakeClient struct {
	info        VersionInfo
	err         error
	containers  []ContainerSummary
	detail      ContainerDetail
	images      []ImageSummary
	imageDetail ImageDetail
	volumes     []VolumeSummary
	networks    []NetworkSummary
	daemon      DaemonInfo
	logs        []LogEntry
	streamLogs  []LogEntry
	streamErr   error
	lastTail    int
	lastSince   time.Time
}

func (f fakeClient) Version(ctx context.Context) (VersionInfo, error) {
	return f.info, f.err
}

func (f fakeClient) Containers(ctx context.Context) ([]ContainerSummary, error) {
	return f.containers, f.err
}

func (f fakeClient) Container(ctx context.Context, id string) (ContainerDetail, error) {
	return f.detail, f.err
}

func (f fakeClient) Images(ctx context.Context) ([]ImageSummary, error) {
	return f.images, f.err
}

func (f fakeClient) Image(ctx context.Context, id string) (ImageDetail, error) {
	return f.imageDetail, f.err
}

func (f fakeClient) Volumes(ctx context.Context) ([]VolumeSummary, error) {
	return f.volumes, f.err
}

func (f fakeClient) Networks(ctx context.Context) ([]NetworkSummary, error) {
	return f.networks, f.err
}

func (f fakeClient) Info(ctx context.Context) (DaemonInfo, error) {
	return f.daemon, f.err
}

func (f fakeClient) ContainerLogs(ctx context.Context, id string, tail int) ([]LogEntry, error) {
	return f.logs, f.err
}

func (f fakeClient) ContainerLogStream(ctx context.Context, id string, since time.Time, emit func(LogEntry)) error {
	for _, entry := range f.streamLogs {
		emit(entry)
	}
	return f.streamErr
}

func newManager(t *testing.T, c Client) *Manager {
	t.Helper()
	m, err := New(Config{Client: c})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return m
}

// AC: docker.status returns availability + version fields when reachable.
func TestStatusReachable(t *testing.T) {
	m := newManager(t, fakeClient{info: VersionInfo{Version: "26.1.4", APIVersion: "1.45"}})
	st := m.Status(context.Background())
	if !st.Available {
		t.Fatalf("expected available, got %+v", st)
	}
	if st.Version != "26.1.4" || st.APIVersion != "1.45" {
		t.Errorf("version fields = %+v", st)
	}
	if st.UnavailableReason != "" {
		t.Errorf("reachable status must not carry an unavailable reason, got %q", st.UnavailableReason)
	}
}

// AC: missing Docker is distinguishable from a down daemon.
func TestStatusMissingDocker(t *testing.T) {
	m := newManager(t, fakeClient{err: errors.New("wrap: " + ErrNotInstalled.Error())})
	st := m.Status(context.Background())
	if st.Available {
		t.Fatal("expected unavailable")
	}
	// errors.Is requires the sentinel be wrapped, not just string-included.
	m = newManager(t, fakeClient{err: wrap(ErrNotInstalled, "socket missing")})
	st = m.Status(context.Background())
	if st.UnavailableReason != ReasonNotInstalled {
		t.Errorf("reason = %q want %q", st.UnavailableReason, ReasonNotInstalled)
	}
	if st.UnavailableMessage == "" {
		t.Error("expected human-readable message on unavailable status")
	}
}

// AC: daemon-unavailable state is distinct from permission denied.
func TestStatusDaemonDown(t *testing.T) {
	m := newManager(t, fakeClient{err: wrap(ErrDaemonDown, "connection refused")})
	st := m.Status(context.Background())
	if st.Available {
		t.Fatal("expected unavailable")
	}
	if st.UnavailableReason != ReasonDaemonDown {
		t.Errorf("reason = %q want %q", st.UnavailableReason, ReasonDaemonDown)
	}
}

// AC: socket permission denied is its own state.
func TestStatusPermissionDenied(t *testing.T) {
	m := newManager(t, fakeClient{err: wrap(ErrPermissionDenied, "EACCES")})
	st := m.Status(context.Background())
	if st.Available {
		t.Fatal("expected unavailable")
	}
	if st.UnavailableReason != ReasonPermissionDenied {
		t.Errorf("reason = %q want %q", st.UnavailableReason, ReasonPermissionDenied)
	}
}

// Anything we don't recognize collapses into ReasonUnknown rather than being
// silently dropped or surfaced as available.
func TestStatusUnknownError(t *testing.T) {
	m := newManager(t, fakeClient{err: errors.New("totally novel failure")})
	st := m.Status(context.Background())
	if st.Available {
		t.Fatal("expected unavailable")
	}
	if st.UnavailableReason != ReasonUnknown {
		t.Errorf("reason = %q want %q", st.UnavailableReason, ReasonUnknown)
	}
}

func TestNewRejectsNilClient(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error when Client is nil")
	}
}

// AC: docker.container.list returns all local containers with ID, name, image,
// status/state, health, ports summary, Compose labels, and project association.
func TestContainerListMapsSummaryFieldsAndProjectAssociation(t *testing.T) {
	m, err := New(Config{
		Client: fakeClient{containers: []ContainerSummary{{
			ID:           "abc123",
			Name:         "api-1",
			Image:        "api:latest",
			Status:       "Up 4 minutes (health: healthy)",
			State:        "running",
			Health:       "healthy",
			PortsSummary: "8080->80/tcp",
			Labels: map[string]string{
				"com.docker.compose.project": "nest",
				"com.docker.compose.service": "api",
			},
			Mounts: []MountSummary{{
				Source: "/var/lib/claver/claver/projects/proj_1/app",
			}},
		}}},
		ProjectRoot: "/var/lib/claver/claver/projects",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Containers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("containers len = %d", len(got))
	}
	c := got[0]
	if c.ID != "abc123" || c.Name != "api-1" || c.Image != "api:latest" || c.State != "running" {
		t.Fatalf("summary fields not mapped: %+v", c)
	}
	if c.Health != "healthy" || c.PortsSummary != "8080->80/tcp" {
		t.Fatalf("health/ports not mapped: %+v", c)
	}
	if c.ComposeProject != "nest" || c.ComposeService != "api" || !c.Managed {
		t.Fatalf("compose grouping not mapped: %+v", c)
	}
	if c.ProjectID != "proj_1" {
		t.Fatalf("project id = %q", c.ProjectID)
	}
}

// AC: Compose-backed containers are grouped by Compose project/service labels
// without editing compose files or running Compose commands.
func TestComposeGroupingComesOnlyFromLabels(t *testing.T) {
	m := newManager(t, fakeClient{containers: []ContainerSummary{{
		ID: "1",
		Labels: map[string]string{
			"com.docker.compose.project": "storefront",
			"com.docker.compose.service": "web",
		},
	}}})
	got, err := m.Containers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ComposeProject != "storefront" || got[0].ComposeService != "web" || !got[0].Managed {
		t.Fatalf("compose grouping = %+v", got[0])
	}
}

// AC: Unmanaged containers are visible and clearly marked as unmanaged.
func TestUnmanagedContainersRemainVisible(t *testing.T) {
	m := newManager(t, fakeClient{containers: []ContainerSummary{{ID: "solo", Name: "redis"}}})
	got, err := m.Containers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Managed {
		t.Fatalf("unmanaged container missing or marked managed: %+v", got)
	}
}

// AC: docker.container.get returns detail with safe inspect fields and
// redacted environment summary.
func TestContainerDetailRedactsEnvironmentAndMapsInspectFields(t *testing.T) {
	m, err := New(Config{
		Client: fakeClient{detail: ContainerDetail{
			ID:            "abc123",
			Name:          "api-1",
			Image:         "api:latest",
			Command:       "npm start",
			Status:        "running",
			State:         "running",
			Health:        "healthy",
			RestartPolicy: "unless-stopped",
			Ports:         []PortSummary{{PrivatePort: 80, PublicPort: 8080, Type: "tcp"}},
			Mounts: []MountSummary{{
				Type:        "bind",
				Source:      "/var/lib/claver/claver/projects/proj_2/app",
				Destination: "/app",
			}},
			Labels: map[string]string{
				"com.docker.compose.project": "nest",
				"com.docker.compose.service": "api",
			},
			EnvironmentVars: []EnvSummary{
				{Key: "DATABASE_URL", Value: "postgres://db", Redacted: false},
				{Key: "API_TOKEN", Value: "REDACTED", Redacted: true},
			},
		}},
		ProjectRoot: "/var/lib/claver/claver/projects",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Container(context.Background(), "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if got.Image != "api:latest" || got.Command != "npm start" || got.RestartPolicy != "unless-stopped" {
		t.Fatalf("inspect fields not mapped: %+v", got)
	}
	if got.ComposeProject != "nest" || got.ComposeService != "api" || got.ProjectID != "proj_2" {
		t.Fatalf("metadata/project fields not enriched: %+v", got)
	}
	if len(got.EnvironmentVars) != 2 || !got.EnvironmentVars[1].Redacted || got.EnvironmentVars[1].Value != "REDACTED" {
		t.Fatalf("env summary not redacted: %+v", got.EnvironmentVars)
	}
}

// Review comment 3326987577: connection-string style environment keys must be
// redacted because values commonly embed credentials.
func TestRedactEnvRedactsConnectionStringKeys(t *testing.T) {
	got := redactEnv([]string{
		"DATABASE_URL=postgres://user:password@host/db",
		"REDIS_URL=redis://:password@host:6379/0",
		"MONGO_URI=mongodb://user:password@host/db",
		"SENTRY_DSN=https://public:secret@sentry.example/1",
		"PUBLIC_HOST=example.com",
	})
	for i, key := range []string{"DATABASE_URL", "REDIS_URL", "MONGO_URI", "SENTRY_DSN"} {
		if got[i].Key != key || !got[i].Redacted || got[i].Value != "REDACTED" {
			t.Fatalf("%s not redacted: %+v", key, got[i])
		}
	}
	if got[4].Redacted {
		t.Fatalf("non-secret host value should remain visible: %+v", got[4])
	}
}

// AC: docker.image.list exposes image IDs, tags, created time, size, labels.
func TestImageListMapsSafeMetadata(t *testing.T) {
	m := newManager(t, fakeClient{images: []ImageSummary{{
		ID:         "sha256:abc",
		Tags:       []string{"nginx:latest"},
		Created:    1700000000,
		Size:       12345,
		Labels:     map[string]string{"maintainer": "team"},
		Containers: 2,
	}}})
	got, err := m.Images(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "sha256:abc" || got[0].Tags[0] != "nginx:latest" {
		t.Fatalf("image summary not mapped: %+v", got)
	}
	if got[0].Created != 1700000000 || got[0].Size != 12345 || got[0].Containers != 2 {
		t.Fatalf("metadata fields not mapped: %+v", got[0])
	}
}

// AC: docker.image.get exposes safe inspect metadata.
func TestImageDetailMapsSafeMetadata(t *testing.T) {
	m := newManager(t, fakeClient{imageDetail: ImageDetail{
		ImageSummary: ImageSummary{ID: "sha256:abc", Tags: []string{"app:v1"}, Size: 99},
		Architecture: "arm64",
		OS:           "linux",
		Author:       "team",
		ParentID:     "sha256:parent",
	}})
	got, err := m.Image(context.Background(), "sha256:abc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Architecture != "arm64" || got.OS != "linux" || got.ParentID != "sha256:parent" {
		t.Fatalf("image inspect not mapped: %+v", got)
	}
}

func TestImageGetRejectsBlankID(t *testing.T) {
	m := newManager(t, fakeClient{})
	if _, err := m.Image(context.Background(), "  "); err == nil {
		t.Fatal("expected error for blank id")
	}
}

// AC: docker.volume.list exposes volume names, drivers, mountpoint, labels,
// and in-use hints when available.
func TestVolumeListMapsFieldsIncludingUsageHint(t *testing.T) {
	m := newManager(t, fakeClient{volumes: []VolumeSummary{
		{Name: "data", Driver: "local", Mountpoint: "/var/lib/docker/volumes/data/_data",
			Labels: map[string]string{"app": "api"}, InUseCount: 2},
		{Name: "orphan", Driver: "local", InUseCount: -1},
	}})
	got, err := m.Volumes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "data" || got[0].Driver != "local" {
		t.Fatalf("volume list not mapped: %+v", got)
	}
	if got[0].Mountpoint == "" || got[0].InUseCount != 2 {
		t.Fatalf("volume mountpoint/usage not mapped: %+v", got[0])
	}
	if got[1].InUseCount != -1 {
		t.Fatalf("unknown usage hint must remain -1: %+v", got[1])
	}
}

// AC: docker.network.list exposes network IDs, names, drivers, scopes,
// labels, and attached-container counts when available.
func TestNetworkListMapsFieldsIncludingAttachedCount(t *testing.T) {
	m := newManager(t, fakeClient{networks: []NetworkSummary{{
		ID: "net1", Name: "bridge", Driver: "bridge", Scope: "local",
		Labels:        map[string]string{"env": "dev"},
		AttachedCount: 3,
	}}})
	got, err := m.Networks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "net1" || got[0].Driver != "bridge" {
		t.Fatalf("network list not mapped: %+v", got)
	}
	if got[0].Scope != "local" || got[0].AttachedCount != 3 {
		t.Fatalf("network scope/attached not mapped: %+v", got[0])
	}
}

// AC: agent tests cover daemon inventory mapping.
func TestDaemonInfoMapsCountsAndVersion(t *testing.T) {
	m := newManager(t, fakeClient{daemon: DaemonInfo{
		Containers: 7, ContainersRunning: 4, ContainersStopped: 3,
		Images: 11, ServerVersion: "26.0.0", OperatingSystem: "Ubuntu 22.04",
	}})
	got, err := m.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Containers != 7 || got.ContainersRunning != 4 || got.Images != 11 {
		t.Fatalf("daemon counts not mapped: %+v", got)
	}
	if got.ServerVersion != "26.0.0" || got.OperatingSystem != "Ubuntu 22.04" {
		t.Fatalf("daemon metadata not mapped: %+v", got)
	}
}

// AC issue #30: docker.container.logs returns a bounded recent log tail with
// stdout/stderr stream markers and timestamps when Docker provides them.
func TestContainerLogsReturnsBoundedTailWithStreamsAndTimestamps(t *testing.T) {
	m := newManager(t, fakeClient{logs: []LogEntry{
		{ContainerID: "abc", Stream: "stdout", Timestamp: "2026-05-29T10:00:00Z", Line: "ready"},
		{ContainerID: "abc", Stream: "stderr", Timestamp: "2026-05-29T10:00:01Z", Line: "warn"},
	}})
	got, err := m.Logs(context.Background(), "abc", MaxLogTail+100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Stream != "stdout" || got[1].Stream != "stderr" {
		t.Fatalf("log stream markers not preserved: %+v", got)
	}
	if got[0].Timestamp == "" || got[1].Line != "warn" {
		t.Fatalf("log timestamp/line not preserved: %+v", got)
	}
}

// AC issue #30: streaming emits follow-up log events and surfaces Docker stream
// termination/errors to callers.
func TestContainerLogsSubscribeStreamsEventsAndErrors(t *testing.T) {
	expectedErr := errors.New("container removed")
	m := newManager(t, fakeClient{
		streamLogs: []LogEntry{{ContainerID: "abc", Stream: "stdout", Line: "next"}},
		streamErr:  expectedErr,
	})
	var got []LogEntry
	err := m.SubscribeLogs(context.Background(), "abc", time.Unix(10, 0), func(entry LogEntry) {
		got = append(got, entry)
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("err = %v want %v", err, expectedErr)
	}
	if len(got) != 1 || got[0].Line != "next" {
		t.Fatalf("streamed logs = %+v", got)
	}
}

// AC issue #30: Docker multiplexed log frames are decoded into stdout/stderr
// events and Docker timestamps are separated from the visible line.
func TestDecodeDockerLogsMultiplexedFrames(t *testing.T) {
	var body bytes.Buffer
	writeDockerLogFrame(&body, 1, "2026-05-29T10:00:00.000000001Z hello\n")
	writeDockerLogFrame(&body, 2, "2026-05-29T10:00:01Z bad\n")
	var got []LogEntry
	if err := decodeDockerLogs(&body, "abc", func(entry LogEntry) {
		got = append(got, entry)
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Stream != "stdout" || got[1].Stream != "stderr" {
		t.Fatalf("decoded stream markers = %+v", got)
	}
	if got[0].Timestamp != "2026-05-29T10:00:00.000000001Z" || got[0].Line != "hello" {
		t.Fatalf("decoded timestamp/line = %+v", got[0])
	}
}

func writeDockerLogFrame(buf *bytes.Buffer, stream byte, line string) {
	header := make([]byte, 8)
	header[0] = stream
	binary.BigEndian.PutUint32(header[4:8], uint32(len(line)))
	buf.Write(header)
	buf.WriteString(line)
}

// SocketClient image list strips Docker's "<none>:<none>" placeholders so the
// UI never has to special-case them.
func TestDropNoneTagsStripsPlaceholders(t *testing.T) {
	got := dropNoneTags([]string{"<none>:<none>", "", "real:tag"})
	if len(got) != 1 || got[0] != "real:tag" {
		t.Fatalf("expected only 'real:tag', got %v", got)
	}
	if dropNoneTags([]string{"<none>:<none>"}) != nil {
		t.Fatal("placeholder-only slice must collapse to nil")
	}
}

// wrap returns an error chain whose root is sentinel, so errors.Is works.
func wrap(sentinel error, msg string) error {
	return errWithCause{msg: msg, cause: sentinel}
}

type errWithCause struct {
	msg   string
	cause error
}

func (e errWithCause) Error() string { return e.msg + ": " + e.cause.Error() }
func (e errWithCause) Unwrap() error { return e.cause }
