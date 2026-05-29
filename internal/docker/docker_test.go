package docker

import (
	"context"
	"errors"
	"testing"
)

// fakeClient is a hand-rolled Client used by every Manager.Status test below.
// Each case exercises a distinct unavailable reason so the AC mapping is
// covered end-to-end.
type fakeClient struct {
	info       VersionInfo
	err        error
	containers []ContainerSummary
	detail     ContainerDetail
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
