package sessions

import (
	"context"
	"errors"
	"testing"
)

func TestStartDefaultsTransportToTerminal(t *testing.T) {
	m, rt := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "claude", "manual", ""); err != nil {
		t.Fatal(err)
	}
	sess, err := m.Store.GetSession("s1")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Transport != TransportTerminal {
		t.Fatalf("transport = %q want terminal", sess.Transport)
	}
	if len(rt.started) != 1 || rt.started[0].Transport != TransportTerminal {
		t.Fatalf("spec transport = %+v", rt.started)
	}
}

func TestStartPersistsStructuredTransport(t *testing.T) {
	m, rt := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "codex", "manual", TransportStructured); err != nil {
		t.Fatal(err)
	}
	sess, err := m.Store.GetSession("s1")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Transport != TransportStructured {
		t.Fatalf("transport = %q want structured", sess.Transport)
	}
	// The spec carries the transport so Phase 1 can select a structured runtime.
	if len(rt.started) != 1 || rt.started[0].Transport != TransportStructured {
		t.Fatalf("spec transport = %+v", rt.started)
	}
}

func TestSendApprovalReachesRuntime(t *testing.T) {
	m, rt := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "claude", "manual", TransportStructured); err != nil {
		t.Fatal(err)
	}
	if err := m.SendApproval(context.Background(), "s1", "req_1", DecisionAllow, "ok"); err != nil {
		t.Fatal(err)
	}
	if len(rt.approvals) != 1 || rt.approvals[0] != "s1:req_1:allow:ok" {
		t.Fatalf("approvals = %v", rt.approvals)
	}
}

func TestSetModeReachesRuntime(t *testing.T) {
	m, rt := newTestManager(t)
	if _, err := m.Start(context.Background(), "p1", "claude", "manual", TransportStructured); err != nil {
		t.Fatal(err)
	}
	if err := m.SetMode(context.Background(), "s1", ModePlan); err != nil {
		t.Fatal(err)
	}
	if len(rt.modes) != 1 || rt.modes[0] != "s1:"+ModePlan {
		t.Fatalf("modes = %v", rt.modes)
	}
}

func TestSendApprovalUnknownSession(t *testing.T) {
	m, _ := newTestManager(t)
	if err := m.SendApproval(context.Background(), "nope", "r", DecisionDeny, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}

func TestSetModeUnknownSession(t *testing.T) {
	m, _ := newTestManager(t)
	if err := m.SetMode(context.Background(), "nope", ModeDefault); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}

func TestTmuxRuntimeRejectsStructuredOps(t *testing.T) {
	var rt TmuxRuntime
	if err := rt.SendApproval(context.Background(), "s", "r", DecisionAllow, ""); !errors.Is(err, ErrNotStructured) {
		t.Fatalf("SendApproval err = %v want ErrNotStructured", err)
	}
	if err := rt.SetMode(context.Background(), "s", ModePlan); !errors.Is(err, ErrNotStructured) {
		t.Fatalf("SetMode err = %v want ErrNotStructured", err)
	}
}
