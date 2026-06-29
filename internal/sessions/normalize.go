// normalize.go defines the normalized agent event/command schema (the contract
// from plans/structured-agent-ui.md, Appendix A) that the Claude and Codex
// structured runtimes translate their native protocols into. Normalized events
// ride the existing session.event frame as store.SessionEvent{Type, Data}, where
// Data is the JSON-encoded payload. A zero Seq marks an event as ephemeral
// (live-only); finalized events are persisted and replayed on reconnect.
//
// The terminal transport keeps emitting "stdout"/"lifecycle"/"prompt"/"memory";
// the constants here are additive and never collide with those.
package sessions

import (
	"encoding/json"

	"github.com/rockclaver/claver-agent/internal/store"
)

// Normalized SessionEvent.Type values for structured sessions.
const (
	EvMessageDelta    = "message_delta"
	EvMessage         = "message"
	EvReasoning       = "reasoning"
	EvToolCall        = "tool_call"
	EvDiff            = "diff"
	EvPlan            = "plan"
	EvApprovalRequest = "approval_request"
	EvUsage           = "usage"
	EvTurn            = "turn"
	EvError           = "error"
)

// Tool-call lifecycle states (ToolCall.Status).
const (
	ToolStarted   = "started"
	ToolUpdated   = "updated"
	ToolCompleted = "completed"
	ToolFailed    = "failed"
)

// Turn states (Turn.State).
const (
	TurnStarted  = "started"
	TurnComplete = "complete"
)

// Approval kinds (ApprovalRequest.Kind).
const (
	ApprovalCommand = "command"
	ApprovalEdit    = "edit"
	ApprovalPlan    = "plan"
)

// Approval decisions accepted by Manager.SendApproval (session.approval).
const (
	DecisionAllow       = "allow"
	DecisionAllowAlways = "allow_always"
	DecisionDeny        = "deny"
)

// Permission/run modes accepted by Manager.SetMode (session.set_mode).
const (
	ModePlan        = "plan"
	ModeDefault     = "default"
	ModeAcceptEdits = "acceptEdits"
	ModeYolo        = "yolo"
)

// Transport selects how a session's agent CLI is driven. Terminal is the legacy
// tmux TUI + ANSI byte stream; Structured speaks the CLI's machine protocol and
// emits the normalized events above. Terminal is the default until cutover.
const (
	TransportTerminal   = "terminal"
	TransportStructured = "structured"
)

// MessageDelta is a streaming chunk of an in-progress message. Emitted
// ephemerally (Seq 0); the finalized block arrives later as Message.
type MessageDelta struct {
	Role string `json:"role"`
	Text string `json:"text"`
}

// MessageBlock is one content block of a finalized message.
type MessageBlock struct {
	Kind string `json:"kind"`
	Text string `json:"text,omitempty"`
}

// Message is a finalized message turn block, persisted for replay.
type Message struct {
	Role   string         `json:"role"`
	Text   string         `json:"text"`
	Blocks []MessageBlock `json:"blocks,omitempty"`
}

// Reasoning is a (collapsible) model thinking block.
type Reasoning struct {
	Text string `json:"text"`
}

// ToolCall is one tool invocation and its evolving state. Args is the raw tool
// input as the CLI reported it, passed through untouched for the UI to render.
type ToolCall struct {
	CallID string          `json:"call_id"`
	Name   string          `json:"name"`
	Args   json.RawMessage `json:"args,omitempty"`
	Status string          `json:"status"`
	Result string          `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Diff is a single file edit expressed as a unified-diff patch.
type Diff struct {
	CallID string `json:"call_id,omitempty"`
	Path   string `json:"path"`
	Patch  string `json:"patch"`
}

// PlanItem is one step of an agent plan.
type PlanItem struct {
	Title  string `json:"title"`
	Status string `json:"status"`
}

// Plan is the agent's plan. Gating is true only when proceeding requires an
// explicit approval (Claude plan mode); Codex plans are display-only (false).
type Plan struct {
	Items  []PlanItem `json:"items"`
	Gating bool       `json:"gating"`
}

// ApprovalRequest asks the user to allow or deny a proposed action. One
// request/response pair (session.approval) unifies Claude canUseTool +
// ExitPlanMode and Codex exec/patch approvals.
type ApprovalRequest struct {
	RequestID string   `json:"request_id"`
	Kind      string   `json:"kind"`
	Summary   string   `json:"summary"`
	Detail    string   `json:"detail,omitempty"`
	Options   []string `json:"options,omitempty"`
}

// Usage is token/cost accounting for a turn, sourced from the CLI's structured
// usage rather than scraped from the transcript.
type Usage struct {
	Input   int     `json:"input"`
	Output  int     `json:"output"`
	Cache   int     `json:"cache"`
	CostUSD float64 `json:"cost_usd"`
}

// Turn marks a turn boundary.
type Turn struct {
	State      string `json:"state"`
	StopReason string `json:"stop_reason,omitempty"`
}

// ErrorEvent is a runtime/protocol error surfaced to the client. Fatal means
// the session has ended.
type ErrorEvent struct {
	Message string `json:"message"`
	Fatal   bool   `json:"fatal"`
}

// normalizedEvent builds a store.SessionEvent of evType carrying the JSON
// encoding of payload. Seq is assigned by the store on append; pass the result
// to Manager.Publish (persisted) or Manager.publishEphemeral (live-only).
func normalizedEvent(sessionID, evType string, payload any) (store.SessionEvent, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return store.SessionEvent{}, err
	}
	return store.SessionEvent{SessionID: sessionID, Type: evType, Data: string(data)}, nil
}

// normalizeTransport returns a valid transport, defaulting empty or unknown
// values to the safe terminal transport.
func normalizeTransport(t string) string {
	if t == TransportStructured {
		return TransportStructured
	}
	return TransportTerminal
}
