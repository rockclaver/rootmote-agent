package watchtower

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Playbook statuses returned by the relay (contract C4).
const (
	PlaybookOK              = "ok"
	PlaybookNone            = "no_playbook"
	PlaybookLimitReached    = "limit_reached"
	PlaybookConsentRequired = "consent_required"
	PlaybookUnavailable     = "unavailable"
)

// playbookTimeout bounds one playbook request. The relay may wait on a slow
// model, so this is much longer than the default request timeout.
const playbookTimeout = 3 * time.Minute

// PlaybookSignature is one deterministic finding sent with a request.
type PlaybookSignature struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// PlaybookCompose names one Compose service and its project.
type PlaybookCompose struct {
	Project string `json:"project"`
	Service string `json:"service"`
}

// PlaybookPM2 names one PM2 app and the user that owns it.
type PlaybookPM2 struct {
	User string `json:"user"`
	App  string `json:"app"`
}

// PlaybookInventory is the names-only list of things a step may target.
type PlaybookInventory struct {
	Units              []string          `json:"units"`
	Containers         []string          `json:"containers"`
	ComposeServices    []PlaybookCompose `json:"compose_services"`
	PM2Apps            []PlaybookPM2     `json:"pm2_apps"`
	SupervisorPrograms []string          `json:"supervisor_programs"`
	Certs              []string          `json:"certs"`
	URLs               []string          `json:"urls"`
	Ports              []int             `json:"ports"`
}

// PlaybookMetrics is the resource snapshot sent with a request.
type PlaybookMetrics struct {
	CPUPercent   float64 `json:"cpuPercent"`
	MemPercent   float64 `json:"memPercent"`
	DiskPercent  float64 `json:"diskPercent"`
	InodePercent float64 `json:"inodePercent"`
	Load1        float64 `json:"load1"`
	MemTotalMB   float64 `json:"memTotalMB"`
	SwapTotalMB  float64 `json:"swapTotalMB"`
}

// PlaybookOS names the distribution.
type PlaybookOS struct {
	Distro  string `json:"distro"`
	Version string `json:"version"`
}

// PlaybookRequest is the body of POST /v1/agents/playbooks (contract C4).
// The caller redacts it before it gets here.
type PlaybookRequest struct {
	IncidentID     string              `json:"incidentId"`
	Kind           string              `json:"kind"`
	Severity       string              `json:"severity"`
	Signatures     []PlaybookSignature `json:"signatures"`
	Inventory      PlaybookInventory   `json:"inventory"`
	Metrics        PlaybookMetrics     `json:"metrics"`
	OS             PlaybookOS          `json:"os"`
	Logs           []string            `json:"logs"`
	CatalogVersion int                 `json:"catalogVersion"`
	UserRequested  bool                `json:"userRequested"`
}

// PlaybookStep is one catalog step in a returned playbook.
type PlaybookStep struct {
	Step   string         `json:"step"`
	Params map[string]any `json:"params"`
}

// PlaybookManual is one step the user does by hand.
type PlaybookManual struct {
	Text    string `json:"text"`
	Command string `json:"command,omitempty"`
}

// PlaybookDraft is the playbook the relay returns with status "ok".
type PlaybookDraft struct {
	Title           string           `json:"title"`
	Summary         string           `json:"summary"`
	ReviewCarefully bool             `json:"reviewCarefully"`
	Steps           []PlaybookStep   `json:"steps"`
	Manual          []PlaybookManual `json:"manual"`
}

// PlaybookResponse is the relay's answer. Playbook is set only when Status
// is PlaybookOK; Message is plain English for every other status.
type PlaybookResponse struct {
	Status   string         `json:"status"`
	Message  string         `json:"message"`
	Playbook *PlaybookDraft `json:"playbook,omitempty"`
}

// RequestPlaybook sends the redacted problem report to the relay with the
// same signed envelope the heartbeat uses and returns its answer. A non-200
// reply is an error (transport or authentication failure); every playbook
// outcome, including refusals, arrives as a 200 with a status.
func (c *Client) RequestPlaybook(ctx context.Context, in PlaybookRequest) (PlaybookResponse, error) {
	c.mu.Lock()
	if c.creds == nil {
		c.mu.Unlock()
		return PlaybookResponse{}, ErrNotEnrolled
	}
	next := *c.creds
	next.Seq++
	if err := saveCreds(c.DataDir, &next); err != nil {
		c.mu.Unlock()
		return PlaybookResponse{}, fmt.Errorf("watchtower: persist sequence: %w", err)
	}
	c.creds = &next
	creds := next
	c.mu.Unlock()

	payloadBytes, err := json.Marshal(in)
	if err != nil {
		return PlaybookResponse{}, err
	}
	nonce, err := newNonce()
	if err != nil {
		return PlaybookResponse{}, err
	}
	timestamp := c.now().UTC().Format(time.RFC3339)
	payloadHash := PayloadHash(payloadBytes)
	sig, err := Sign(creds.Secret, SigningString(creds.AgentID, creds.ServerID, creds.Seq, timestamp, nonce, payloadHash))
	if err != nil {
		return PlaybookResponse{}, err
	}
	body, err := json.Marshal(envelope{
		AgentID:        creds.AgentID,
		ServerID:       creds.ServerID,
		SequenceNumber: creds.Seq,
		Timestamp:      timestamp,
		Nonce:          nonce,
		PayloadHash:    payloadHash,
		Payload:        json.RawMessage(payloadBytes),
		Signature:      sig,
	})
	if err != nil {
		return PlaybookResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, playbookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, creds.RelayURL+"/v1/agents/playbooks", bytes.NewReader(body))
	if err != nil {
		return PlaybookResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.playbookHTTP().Do(req)
	if err != nil {
		return PlaybookResponse{}, fmt.Errorf("watchtower: playbooks: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return PlaybookResponse{}, fmt.Errorf("watchtower: playbooks: relay returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var out PlaybookResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return PlaybookResponse{}, fmt.Errorf("watchtower: playbooks: decode response: %w", err)
	}
	return out, nil
}

func (c *Client) playbookHTTP() HTTPDoer {
	if c.PlaybookHTTP != nil {
		return c.PlaybookHTTP
	}
	return &http.Client{Timeout: playbookTimeout}
}
