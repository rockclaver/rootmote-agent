// Package watchtower is the agent-side client for the Rootmote Watchtower
// cloud spine (issue #79): a signed-envelope heartbeat sent to a relay so a
// phone gets paged when an agent goes dark. It is a pure outbound HTTP
// client -- it opens no listening socket of its own and rides entirely on
// the agent's existing egress.
//
// Enrollment state (relay URL, minted agentId/serverId, the HMAC secret,
// and the last-sent sequence number) is persisted to a 0600 credential file
// so a restart resumes without re-enrolling and never reuses a sequence
// number the relay may already have processed.
package watchtower

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Creds is the persisted enrollment state for one relay, mirroring the
// exact JSON shape the wire contract specifies for
// <dataDir>/watchtower.cred.
type Creds struct {
	RelayURL string `json:"relayUrl"`
	AgentID  string `json:"agentId"`
	ServerID string `json:"serverId"`
	Secret   string `json:"secret"`
	Seq      int64  `json:"seq"`
}

// CredFileName is the credential file's basename inside the agent's data dir.
const CredFileName = "watchtower.cred"

// CredPath returns the full path to the credential file for dataDir.
func CredPath(dataDir string) string {
	return filepath.Join(dataDir, CredFileName)
}

// DefaultInterval is the heartbeat cadence Run uses when given interval<=0.
const DefaultInterval = 30 * time.Second

// ErrNotEnrolled is returned by Heartbeat when the client has no
// credentials yet (Enroll has never succeeded).
var ErrNotEnrolled = errors.New("watchtower: not enrolled")

// HTTPDoer is satisfied by *http.Client and any test stub.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func defaultHTTPClient(c HTTPDoer) HTTPDoer {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// LoadCreds reads the credential file at CredPath(dataDir). It returns
// (nil, nil) when the file does not exist -- an agent that has never
// enrolled is not an error condition. Enforces 0600 on every successful
// load (mirroring loadOrCreateControlPlaneKey in cmd/rootmote-agent) so an
// earlier version or a manual edit that left the HMAC secret group/other
// readable can't quietly widen access.
func LoadCreds(dataDir string) (*Creds, error) {
	path := CredPath(dataDir)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var c Creds
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("watchtower: parse %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	return &c, nil
}

// saveCreds writes c to CredPath(dataDir) as 0600. Written then chmod'd
// explicitly (rather than relying solely on WriteFile's mode) so the file
// ends up 0600 regardless of the process umask.
func saveCreds(dataDir string, c *Creds) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	path := CredPath(dataDir)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// Client is a pure outbound Watchtower client for one relay enrollment.
// Safe for concurrent use: Enroll and Heartbeat/Run may be called from
// different goroutines (e.g. Run's ticking loop and a control-plane
// watchtower.enable request racing an initial enrollment).
type Client struct {
	// DataDir is the agent's data directory; the credential file lives at
	// CredPath(DataDir).
	DataDir string
	// AgentVersion is reported to the relay on register and on every
	// heartbeat payload.
	AgentVersion string
	// HTTP performs outbound requests. Defaults to a 10s-timeout
	// *http.Client when nil.
	HTTP HTTPDoer
	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
	// Logf receives non-fatal diagnostics (unenrolled skips, heartbeat
	// failures). Defaults to log.Printf; set to nil to silence.
	Logf func(format string, args ...any)

	mu      sync.Mutex
	creds   *Creds
	runOnce sync.Once
}

// NewClient constructs a Client, loading any existing credential file from
// dataDir. A nil Client.Creds() result means the agent is not yet enrolled;
// that is not an error.
func NewClient(dataDir, agentVersion string, httpClient HTTPDoer) (*Client, error) {
	creds, err := LoadCreds(dataDir)
	if err != nil {
		return nil, err
	}
	return &Client{
		DataDir:      dataDir,
		AgentVersion: agentVersion,
		HTTP:         defaultHTTPClient(httpClient),
		Now:          time.Now,
		Logf:         log.Printf,
		creds:        creds,
	}, nil
}

// Creds returns a copy of the current enrollment state, or nil when the
// client has never enrolled.
func (c *Client) Creds() *Creds {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.creds == nil {
		return nil
	}
	cp := *c.creds
	return &cp
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) log(format string, args ...any) {
	if c.Logf != nil {
		c.Logf("rootmote-agent: watchtower: "+format, args...)
	}
}

func (c *Client) http() HTTPDoer {
	return defaultHTTPClient(c.HTTP)
}

type registerRequest struct {
	EnrollmentCode string `json:"enrollmentCode"`
	AgentVersion   string `json:"agentVersion"`
}

type registerResponse struct {
	AgentID  string `json:"agentId"`
	ServerID string `json:"serverId"`
	Secret   string `json:"secret"`
}

// Enroll calls POST relayURL/v1/agents/register with the one-time
// enrollmentCode, persists the returned credentials to the cred file
// (0600), and updates the client's in-memory state. Re-enrolling (e.g. to
// rotate the secret or move the agent onto a different relay) overwrites
// any existing credentials; the sequence counter resets to 0 since it is
// scoped to the newly minted agentId.
func (c *Client) Enroll(ctx context.Context, relayURL, enrollmentCode string) (*Creds, error) {
	relayURL = strings.TrimRight(relayURL, "/")
	if relayURL == "" {
		return nil, errors.New("watchtower: relayURL required")
	}
	if enrollmentCode == "" {
		return nil, errors.New("watchtower: enrollmentCode required")
	}
	body, err := json.Marshal(registerRequest{EnrollmentCode: enrollmentCode, AgentVersion: c.AgentVersion})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, relayURL+"/v1/agents/register", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("watchtower: register: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("watchtower: register: relay returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var out registerResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("watchtower: register: decode response: %w", err)
	}
	if out.AgentID == "" || out.ServerID == "" || out.Secret == "" {
		return nil, fmt.Errorf("watchtower: register: incomplete response from relay")
	}
	creds := &Creds{RelayURL: relayURL, AgentID: out.AgentID, ServerID: out.ServerID, Secret: out.Secret, Seq: 0}
	if err := saveCreds(c.DataDir, creds); err != nil {
		return nil, fmt.Errorf("watchtower: persist credentials: %w", err)
	}
	c.mu.Lock()
	c.creds = creds
	c.mu.Unlock()
	return creds, nil
}

type heartbeatPayload struct {
	Kind         string `json:"kind"`
	AgentVersion string `json:"agentVersion"`
}

type envelope struct {
	AgentID        string          `json:"agentId"`
	ServerID       string          `json:"serverId"`
	SequenceNumber int64           `json:"sequenceNumber"`
	Timestamp      string          `json:"timestamp"`
	Nonce          string          `json:"nonce"`
	PayloadHash    string          `json:"payloadHash"`
	Payload        json.RawMessage `json:"payload"`
	Signature      string          `json:"signature"`
}

// SigningString builds the exact newline-joined string the relay
// recomputes the HMAC over, per the watchtower wire contract:
//
//	agentId + "\n" + serverId + "\n" + seq + "\n" + timestamp + "\n" + nonce + "\n" + payloadHash
func SigningString(agentID, serverID string, seq int64, timestamp, nonce, payloadHash string) string {
	return strings.Join([]string{agentID, serverID, strconv.FormatInt(seq, 10), timestamp, nonce, payloadHash}, "\n")
}

// PayloadHash hex-encodes sha256(payloadBytes) -- the exact bytes carried
// verbatim in envelope.payload, so the relay's raw-bytes rehash matches.
func PayloadHash(payloadBytes []byte) string {
	sum := sha256.Sum256(payloadBytes)
	return hex.EncodeToString(sum[:])
}

// Sign returns hex(HMAC_SHA256(secret, signingString)); secret is the
// agent's hex-encoded shared secret.
func Sign(secret, signingString string) (string, error) {
	key, err := hex.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("watchtower: decode secret: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingString))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Heartbeat builds and signs one event envelope carrying a {kind:"heartbeat"}
// payload and POSTs it to relayURL/v1/agents/heartbeat. The sequence number
// is incremented and persisted to the credential file BEFORE the request is
// sent, so a crash mid-request never reuses a sequence number the relay may
// already have processed. Returns ErrNotEnrolled if Enroll has not
// succeeded yet.
func (c *Client) Heartbeat(ctx context.Context) error {
	c.mu.Lock()
	if c.creds == nil {
		c.mu.Unlock()
		return ErrNotEnrolled
	}
	next := *c.creds
	next.Seq++
	if err := saveCreds(c.DataDir, &next); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("watchtower: persist sequence: %w", err)
	}
	c.creds = &next
	creds := next
	c.mu.Unlock()

	payload := heartbeatPayload{Kind: "heartbeat", AgentVersion: c.AgentVersion}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	timestamp := c.now().UTC().Format(time.RFC3339)
	payloadHash := PayloadHash(payloadBytes)
	signingString := SigningString(creds.AgentID, creds.ServerID, creds.Seq, timestamp, nonce, payloadHash)
	sig, err := Sign(creds.Secret, signingString)
	if err != nil {
		return err
	}
	env := envelope{
		AgentID:        creds.AgentID,
		ServerID:       creds.ServerID,
		SequenceNumber: creds.Seq,
		Timestamp:      timestamp,
		Nonce:          nonce,
		PayloadHash:    payloadHash,
		Payload:        json.RawMessage(payloadBytes),
		Signature:      sig,
	}
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, creds.RelayURL+"/v1/agents/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("watchtower: heartbeat: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("watchtower: heartbeat: relay returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// Run starts the outbound heartbeat loop: every interval (DefaultInterval
// when interval<=0) it sends one heartbeat if enrolled. It opens no
// listening socket of its own -- purely outbound HTTP. Being unenrolled is
// logged, never fatal: Run keeps ticking so a later Enroll (e.g. via the
// agent's watchtower.enable control-plane kind) is picked up on the very
// next tick. Returns when ctx is done.
func (c *Client) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.Creds() == nil {
				c.log("not enrolled, skipping heartbeat")
				continue
			}
			if err := c.Heartbeat(ctx); err != nil {
				c.log("heartbeat failed: %v", err)
			}
		}
	}
}

// EnsureRunning starts the heartbeat loop in a background goroutine on the
// first call; later calls are no-ops. The loop runs for the process's
// lifetime (context.Background()), independent of whatever triggered the
// call -- in particular, independent of any single WebSocket connection --
// since heartbeats must keep flowing after the mobile app disconnects.
// Safe to call from both agent boot (when pre-configured with a relay URL
// or an existing cred file) and the watchtower.enable control-plane kind
// (first enable via the mobile app): whichever fires first wins, and only
// one Run loop is ever started.
func (c *Client) EnsureRunning(interval time.Duration) {
	c.runOnce.Do(func() {
		go c.Run(context.Background(), interval)
	})
}
