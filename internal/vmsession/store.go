// Package vmsession is the relay for VM-provisioning progress, ported from
// p3dx-aaa/src/services/vmProvisioning.service.js. Backs both the
// auto-provision SSE stream and the legacy deploy.sh-driven flow (a
// participant's own local `terraform/participant-vm/deploy.sh` run, reporting
// status back over POST /events with a token instead of a JWT).
//
// A Store made with NewPersistentStore also keeps every run on disk (one JSON
// file per token), so a participant can reopen a run's progress panel days
// later and after an orchestrator restart. Secrets never enter a Session: the
// run's SSH private key stays in provisioning's memory only.
package vmsession

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultRetention is how long a run is kept after its last change — long
// enough to reopen a finished FL run's panel well after the session.
const DefaultRetention = 30 * 24 * time.Hour

// Event is one reported provisioning step.
type Event struct {
	Step    string `json:"step"`
	Command string `json:"command,omitempty"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	At      string `json:"at"`
	// Round/MaxRounds: structured progress of a "Training round" event.
	Round     int `json:"round,omitempty"`
	MaxRounds int `json:"max_rounds,omitempty"`
}

// RunInfo describes a run when it is created.
type RunInfo struct {
	Username     string
	Role         string
	SubmissionID string
	VMName       string
	// OutputOwner is the submission's output owner on a server ("user") VM
	// run started by someone else (the operator), so the owner can list it.
	OutputOwner string
}

// Session tracks one provisioning run. Its JSON form is the on-disk record.
type Session struct {
	// Token is kept in the record because the run is looked up by it (the
	// SSE stream, the runs list) while the file is named by its hash.
	Token        string    `json:"token,omitempty"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	SubmissionID string    `json:"submissionId,omitempty"`
	VMName       string    `json:"vmName,omitempty"`
	OutputOwner  string    `json:"outputOwner,omitempty"`
	Status       string    `json:"status"`
	VMReady      bool      `json:"vmReady"`
	Events       []Event   `json:"events"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	// rev counts changes: the SSE stream re-sends on any change (an event
	// replaced in place keeps len(Events)), and persistence skips a write
	// that a newer one already overtook.
	rev uint64
}

// Store is a thread-safe token -> Session map, optionally persisted.
type Store struct {
	mu        sync.Mutex
	sessions  map[string]*Session
	retention time.Duration

	dir       string // "" = memory only
	writeMu   sync.Mutex
	written   map[string]uint64 // token -> rev last written to disk
	restarted map[string]bool   // tokens Load marked as killed by a restart
}

// NewStore returns a memory-only store (tests, cmd/postapply).
func NewStore() *Store {
	return &Store{sessions: make(map[string]*Session), retention: DefaultRetention, written: map[string]uint64{}}
}

// NewPersistentStore returns a store that keeps every run as
// <dir>/<sha256(token)>.json (dir 0700, files 0600) and loads the runs already there. A run that was still
// provisioning when the previous process stopped can never finish (its
// terraform child and SSH key died with it), so it is marked failed.
func NewPersistentStore(dir string, retention time.Duration) (*Store, error) {
	s := NewStore()
	if retention > 0 {
		s.retention = retention
	}
	s.dir = dir
	s.restarted = map[string]bool{}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

var (
	tokenRe = regexp.MustCompile(`^[0-9a-f]{48}$`)
	hashRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// fileName is a run's on-disk name: the token's sha256, so a directory
// listing or backup does not hand out working run tokens.
func fileName(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:]) + ".json"
}

func (s *Store) path(token string) string { return filepath.Join(s.dir, fileName(token)) }

// CanAccess reports whether username may use the run's token for a
// sensitive action: it is their run, or a server VM run whose output they own.
func (s *Store) CanAccess(token, username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.sessions[token]
	return ok && username != "" && (r.Username == username || (r.Role == "user" && r.OutputOwner == username))
}

func (s *Store) load() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-s.retention)
	s.mu.Lock()
	var dirty []string
	for _, e := range entries {
		base, ok := strings.CutSuffix(e.Name(), ".json")
		if e.IsDir() || !ok || !(tokenRe.MatchString(base) || hashRe.MatchString(base)) {
			continue
		}
		legacy := tokenRe.MatchString(base) // old layout: named by the raw token
		path := filepath.Join(s.dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[vmsession] skipping %s: %v", path, err)
			continue
		}
		var session Session
		if err := json.Unmarshal(raw, &session); err != nil {
			log.Printf("[vmsession] skipping %s: %v", path, err)
			continue
		}
		if session.UpdatedAt.Before(cutoff) {
			_ = os.Remove(path)
			continue
		}
		token := base
		if !legacy {
			token = session.Token
			if !tokenRe.MatchString(token) || fileName(token) != e.Name() {
				log.Printf("[vmsession] skipping %s: token does not match file name", path)
				continue
			}
		}
		session.Token = token
		if legacy {
			// Migrate: rewrite under the hashed name, drop the token-named file.
			if data, err := json.Marshal(&session); err == nil {
				if err := writeAtomic(s.path(token), data); err == nil {
					_ = os.Remove(path)
				} else {
					log.Printf("[vmsession] migrate %s: %v", path, err)
				}
			}
		}
		if session.Events == nil {
			session.Events = []Event{}
		}
		// An auto-create run (it has a VMName) may die before its first
		// event; a bare deploy.sh token ("idle", no VMName) is still usable.
		if !session.VMReady && (session.Status == "running" || (session.Status == "idle" && session.VMName != "")) {
			// Not via appendLocked: that would latch VMReady, but this run
			// has no VM key to download — it died with the old process.
			session.Events = append(session.Events, Event{
				Step: "Provisioning failed", Status: "error", Message: "Orchestrator restarted",
				At: nowStamp(),
			})
			session.Status = "error"
			session.UpdatedAt = time.Now()
			s.restarted[token] = true
			dirty = append(dirty, token)
		}
		session.rev = 1
		s.sessions[token] = &session
	}
	var writes []pendingWrite
	for _, token := range dirty {
		writes = append(writes, s.prepareLocked(token))
	}
	s.mu.Unlock()
	for _, w := range writes {
		s.write(w)
	}
	return nil
}

// Resumable lists the loaded runs that belong to a submission and survived
// the restart, token -> submission, so the caller can re-register them for
// that submission's FL events.
func (s *Store) Resumable() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for token, session := range s.sessions {
		if session.SubmissionID != "" && !s.restarted[token] {
			out[token] = session.SubmissionID
		}
	}
	return out
}

func nowStamp() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00") }

// dropExpiredLocked forgets runs untouched for longer than the retention.
func (s *Store) dropExpiredLocked() {
	cutoff := time.Now().Add(-s.retention)
	for token, session := range s.sessions {
		if session.UpdatedAt.Before(cutoff) {
			delete(s.sessions, token)
			if s.dir != "" {
				_ = os.Remove(s.path(token))
			}
		}
	}
}

type pendingWrite struct {
	token string
	rev   uint64
	data  []byte
}

// prepareLocked bumps the session's revision and snapshots it for write.
func (s *Store) prepareLocked(token string) pendingWrite {
	session := s.sessions[token]
	session.rev++
	if s.dir == "" {
		return pendingWrite{}
	}
	data, err := json.Marshal(session)
	if err != nil {
		log.Printf("[vmsession] marshal run: %v", err)
		return pendingWrite{}
	}
	return pendingWrite{token: token, rev: session.rev, data: data}
}

// write persists one snapshot atomically (temp file + rename). Called
// without s.mu so disk I/O never blocks readers; a snapshot older than one
// already written is dropped, so concurrent writers can't regress the file.
func (s *Store) write(w pendingWrite) {
	if w.data == nil {
		return
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.written[w.token] >= w.rev {
		return
	}
	if err := writeAtomic(s.path(w.token), w.data); err != nil {
		log.Printf("[vmsession] persist run: %v", err)
		return
	}
	s.written[w.token] = w.rev
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("rename %s: %w", path, err)
	}
	return nil
}

// CreateToken mints a token identifying which logged-in user a later
// provisioning run (or deploy.sh invocation) belongs to.
func (s *Store) CreateToken(username, role string) string {
	return s.CreateRun(RunInfo{Username: username, Role: role})
}

// CreateRun mints a run token carrying the run's submission/VM details.
func (s *Store) CreateRun(info RunInfo) string {
	buf := make([]byte, 24)
	_, _ = rand.Read(buf)
	token := hex.EncodeToString(buf)
	now := time.Now()

	s.mu.Lock()
	s.dropExpiredLocked()
	s.sessions[token] = &Session{
		Token:        token,
		Username:     info.Username,
		Role:         info.Role,
		SubmissionID: info.SubmissionID,
		VMName:       info.VMName,
		OutputOwner:  info.OutputOwner,
		Status:       "idle",
		Events:       []Event{},
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	w := s.prepareLocked(token)
	s.mu.Unlock()
	s.write(w)
	return token
}

// AppendEvent records one provisioning step. VMReady latches true the first
// time a run reaches "done" or "error" and never reverts, mirroring the Node
// version — flauto keeps appending further events (waiting for clients,
// starting the FL session) onto this same token afterward, and Status alone
// would flip back to "running" for those, hiding the SSH-key download button
// again; VMReady is what the panel keys that button's visibility on instead.
// Returns false if the token is unknown (e.g. expired).
func (s *Store) AppendEvent(token, step, command, status, message string) bool {
	return s.putEvent(token, Event{Step: step, Command: command, Status: status, Message: message}, false)
}

// ReplaceEvent records ev in place of the run's latest event with the same
// step (appending if there is none) — for progress that would otherwise
// flood the log, like one "Training round" event per round.
func (s *Store) ReplaceEvent(token string, ev Event) bool {
	return s.putEvent(token, ev, true)
}

func (s *Store) putEvent(token string, ev Event, replace bool) bool {
	s.mu.Lock()
	session, ok := s.sessions[token]
	if !ok {
		s.mu.Unlock()
		return false
	}
	ev.At = nowStamp()
	replaced := false
	if replace {
		for i := len(session.Events) - 1; i >= 0; i-- {
			if session.Events[i].Step == ev.Step {
				session.Events[i] = ev
				replaced = true
				break
			}
		}
	}
	if !replaced {
		session.Events = append(session.Events, ev)
	}
	switch ev.Status {
	case "error":
		session.Status = "error"
	case "done":
		session.Status = "done"
	default:
		session.Status = "running"
	}
	if ev.Status == "done" || ev.Status == "error" {
		session.VMReady = true
	}
	session.UpdatedAt = time.Now()
	w := s.prepareLocked(token)
	s.mu.Unlock()
	s.write(w)
	return true
}

// Snapshot is a read-only copy of a session's current state, safe to hold
// after the lock is released.
type Snapshot struct {
	Status  string
	VMReady bool
	Events  []Event
	Rev     uint64 // changes whenever the run does
}

// Get returns a snapshot of one specific run's session, identified by token.
func (s *Store) Get(token string) (Snapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[token]
	if !ok {
		return Snapshot{}, false
	}
	events := make([]Event, len(session.Events))
	copy(events, session.Events)
	return Snapshot{Status: session.Status, VMReady: session.VMReady, Events: events, Rev: session.rev}, true
}

// RunSummary is one run in a ListRuns result.
type RunSummary struct {
	Token        string    `json:"token"`
	Role         string    `json:"role"`
	SubmissionID string    `json:"submissionId"`
	VMName       string    `json:"vmName"`
	Status       string    `json:"status"`
	VMReady      bool      `json:"vmReady"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// ListRuns returns the runs username may reopen, newest first: their own,
// plus server ("user") VM runs started for a submission they own the output
// of. submissionID, if set, narrows to that submission.
func (s *Store) ListRuns(username, submissionID string) []RunSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []RunSummary{}
	if username == "" {
		return out
	}
	for token, r := range s.sessions {
		if r.Username != username && !(r.Role == "user" && r.OutputOwner == username) {
			continue
		}
		if submissionID != "" && r.SubmissionID != submissionID {
			continue
		}
		out = append(out, RunSummary{Token: token, Role: r.Role, SubmissionID: r.SubmissionID, VMName: r.VMName,
			Status: r.Status, VMReady: r.VMReady, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].Token < out[j].Token
	})
	return out
}
