// Package vmcred holds Flotilla VM credentials between the moment p3dx-aaa
// hands one over (POST /p3dx/internal/vm-credentials) and the moment the
// provisioning run writes it onto the provider's new client VM.
//
// A credential is a Keycloak offline token for the flotilla-vm client — it
// lets the VM's sidecar rejoin the FL session as that provider — so it is
// handled as a secret throughout:
//   - memory only: never written to disk, logs, SSE events or terraform;
//   - Claim binds it once to the provisioning run of the same provider and
//     submission (anything else is refused);
//   - Take hands the bytes out exactly once and wipes the stored copy;
//   - a credential not taken within the TTL is wiped and dropped (its
//     Keycloak session still ends at contract expiry; p3dx-aaa's sweeper
//     removes it).
package vmcred

import (
	"errors"
	"log"
	"sync"
	"time"
)

var (
	ErrUnknown  = errors.New("unknown or expired VM credential")
	ErrMismatch = errors.New("VM credential belongs to a different provider or submission")
	ErrClaimed  = errors.New("VM credential already claimed")
	ErrNotTaken = errors.New("VM credential not claimed or already taken")
)

// Credential is one handed-over VM credential. Token is secret.
type Credential struct {
	ID           string
	SubmissionID string
	ContractID   string
	Username     string
	UserID       string
	ExpiresAt    string // contract valid_until, as p3dx-aaa reported it
	token        []byte
	received     time.Time
	claimed      bool
}

// String never includes the token.
func (c *Credential) String() string {
	return "vmcred{" + c.ID + " " + c.Username + " " + c.SubmissionID + "}"
}

// Store is the in-memory credential store.
type Store struct {
	ttl time.Duration
	now func() time.Time

	mu    sync.Mutex
	creds map[string]*Credential
}

func NewStore(ttl time.Duration) *Store {
	s := &Store{ttl: ttl, now: time.Now, creds: make(map[string]*Credential)}
	go s.expireLoop()
	return s
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Put stores a credential handed over by p3dx-aaa. The token slice is copied
// and the caller's copy wiped.
func (s *Store) Put(c Credential, token []byte) error {
	if c.ID == "" || c.Username == "" || c.SubmissionID == "" || len(token) == 0 {
		wipe(token)
		return errors.New("credential_id, username, submission_id and offline_token are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.creds[c.ID]; exists {
		wipe(token)
		return errors.New("duplicate credential_id")
	}
	c.token = append([]byte(nil), token...)
	wipe(token)
	c.received = s.now()
	s.creds[c.ID] = &c
	return nil
}

// Claim binds credential id to a provisioning run for username/submission.
// It succeeds once; a mismatch drops the credential.
func (s *Store) Claim(id, username, submissionID string) (*Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.creds[id]
	if !ok {
		return nil, ErrUnknown
	}
	if c.Username != username || c.SubmissionID != submissionID {
		wipe(c.token)
		delete(s.creds, id)
		log.Printf("[vmcred] %s claimed by %s for %s — refused and dropped", c, username, submissionID)
		return nil, ErrMismatch
	}
	if c.claimed {
		return nil, ErrClaimed
	}
	c.claimed = true
	meta := *c
	meta.token = nil
	return &meta, nil
}

// Take returns the claimed credential's token exactly once and removes it.
// The caller must wipe the returned slice when done.
func (s *Store) Take(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.creds[id]
	if !ok || !c.claimed {
		return nil, ErrNotTaken
	}
	out := append([]byte(nil), c.token...)
	wipe(c.token)
	delete(s.creds, id)
	return out, nil
}

// Drop wipes and forgets a credential (e.g. its provisioning run failed).
func (s *Store) Drop(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.creds[id]; ok {
		wipe(c.token)
		delete(s.creds, id)
	}
}

func (s *Store) expire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.creds {
		if s.now().Sub(c.received) > s.ttl {
			wipe(c.token)
			delete(s.creds, id)
			log.Printf("[vmcred] %s not delivered within %s — wiped", c, s.ttl)
		}
	}
}

func (s *Store) expireLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		s.expire()
	}
}
