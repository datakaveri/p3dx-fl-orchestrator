package vmcred

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const secret = "offline-token-SECRET-123"

// newTestStore builds a Store without the background expiry loop.
func newTestStore(ttl time.Duration) *Store {
	return &Store{ttl: ttl, now: time.Now, creds: make(map[string]*Credential)}
}

func cred(id string) Credential {
	return Credential{ID: id, SubmissionID: "sub-1", ContractID: "c1", Username: "alice", UserID: "u1"}
}

func zeroed(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func TestPutClaimTakeHappyPath(t *testing.T) {
	s := newTestStore(time.Hour)
	tok := []byte(secret)
	if err := s.Put(cred("id1"), tok); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !zeroed(tok) {
		t.Fatalf("caller's token slice not wiped after Put: %q", tok)
	}
	meta, err := s.Claim("id1", "alice", "sub-1")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if meta.ID != "id1" || meta.Username != "alice" || meta.ContractID != "c1" {
		t.Fatalf("unexpected claim metadata: %+v", meta)
	}
	if meta.token != nil {
		t.Fatalf("Claim returned metadata carrying the token")
	}
	stored := s.creds["id1"].token
	got, err := s.Take("id1")
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if string(got) != secret {
		t.Fatalf("Take returned %q", got)
	}
	if !zeroed(stored) {
		t.Fatalf("stored token not wiped after Take")
	}
	if _, ok := s.creds["id1"]; ok {
		t.Fatalf("credential still stored after Take")
	}
	if _, err := s.Take("id1"); !errors.Is(err, ErrNotTaken) {
		t.Fatalf("second Take: want ErrNotTaken, got %v", err)
	}
}

func TestPutRejectsMissingFieldsAndDuplicates(t *testing.T) {
	s := newTestStore(time.Hour)
	for name, c := range map[string]Credential{
		"no id":         {Username: "alice", SubmissionID: "s"},
		"no username":   {ID: "x", SubmissionID: "s"},
		"no submission": {ID: "x", Username: "alice"},
	} {
		tok := []byte(secret)
		if err := s.Put(c, tok); err == nil {
			t.Errorf("%s: Put succeeded", name)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: error leaks token", name)
		}
		if !zeroed(tok) {
			t.Errorf("%s: token not wiped on rejection", name)
		}
	}
	if err := s.Put(cred("x"), nil); err == nil {
		t.Errorf("Put with empty token succeeded")
	}
	if err := s.Put(cred("dup"), []byte(secret)); err != nil {
		t.Fatal(err)
	}
	tok := []byte("other-token")
	if err := s.Put(cred("dup"), tok); err == nil {
		t.Fatalf("duplicate Put succeeded")
	}
	if !zeroed(tok) {
		t.Errorf("token not wiped on duplicate")
	}
	if string(s.creds["dup"].token) != secret {
		t.Errorf("duplicate Put overwrote the original credential")
	}
}

func TestClaimMismatchDropsCredential(t *testing.T) {
	for name, who := range map[string][2]string{
		"wrong user":       {"mallory", "sub-1"},
		"wrong submission": {"alice", "sub-2"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestStore(time.Hour)
			if err := s.Put(cred("id1"), []byte(secret)); err != nil {
				t.Fatal(err)
			}
			stored := s.creds["id1"].token
			if _, err := s.Claim("id1", who[0], who[1]); !errors.Is(err, ErrMismatch) {
				t.Fatalf("want ErrMismatch, got %v", err)
			}
			if !zeroed(stored) {
				t.Fatalf("token not wiped on mismatch")
			}
			if _, err := s.Claim("id1", "alice", "sub-1"); !errors.Is(err, ErrUnknown) {
				t.Fatalf("credential should be gone after mismatch; got %v", err)
			}
		})
	}
}

func TestClaimTwiceAndUnknown(t *testing.T) {
	s := newTestStore(time.Hour)
	if _, err := s.Claim("nope", "alice", "sub-1"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("want ErrUnknown, got %v", err)
	}
	if err := s.Put(cred("id1"), []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim("id1", "alice", "sub-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim("id1", "alice", "sub-1"); !errors.Is(err, ErrClaimed) {
		t.Fatalf("want ErrClaimed, got %v", err)
	}
}

func TestTakeBeforeClaim(t *testing.T) {
	s := newTestStore(time.Hour)
	if err := s.Put(cred("id1"), []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Take("id1"); !errors.Is(err, ErrNotTaken) {
		t.Fatalf("want ErrNotTaken, got %v", err)
	}
	if _, err := s.Take("missing"); !errors.Is(err, ErrNotTaken) {
		t.Fatalf("want ErrNotTaken, got %v", err)
	}
	// Still present and claimable afterwards.
	if _, err := s.Claim("id1", "alice", "sub-1"); err != nil {
		t.Fatalf("Claim after early Take: %v", err)
	}
}

func TestDropWipes(t *testing.T) {
	s := newTestStore(time.Hour)
	if err := s.Put(cred("id1"), []byte(secret)); err != nil {
		t.Fatal(err)
	}
	stored := s.creds["id1"].token
	s.Drop("id1")
	s.Drop("id1") // idempotent
	if !zeroed(stored) {
		t.Fatalf("Drop did not wipe token")
	}
	if _, ok := s.creds["id1"]; ok {
		t.Fatalf("Drop did not remove credential")
	}
}

func TestStringNeverContainsToken(t *testing.T) {
	s := newTestStore(time.Hour)
	if err := s.Put(cred("id1"), []byte(secret)); err != nil {
		t.Fatal(err)
	}
	c := s.creds["id1"]
	if strings.Contains(c.String(), secret) {
		t.Fatalf("String() leaks token: %s", c)
	}
	if !strings.Contains(c.String(), "id1") {
		t.Fatalf("String() missing id: %s", c)
	}
}

func TestExpireRemovesAndWipes(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := newTestStore(10 * time.Minute)
	s.now = func() time.Time { return now }
	if err := s.Put(cred("old"), []byte(secret)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(9 * time.Minute)
	if err := s.Put(cred("new"), []byte(secret)); err != nil {
		t.Fatal(err)
	}
	oldTok := s.creds["old"].token

	s.expire() // old is 9m old: kept
	if _, ok := s.creds["old"]; !ok {
		t.Fatalf("credential expired before TTL")
	}
	now = now.Add(2 * time.Minute) // old 11m, new 2m
	s.expire()
	if _, ok := s.creds["old"]; ok {
		t.Fatalf("expired credential not removed")
	}
	if !zeroed(oldTok) {
		t.Fatalf("expired credential not wiped")
	}
	if _, ok := s.creds["new"]; !ok {
		t.Fatalf("fresh credential removed")
	}
}

func TestNewStore(t *testing.T) {
	s := NewStore(time.Minute)
	if err := s.Put(cred("id1"), []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim("id1", "alice", "sub-1"); err != nil {
		t.Fatal(err)
	}
}
