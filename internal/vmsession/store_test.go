package vmsession

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestListRunsFiltering(t *testing.T) {
	s := NewStore()
	own := s.CreateRun(RunInfo{Username: "alice", Role: "data-provider", SubmissionID: "gov-1", VMName: "p3dx-fl-1"})
	time.Sleep(2 * time.Millisecond)
	ownerOf := s.CreateRun(RunInfo{Username: "operator", Role: "user", SubmissionID: "gov-1", VMName: "p3dx-fl-1", OutputOwner: "alice"})
	time.Sleep(2 * time.Millisecond)
	ownOther := s.CreateRun(RunInfo{Username: "alice", Role: "user", SubmissionID: "gov-2"})
	// Not alice's: someone else's provider run naming alice as output owner
	// (OutputOwner only counts on a server VM run), and an unrelated run.
	s.CreateRun(RunInfo{Username: "bob", Role: "data-provider", SubmissionID: "gov-1", OutputOwner: "alice"})
	s.CreateRun(RunInfo{Username: "operator", Role: "user", SubmissionID: "gov-1", OutputOwner: "carol"})

	tokens := func(runs []RunSummary) []string {
		out := []string{}
		for _, r := range runs {
			out = append(out, r.Token)
		}
		return out
	}
	for _, tc := range []struct {
		name, user, sub string
		want            []string
	}{
		{"all of alice's, newest first", "alice", "", []string{ownOther, ownerOf, own}},
		{"one submission", "alice", "gov-1", []string{ownerOf, own}},
		{"unknown submission", "alice", "gov-9", []string{}},
		{"operator sees own", "operator", "gov-1", nil}, // checked by length below
		{"no username", "", "", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tokens(s.ListRuns(tc.user, tc.sub))
			if tc.want == nil {
				if len(got) != 2 {
					t.Fatalf("got %d runs, want 2", len(got))
				}
				return
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
	r := s.ListRuns("alice", "gov-1")[0]
	if r.Role != "user" || r.SubmissionID != "gov-1" || r.VMName != "p3dx-fl-1" || r.Status != "idle" || r.CreatedAt.IsZero() {
		t.Fatalf("summary = %+v", r)
	}
}

func TestReplaceEvent(t *testing.T) {
	s := NewStore()
	tok := s.CreateToken("u", "user")
	s.AppendEvent(tok, "Starting FL session", "", "ok", "")
	before, _ := s.Get(tok)
	s.ReplaceEvent(tok, Event{Step: "Training round", Status: "running", Message: "Round 1 of 3 complete", Round: 1, MaxRounds: 3})
	s.ReplaceEvent(tok, Event{Step: "Training round", Status: "running", Message: "Round 2 of 3 complete", Round: 2, MaxRounds: 3})
	snap, _ := s.Get(tok)
	if len(snap.Events) != 2 || snap.Events[1].Round != 2 || snap.Events[1].At == "" {
		t.Fatalf("events = %+v", snap.Events)
	}
	if snap.Rev <= before.Rev {
		t.Fatal("rev did not advance on an in-place replace")
	}
	raw, _ := json.Marshal(snap.Events[1])
	if !strings.Contains(string(raw), `"round":2,"max_rounds":3`) {
		t.Fatalf("event JSON = %s", raw)
	}
	raw, _ = json.Marshal(snap.Events[0])
	if strings.Contains(string(raw), "round") {
		t.Fatalf("non-round event carries round fields: %s", raw)
	}
	if s.ReplaceEvent("nope", Event{Step: "x"}) {
		t.Fatal("unknown token accepted")
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistentStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	ready := s.CreateRun(RunInfo{Username: "alice", Role: "user", SubmissionID: "gov-1", VMName: "p3dx-fl-1", OutputOwner: "owner"})
	s.AppendEvent(ready, "Creating VM", "", "done", "VM created")
	s.ReplaceEvent(ready, Event{Step: "Training round", Status: "running", Round: 4, MaxRounds: 10})
	deploySh := s.CreateToken("bob", "data-provider")

	if _, err := os.Stat(filepath.Join(dir, fileName(ready))); err != nil {
		t.Fatalf("run not persisted: %v", err)
	}
	if tmps, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(tmps) != 0 {
		t.Fatalf("temp files left behind: %v", tmps)
	}

	s2, err := NewPersistentStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	snap, ok := s2.Get(ready)
	if !ok || !snap.VMReady || snap.Status != "running" || len(snap.Events) != 2 || snap.Events[1].Round != 4 {
		t.Fatalf("reloaded = %+v, %v", snap, ok)
	}
	runs := s2.ListRuns("owner", "")
	if len(runs) != 1 || runs[0].Token != ready || runs[0].VMName != "p3dx-fl-1" {
		t.Fatalf("reloaded runs = %+v", runs)
	}
	if snap, ok := s2.Get(deploySh); !ok || snap.Status != "idle" {
		t.Fatalf("idle deploy.sh token not kept as-is: %+v", snap)
	}
	if got := s2.Resumable(); len(got) != 1 || got[ready] != "gov-1" {
		t.Fatalf("Resumable = %v", got)
	}
	// Later changes still persist after a reload.
	s2.AppendEvent(ready, "FL session", "", "done", "finished")
	s3, _ := NewPersistentStore(dir, 0)
	if snap, _ := s3.Get(ready); snap.Status != "done" {
		t.Fatalf("post-reload change not persisted: %+v", snap)
	}
}

func TestRestartMarksProvisioningRunsFailed(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewPersistentStore(dir, 0)
	mid := s.CreateRun(RunInfo{Username: "alice", Role: "data-provider", SubmissionID: "gov-1", VMName: "p3dx-fl-1"})
	s.AppendEvent(mid, "Terraform init", "", "running", "")
	early := s.CreateRun(RunInfo{Username: "alice", Role: "data-provider", SubmissionID: "gov-1", VMName: "p3dx-fl-1"})

	s2, _ := NewPersistentStore(dir, 0)
	for _, tok := range []string{mid, early} {
		snap, _ := s2.Get(tok)
		last := snap.Events[len(snap.Events)-1]
		if snap.Status != "error" || snap.VMReady || last.Step != "Provisioning failed" || last.Status != "error" || last.Message != "Orchestrator restarted" {
			t.Fatalf("restart not marked: %+v", snap)
		}
	}
	if got := s2.Resumable(); len(got) != 0 {
		t.Fatalf("killed runs re-registered for FL events: %v", got)
	}
	// The mark is persisted, and not repeated on the next restart.
	s3, _ := NewPersistentStore(dir, 0)
	if snap, _ := s3.Get(mid); snap.Status != "error" || len(snap.Events) != 2 {
		t.Fatalf("after second restart: %+v", snap)
	}
}

func TestRetention(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewPersistentStore(dir, time.Hour)
	old := s.CreateToken("alice", "user")
	// Age the run on disk past the retention.
	path := filepath.Join(dir, fileName(old))
	raw, _ := os.ReadFile(path)
	var sess Session
	_ = json.Unmarshal(raw, &sess)
	sess.UpdatedAt = time.Now().Add(-2 * time.Hour)
	raw, _ = json.Marshal(sess)
	_ = os.WriteFile(path, raw, 0o600)
	// Junk in the directory is ignored.
	_ = os.WriteFile(filepath.Join(dir, "not-a-token.json"), []byte("{"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, strings.Repeat("a", 48)+".json"), []byte("{"), 0o600)

	s2, err := NewPersistentStore(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Get(old); ok {
		t.Fatal("expired run loaded")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expired run file not removed")
	}
}

func TestPersistedFilesAreHashedAndPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runs")
	s, err := NewPersistentStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	tok := s.CreateToken("alice", "user")
	if _, err := os.Stat(filepath.Join(dir, tok+".json")); !os.IsNotExist(err) {
		t.Fatal("run file named by raw token")
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir perms: %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(dir, fileName(tok))); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file perms: %v %v", fi, err)
	}
	if !s.CanAccess(tok, "alice") || s.CanAccess(tok, "bob") || s.CanAccess(tok, "") {
		t.Fatal("CanAccess wrong")
	}
}

func TestLegacyTokenNamedFilesMigrate(t *testing.T) {
	dir := t.TempDir()
	tok := strings.Repeat("ab", 24)
	sess := Session{Username: "alice", Role: "user", SubmissionID: "gov-1", Status: "done", VMReady: true,
		Events: []Event{}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	raw, _ := json.Marshal(sess)
	old := filepath.Join(dir, tok+".json")
	_ = os.WriteFile(old, raw, 0o644)

	s, err := NewPersistentStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if snap, ok := s.Get(tok); !ok || snap.Status != "done" {
		t.Fatalf("legacy run not loaded: %+v %v", snap, ok)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("legacy file not removed")
	}
	if fi, err := os.Stat(filepath.Join(dir, fileName(tok))); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("migrated file: %v %v", fi, err)
	}
	s2, _ := NewPersistentStore(dir, 0)
	if _, ok := s2.Get(tok); !ok || len(s2.Resumable()) != 1 {
		t.Fatal("migrated run not resumable after reload")
	}
}
