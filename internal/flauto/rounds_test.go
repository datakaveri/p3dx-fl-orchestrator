package flauto

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/govclient"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmsession"
)

func TestRoundFromDisposition(t *testing.T) {
	for _, tc := range []struct {
		cd   string
		want int
		ok   bool
	}{
		{`attachment; filename=global_model_round_12.pt`, 12, true},
		{`attachment; filename="global_model_round_3.weights"`, 3, true},
		{`attachment; filename*=UTF-8''global_model_round_7.pt`, 7, true},
		{`attachment; filename="x.pt"; filename*=UTF-8''global_model_round_9.pt`, 9, true},
		{`attachment; filename=global_model_round_None.pt`, 0, false},
		{`attachment; filename=model.pt`, 0, false},
		{``, 0, false},
		{`garbage;; global_model_round_4.pt`, 4, true}, // unparsable: raw match
	} {
		got, ok := roundFromDisposition(tc.cd)
		if got != tc.want || ok != tc.ok {
			t.Errorf("roundFromDisposition(%q) = %d, %v; want %d, %v", tc.cd, got, ok, tc.want, tc.ok)
		}
	}
}

// bigModel serves a round's model as a large streamed body and counts how
// much of it the client let it write.
type bigModel struct {
	total   int
	written atomic.Int64
	served  chan struct{}
}

func (b *bigModel) handler(round string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename=global_model_round_`+round+`.pt`)
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 64<<10)
		defer func() {
			select {
			case b.served <- struct{}{}:
			default:
			}
		}()
		for n := 0; n < b.total; n += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			b.written.Add(int64(len(chunk)))
			w.(http.Flusher).Flush()
		}
	}
}

func TestLatestRoundReadsOnlyHeaders(t *testing.T) {
	g := newGateway(t)
	model := &bigModel{total: 256 << 20, served: make(chan struct{}, 1)}
	g.latestGM = model.handler("12")
	m := NewManager(vmsession.NewStore(), staticToken("svc-token"), g.port)
	_ = m.SetGatewayCA("sub-1", g.caPEM(), testPin)
	s := m.getOrCreate("sub-1")

	n, ok := m.latestRound(context.Background(), m.client(s, 10*time.Second), "127.0.0.1", "sub_1")
	if !ok || n != 12 {
		t.Fatalf("latestRound = %d, %v; want 12, true", n, ok)
	}
	select {
	case <-model.served:
	case <-time.After(10 * time.Second):
		t.Fatal("handler never saw the client go away")
	}
	if w := model.written.Load(); w >= int64(model.total/2) {
		t.Fatalf("model body was downloaded: %d of %d bytes written", w, model.total)
	}
}

func TestLatestRoundNoRoundYet(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"idle": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"status":"idle","message":"No session is currently running"}`))
		},
		"not_found": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"status":"not_found"}`))
		},
		"no model yet": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Global model not available yet"}`))
		},
		"server error": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := newGateway(t)
			g.latestGM = h
			m := NewManager(vmsession.NewStore(), staticToken("svc-token"), g.port)
			_ = m.SetGatewayCA("sub-1", g.caPEM(), testPin)
			if n, ok := m.latestRound(context.Background(), m.client(m.getOrCreate("sub-1"), 5*time.Second), "127.0.0.1", "sub_1"); ok {
				t.Fatalf("got round %d for %s", n, name)
			}
		})
	}
}

// A running session's rounds become ONE "Training round" event updated in
// place; polling stops once execute_command returns.
func TestRoundPollerDuringSession(t *testing.T) {
	g := newGateway(t)
	g.execHold = make(chan struct{})
	var mu sync.Mutex
	var polls int
	answers := []string{"", "0", "1", "1", "2"} // "" = 404 no model yet
	g.latestGM = func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		i := polls
		polls++
		mu.Unlock()
		if i >= len(answers) {
			i = len(answers) - 1
		}
		if answers[i] == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename=global_model_round_`+answers[i]+`.pt`)
		_, _ = w.Write([]byte("model"))
	}

	store := vmsession.NewStore()
	runTok := store.CreateToken("owner", "user")
	m := NewManager(store, staticToken("svc-token"), g.port)
	m.roundPollInterval = 20 * time.Millisecond
	m.SetFLConfigSource(&stubFLConfig{fl: &govclient.FLRunConfig{NumRounds: 3, LocalEpochs: 1, LearningRate: 0.001, BatchSize: 8}})
	_ = m.SetGatewayCA("sub-1", g.caPEM(), testPin)
	m.RegisterOwnerVM("sub-1", "127.0.0.1", runTok)
	m.startSession("sub-1", m.getOrCreate("sub-1"))

	roundEvents := func() []vmsession.Event {
		snap, _ := store.Get(runTok)
		var out []vmsession.Event
		for _, e := range snap.Events {
			if e.Step == "Training round" {
				out = append(out, e)
			}
		}
		return out
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if evs := roundEvents(); len(evs) == 1 && evs[0].Round == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	evs := roundEvents()
	if len(evs) != 1 {
		t.Fatalf("want one Training round event, got %+v", evs)
	}
	if e := evs[0]; e.Round != 2 || e.MaxRounds != 3 || e.Status != "running" || e.Message != "Round 2 of 3 complete" {
		t.Fatalf("round event = %+v", e)
	}

	close(g.execHold)
	deadline = time.Now().Add(5 * time.Second)
	for {
		snap, _ := store.Get(runTok)
		finished := false
		for _, e := range snap.Events {
			finished = finished || (e.Step == "FL session" && e.Status == "done")
		}
		if finished {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no FL session done event: %+v", snap.Events)
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	after := polls
	mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if polls != after {
		t.Fatalf("still polling after execute_command returned (%d -> %d)", after, polls)
	}
}

func TestQuicksetupMaxRounds(t *testing.T) {
	if n := quicksetupMaxRounds(); n != 100 {
		t.Fatalf("quicksetupMaxRounds = %d", n)
	}
}
