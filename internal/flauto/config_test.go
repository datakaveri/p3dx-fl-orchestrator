package flauto

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/govclient"
)

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSessionConfigForRequiresFLConfig(t *testing.T) {
	if cfg, err := sessionConfigFor(nil); err == nil || cfg != nil {
		t.Fatalf("nil fl_config: want an error, got %v", cfg)
	}
}

func TestSessionConfigForOverrides(t *testing.T) {
	before := mustJSON(t, flotillaQuicksetupConfig)
	for _, tc := range []struct {
		fl      govclient.FLRunConfig
		timeout float64
	}{
		{govclient.FLRunConfig{NumRounds: 3, LocalEpochs: 2, LearningRate: 0.001, BatchSize: 16}, 300},
		{govclient.FLRunConfig{NumRounds: 100, LocalEpochs: 5, LearningRate: 1, BatchSize: 1024}, 500},
		{govclient.FLRunConfig{NumRounds: 1, LocalEpochs: 1, LearningRate: 1e-6, BatchSize: 1}, 300},
	} {
		cfg, err := sessionConfigFor(&tc.fl)
		if err != nil {
			t.Fatalf("%+v: %v", tc.fl, err)
		}
		// Check what flo_server will actually receive.
		var got map[string]any
		if err := json.Unmarshal([]byte(mustJSON(t, cfg)), &got); err != nil {
			t.Fatal(err)
		}
		session := got["session_config"].(map[string]any)
		bench := got["benchmark_config"].(map[string]any)
		client := got["client_training_config"].(map[string]any)
		checks := map[string][2]any{
			"max_rounds":              {session["termination_condition_args"].(map[string]any)["max_rounds"], float64(tc.fl.NumRounds)},
			"epochs":                  {client["epochs"], float64(tc.fl.LocalEpochs)},
			"client learning_rate":    {client["learning_rate"], tc.fl.LearningRate},
			"benchmark learning_rate": {bench["learning_rate"], tc.fl.LearningRate},
			"client batch_size":       {client["batch_size"], float64(tc.fl.BatchSize)},
			"benchmark batch_size":    {bench["batch_size"], float64(tc.fl.BatchSize)},
			"train_timeout":           {client["train_timeout_duration_s"], tc.timeout},
			"untouched model_id":      {client["model_id"], "FedAT_CNN"},
			"untouched checkpoint":    {session["checkpoint_interval"], float64(1000)},
		}
		for name, c := range checks {
			if c[0] != c[1] {
				t.Errorf("%+v: %s = %v, want %v", tc.fl, name, c[0], c[1])
			}
		}
	}
	if mustJSON(t, flotillaQuicksetupConfig) != before {
		t.Fatal("sessionConfigFor mutated flotillaQuicksetupConfig")
	}
}

func TestSessionConfigForRejectsOutOfRange(t *testing.T) {
	ok := govclient.FLRunConfig{NumRounds: 3, LocalEpochs: 2, LearningRate: 0.001, BatchSize: 16}
	before := mustJSON(t, flotillaQuicksetupConfig)
	for _, tc := range []struct {
		name  string
		edit  func(*govclient.FLRunConfig)
		field string
	}{
		{"rounds 0", func(f *govclient.FLRunConfig) { f.NumRounds = 0 }, "num_rounds"},
		{"rounds 101", func(f *govclient.FLRunConfig) { f.NumRounds = 101 }, "num_rounds"},
		{"epochs 0", func(f *govclient.FLRunConfig) { f.LocalEpochs = 0 }, "local_epochs"},
		{"epochs 6", func(f *govclient.FLRunConfig) { f.LocalEpochs = 6 }, "local_epochs"},
		{"lr 0", func(f *govclient.FLRunConfig) { f.LearningRate = 0 }, "learning_rate"},
		{"lr negative", func(f *govclient.FLRunConfig) { f.LearningRate = -0.1 }, "learning_rate"},
		{"lr 1.5", func(f *govclient.FLRunConfig) { f.LearningRate = 1.5 }, "learning_rate"},
		{"lr NaN", func(f *govclient.FLRunConfig) { f.LearningRate = math.NaN() }, "learning_rate"},
		{"batch 0", func(f *govclient.FLRunConfig) { f.BatchSize = 0 }, "batch_size"},
		{"batch 1025", func(f *govclient.FLRunConfig) { f.BatchSize = 1025 }, "batch_size"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fl := ok
			tc.edit(&fl)
			cfg, err := sessionConfigFor(&fl)
			if err == nil || cfg != nil {
				t.Fatalf("want an error, got %v", cfg)
			}
			if !strings.Contains(err.Error(), "fl_config."+tc.field) {
				t.Fatalf("error %q does not name %s", err, tc.field)
			}
		})
	}
	if mustJSON(t, flotillaQuicksetupConfig) != before {
		t.Fatal("flotillaQuicksetupConfig changed")
	}
}
