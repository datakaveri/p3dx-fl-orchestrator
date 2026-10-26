package flauto

import (
	"encoding/json"
	"fmt"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/govclient"
)

// flotillaQuicksetupConfig is a Go transcription of
// Flotilla_Deployment/config/flotilla_quicksetup_config.yaml (CIFAR10_IID +
// FedAT_CNN demo, 100 rounds) — the dataset cloud-init.sh.tftpl already
// generates on every VM. Ported from
// p3dx-aaa/src/config/flotillaQuicksetupConfig.js; this IS the
// federated_learning_config body flo_server.py's POST /execute_command
// expects.
var flotillaQuicksetupConfig = map[string]any{
	"session_config": map[string]any{
		"session_id":             "facnn_fedavg_iid_docker",
		"use_gpu":                false,
		"aggregator":             "fedavg_torch",
		"aggregator_args":        "None",
		"client_selection":       "fedavg",
		"client_selection_args":  map[string]any{"client_fraction": 1},
		"termination_condition":  "max_rounds",
		"termination_condition_args": map[string]any{"max_rounds": 100},
		"checkpoint_interval":       1000,
		"validation_round_interval": 1,
		"generate_plots":            false,
	},
	"benchmark_config": map[string]any{
		"skip_benchmark":       true,
		"model_id":             "FedAT_CNN",
		"model_dir":            "../models/FedAT_CNN",
		"model_class":          "FedAT_CNN",
		"dataset":              "CIFAR10_IID",
		"bench_minibatch_count": 500,
		"batch_size":           4,
		"learning_rate":        0.0001,
		"timeout_duration_s":   180,
	},
	"server_training_config": map[string]any{
		"model_dir":                        "../models/FedAT_CNN",
		"validation_dataset":               "CIFAR10_IID",
		"global_model_validation_batch_size": 100,
	},
	"client_training_config": map[string]any{
		"model_id":                 "FedAT_CNN",
		"model_class":              "FedAT_CNN",
		"dataset":                  "CIFAR10_IID",
		"epochs":                   3,
		"batch_size":               4,
		"learning_rate":            0.00005,
		"train_timeout_duration_s": 300,
		"loss_function":            "crossentropy",
		"loss_function_custom":     true,
		"optimizer":                "adam",
		"optimizer_custom":         true,
	},
	"model_config": map[string]any{
		"use_custom_dataloader":  false,
		"custom_loader_args":     "None",
		"use_custom_trainer":     false,
		"custom_trainer_args":    "None",
		"use_custom_validator":   false,
		"custom_validator_args":  "None",
		"model_args":             map[string]any{"num_classes": 10},
	},
}

// sessionConfigFor returns the federated_learning_config for a session from
// its contract's fl_config, which is required. The values are range-checked —
// flo_server retries a config it cannot run forever — and applied to a deep
// copy of flotillaQuicksetupConfig (model, dataset, aggregator), never to the
// package-level map itself.
func sessionConfigFor(fl *govclient.FLRunConfig) (map[string]any, error) {
	if fl == nil {
		return nil, fmt.Errorf("the contract has no fl_config")
	}
	switch {
	case fl.NumRounds < 1 || fl.NumRounds > 100:
		return nil, fmt.Errorf("fl_config.num_rounds must be between 1 and 100 (got %d)", fl.NumRounds)
	case fl.LocalEpochs < 1 || fl.LocalEpochs > 5:
		return nil, fmt.Errorf("fl_config.local_epochs must be between 1 and 5 (got %d)", fl.LocalEpochs)
	case !(fl.LearningRate > 0 && fl.LearningRate <= 1): // also rejects NaN
		return nil, fmt.Errorf("fl_config.learning_rate must be > 0 and <= 1 (got %g)", fl.LearningRate)
	case fl.BatchSize < 1 || fl.BatchSize > 1024:
		return nil, fmt.Errorf("fl_config.batch_size must be between 1 and 1024 (got %d)", fl.BatchSize)
	}

	// JSON round-trip deep copy; numbers come back as float64, which marshal
	// to the same JSON (1000, 0.0001, ...).
	raw, err := json.Marshal(flotillaQuicksetupConfig)
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	session := cfg["session_config"].(map[string]any)
	bench := cfg["benchmark_config"].(map[string]any)
	client := cfg["client_training_config"].(map[string]any)

	session["termination_condition_args"].(map[string]any)["max_rounds"] = fl.NumRounds
	client["epochs"] = fl.LocalEpochs
	client["learning_rate"] = fl.LearningRate
	bench["learning_rate"] = fl.LearningRate
	client["batch_size"] = fl.BatchSize
	bench["batch_size"] = fl.BatchSize
	// 100s per local epoch, never below the quicksetup default of 300s.
	client["train_timeout_duration_s"] = max(300, 100*fl.LocalEpochs)
	return cfg, nil
}
