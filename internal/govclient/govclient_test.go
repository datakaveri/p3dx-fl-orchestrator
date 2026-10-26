package govclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func staticToken(tok string) TokenFunc { return func() (string, error) { return tok, nil } }

func TestContractByProject(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.EscapedPath(), r.Header.Get("Authorization")
		switch {
		case strings.HasSuffix(r.URL.Path, "/with"):
			_, _ = w.Write([]byte(`{"status":"SUCCESS","contract":{"project_id":"proj/with","contract_id":"c1","session_info":{"session_id":"sub-1"},"fl_config":{"num_rounds":3,"local_epochs":2,"learning_rate":0.001,"batch_size":16}}}`))
		case strings.HasSuffix(r.URL.Path, "/without"):
			_, _ = w.Write([]byte(`{"status":"SUCCESS","contract":{"project_id":"without","contract_id":"c2"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"status":"FAILED","error":"NOT_FOUND"}`))
		}
	}))
	defer srv.Close()
	c := New(srv.URL+"/api/v1/", staticToken("svc-token"))

	got, err := c.ContractByProject(context.Background(), "proj/with")
	if err != nil {
		t.Fatal(err)
	}
	if got.ProjectID != "proj/with" || got.ContractID != "c1" || got.SessionInfo.SessionID != "sub-1" {
		t.Fatalf("contract = %+v", got)
	}
	if got.FLConfig == nil || *got.FLConfig != (FLRunConfig{NumRounds: 3, LocalEpochs: 2, LearningRate: 0.001, BatchSize: 16}) {
		t.Fatalf("fl_config = %+v", got.FLConfig)
	}
	if gotPath != "/api/v1/contracts/by-project/proj%2Fwith" {
		t.Fatalf("path = %q, want the project id path-escaped", gotPath)
	}
	if gotAuth != "Bearer svc-token" {
		t.Fatalf("Authorization = %q", gotAuth)
	}

	got, err = c.ContractByProject(context.Background(), "without")
	if err != nil || got.FLConfig != nil {
		t.Fatalf("no fl_config: got %+v, %v; want nil fl_config", got, err)
	}

	if _, err := c.ContractByProject(context.Background(), "missing"); err == nil || !strings.Contains(err.Error(), "no contract for project") {
		t.Fatalf("404: want a no-contract error, got %v", err)
	}
}

func TestContractByProjectTokenError(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()
	c := New(srv.URL, func() (string, error) { return "", context.Canceled })
	if _, err := c.ContractByProject(context.Background(), "x"); err == nil {
		t.Fatal("want token error")
	}
	if called {
		t.Fatal("request sent without a token")
	}
}
