package govclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func staticToken(tok string) TokenFunc { return func() (string, error) { return tok, nil } }

func TestLatestFLConfig(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.EscapedPath(), r.Header.Get("Authorization")
		switch {
		case strings.HasSuffix(r.URL.Path, "/with"):
			_, _ = w.Write([]byte(`{"status":"SUCCESS","contract":{"contract_id":"c1","fl_config":{"num_rounds":3,"local_epochs":2,"learning_rate":0.001,"batch_size":16}}}`))
		case strings.HasSuffix(r.URL.Path, "/without"):
			_, _ = w.Write([]byte(`{"status":"SUCCESS","contract":{"contract_id":"c1"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"status":"FAILURE","message":"no contract"}`))
		}
	}))
	defer srv.Close()
	c := New(srv.URL+"/api/v1/", staticToken("svc-token"))

	fl, err := c.LatestFLConfig(context.Background(), "sub/with")
	if err != nil {
		t.Fatal(err)
	}
	if *fl != (FLRunConfig{NumRounds: 3, LocalEpochs: 2, LearningRate: 0.001, BatchSize: 16}) {
		t.Fatalf("fl_config = %+v", *fl)
	}
	if gotPath != "/api/v1/contract/sub%2Fwith" {
		t.Fatalf("path = %q, want the id path-escaped", gotPath)
	}
	if gotAuth != "Bearer svc-token" {
		t.Fatalf("Authorization = %q", gotAuth)
	}

	fl, err = c.LatestFLConfig(context.Background(), "without")
	if err != nil || fl != nil {
		t.Fatalf("no fl_config: got %+v, %v; want nil, nil", fl, err)
	}

	if _, err := c.LatestFLConfig(context.Background(), "missing"); err == nil || !strings.Contains(err.Error(), "no contract") {
		t.Fatalf("404: want a no-contract error, got %v", err)
	}
}

func TestLatestFLConfigTokenError(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()
	c := New(srv.URL, func() (string, error) { return "", context.Canceled })
	if _, err := c.LatestFLConfig(context.Background(), "x"); err == nil {
		t.Fatal("want token error")
	}
	if called {
		t.Fatal("request sent without a token")
	}
}
