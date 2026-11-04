package govclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// gatewayGov fakes gov_layer's GET /contract/{sid} and
// GET /contracts/{id}/signatures.
func gatewayGov(t *testing.T, technique string, validUntil time.Time, signatures string) (*Client, *[]string) {
	t.Helper()
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath())
		if r.Header.Get("Authorization") != "Bearer svc-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/api/v1/contract/sub-1":
			fmt.Fprintf(w, `{"status":"SUCCESS","contract":{"contract_id":"c/1","project_id":"proj-1","job_id":"job-1","technique":%q,
				"session_info":{"session_id":"sub-1"},"lifecycle":{"valid_until":%q},
				"parties":{"user":{"id":"u","name":"owner"},"data_providers":[{"id":"kc-alice","name":"alice"}]}}}`,
				technique, validUntil.UTC().Format(time.RFC3339))
		case strings.HasSuffix(r.URL.Path, "/signatures"):
			fmt.Fprintf(w, `{"signatures":%q,"tee":"x"}`, signatures)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL+"/api/v1", staticToken("svc-token")), &paths
}

func TestGatewayAuthorization(t *testing.T) {
	validUntil := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	c, paths := gatewayGov(t, "FL", validUntil, "matching")
	a, err := c.GatewayAuthorization(context.Background(), "sub-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if a.ContractID != "c/1" || a.ProjectID != "proj-1" || a.JobID != "job-1" || a.SubmissionID != "sub-1" || !a.ValidUntil.Equal(validUntil) {
		t.Fatalf("authorization = %+v", a)
	}
	if len(a.Parties) != 1 || a.Parties[0].ID != "kc-alice" || a.Parties[0].Name != "alice" {
		t.Fatalf("parties = %+v", a.Parties)
	}
	// The signatures check names the exact contract just fetched.
	if len(*paths) != 2 || (*paths)[1] != "/api/v1/contracts/c%2F1/signatures" {
		t.Fatalf("calls = %v", *paths)
	}
}

func TestGatewayAuthorizationRejects(t *testing.T) {
	future := time.Now().Add(time.Hour)
	for _, tc := range []struct {
		name       string
		technique  string
		validUntil time.Time
		signatures string
		want       error
	}{
		{"not FL", "TEE", future, "matching", ErrContractNotFL},
		{"not signed", "FL", future, "not matching", ErrContractNotSigned},
		{"expired", "FL", time.Now().Add(-time.Minute), "matching", ErrContractExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gatewayGov(t, tc.technique, tc.validUntil, tc.signatures)
			if a, err := c.GatewayAuthorization(context.Background(), "sub-1", time.Now()); !errors.Is(err, tc.want) {
				t.Fatalf("got %+v, %v; want %v", a, err, tc.want)
			}
		})
	}
	c, _ := gatewayGov(t, "FL", future, "matching")
	if _, err := c.GatewayAuthorization(context.Background(), "missing", time.Now()); !errors.Is(err, ErrNoContract) {
		t.Fatalf("missing contract: got %v, want ErrNoContract", err)
	}
}
