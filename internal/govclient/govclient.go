// Package govclient reads what the orchestrator needs from gov_layer's
// contract API, authenticated with the orchestrator's Keycloak
// service-account token (the same token /gateway-certs and /fl-output take).
package govclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenFunc returns the orchestrator's service-account access token
// (keycloak.TokenSource.Token).
type TokenFunc func() (string, error)

// FLRunConfig is the signed contract's "fl_config" block: the
// training knobs the parties agreed on for this session.
type FLRunConfig struct {
	NumRounds    int     `json:"num_rounds"`
	LocalEpochs  int     `json:"local_epochs"`
	LearningRate float64 `json:"learning_rate"`
	BatchSize    int     `json:"batch_size"`
}

// Client talks to gov_layer at BaseURL (e.g. http://localhost:8083/api/v1).
type Client struct {
	baseURL string
	token   TokenFunc
	http    *http.Client
}

func New(baseURL string, token TokenFunc) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// ErrNoContract: gov_layer has no contract for the submission (404).
var ErrNoContract = errors.New("gov_layer has no contract for this submission")

// Parties are the contract's signing parties, as far as authorization
// needs them: UserName is the session's output owner (parties.user.name),
// DataProviders the data providers' usernames (parties.data_providers[].name;
// their "id" is the Keycloak sub).
type Parties struct {
	UserName      string
	DataProviders []string
}

// IsOwner reports whether username is the contract's output owner.
func (p *Parties) IsOwner(username string) bool {
	return username != "" && strings.EqualFold(p.UserName, username)
}

// IsDataProvider reports whether username is one of the contract's data providers.
func (p *Parties) IsDataProvider(username string) bool {
	if username == "" {
		return false
	}
	for _, d := range p.DataProviders {
		if strings.EqualFold(d, username) {
			return true
		}
	}
	return false
}

type contractBody struct {
	Status   string `json:"status"`
	Contract *struct {
		Parties struct {
			User struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"user"`
			DataProviders []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"data_providers"`
		} `json:"parties"`
	} `json:"contract"`
}

func (c *Client) fetchContract(ctx context.Context, submissionID string) (*contractBody, error) {
	tok, err := c.token()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/contract/"+url.PathEscape(submissionID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gov_layer contract: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w (submission %s)", ErrNoContract, submissionID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gov_layer contract returned %d", resp.StatusCode)
	}
	var body contractBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("gov_layer contract: %w", err)
	}
	if body.Status != "SUCCESS" || body.Contract == nil {
		return nil, fmt.Errorf("gov_layer contract: unexpected response (status %q)", body.Status)
	}
	return &body, nil
}

// ContractParties returns the latest contract's parties for the submission.
// A missing contract wraps ErrNoContract; any other error means gov_layer
// could not be read.
func (c *Client) ContractParties(ctx context.Context, submissionID string) (*Parties, error) {
	body, err := c.fetchContract(ctx, submissionID)
	if err != nil {
		return nil, err
	}
	p := &Parties{UserName: body.Contract.Parties.User.Name}
	if p.UserName == "" {
		p.UserName = body.Contract.Parties.User.ID
	}
	for _, d := range body.Contract.Parties.DataProviders {
		if d.Name != "" {
			p.DataProviders = append(p.DataProviders, d.Name)
		}
	}
	return p, nil
}

// Contract is the part of a signed contract the session pinning acts on.
type Contract struct {
	ProjectID   string `json:"project_id"`
	ContractID  string `json:"contract_id"`
	SessionInfo struct {
		SessionID string `json:"session_id"`
	} `json:"session_info"`
	FLConfig *FLRunConfig `json:"fl_config"` // nil when the contract has none
}

// ContractByProject returns the contract stored for one project
// (GET /contracts/by-project/{projectID}) — the exact contract a session's
// gateway certificate was issued for, never "the submission's latest", which
// a restart can replace. A missing contract (404) is an error.
func (c *Client) ContractByProject(ctx context.Context, projectID string) (*Contract, error) {
	tok, err := c.token()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/contracts/by-project/"+url.PathEscape(projectID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gov_layer contract: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("gov_layer has no contract for project %s", projectID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gov_layer contract returned %d", resp.StatusCode)
	}
	var body struct {
		Status   string    `json:"status"`
		Contract *Contract `json:"contract"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("gov_layer contract: %w", err)
	}
	if body.Status != "SUCCESS" || body.Contract == nil {
		return nil, fmt.Errorf("gov_layer contract: unexpected response (status %q)", body.Status)
	}
	return body.Contract, nil
}
