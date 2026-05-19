package oidclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// registrationRequest is the RFC 7591 §3.1 client registration request body.
// Only the client metadata oidclient sends is included; the server assigns
// client_id (and optionally client_secret) and returns them in the response.
type registrationRequest struct {
	ClientName   string   `json:"client_name,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
}

// registrationResponse is the subset of the RFC 7591 §3.2.1 client information
// response that oidclient consumes. Additional fields the server may return
// (client_id_issued_at, registration_access_token, etc.) are ignored.
type registrationResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
}

// autoRegister performs RFC 7591 dynamic client registration. The server is
// canonical: whatever client_id (and client_secret, if any) it returns is
// what the client must use for subsequent token exchanges. Both 201 Created
// (new registration) and 200 OK (existing registration, returned by servers
// that derive client_id from request inputs) are treated as success.
func autoRegister(ctx context.Context, registrationEndpoint, clientName, callbackURL string, httpClient *http.Client) (*registrationResponse, error) {
	body := registrationRequest{
		ClientName:   clientName,
		RedirectURIs: []string{callbackURL},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationEndpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := httpClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registration request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("registration returned HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(errBody))
	}

	var info registrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode registration response: %w", err)
	}
	if info.ClientID == "" {
		return nil, fmt.Errorf("registration response missing client_id")
	}
	return &info, nil
}
