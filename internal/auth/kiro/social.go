package kiro

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Kiro's social device flow, also used by OmniRoute, needs no callback server.
// This public CLI identifier is not an AWS OIDC registration or a secret.
const socialClientID = "kiro-cli"
const socialAuthBase = "https://prod.us-east-1.auth.desktop.kiro.dev"
const maxSocialResponseBytes = 1 << 20

type SocialDeviceAuthorization struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresInMilliseconds   int64  `json:"expiresInMilliseconds"`
	IntervalInMilliseconds  int64  `json:"intervalInMilliseconds"`
}

// ValidateSocialAuthorizationURL admits only Kiro's device verification page.
func ValidateSocialAuthorizationURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "app.kiro.dev" || u.User != nil || u.Path != "/account/device" || u.Fragment != "" {
		return fmt.Errorf("Kiro returned an invalid GitHub authorization URL")
	}
	return nil
}

func (c *SSOOIDCClient) StartGitHubDeviceAuthorization(ctx context.Context) (*SocialDeviceAuthorization, error) {
	var result SocialDeviceAuthorization
	if err := c.socialJSON(ctx, "/oauth/device/authorization", map[string]string{"clientId": socialClientID, "loginProvider": "Github"}, &result); err != nil {
		return nil, err
	}
	if strings.TrimSpace(result.DeviceCode) == "" || strings.TrimSpace(result.UserCode) == "" {
		return nil, OIDCStatusError{Status: http.StatusBadGateway, Message: "Kiro returned incomplete GitHub device authorization"}
	}
	if err := ValidateSocialAuthorizationURL(result.VerificationURIComplete); err != nil {
		return nil, OIDCStatusError{Status: http.StatusBadGateway, Message: err.Error()}
	}
	if result.ExpiresInMilliseconds <= 0 {
		result.ExpiresInMilliseconds = 300000
	}
	if result.IntervalInMilliseconds <= 0 {
		result.IntervalInMilliseconds = 5000
	}
	return &result, nil
}

func (c *SSOOIDCClient) PollGitHubDeviceToken(ctx context.Context, deviceCode string) (*KiroTokenData, error) {
	if strings.TrimSpace(deviceCode) == "" {
		return nil, OIDCStatusError{Status: http.StatusBadRequest, Message: "Kiro device code is missing"}
	}
	var result struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ProfileARN   string `json:"profileArn"`
		ExpiresIn    int64  `json:"expiresIn"`
	}
	if err := c.socialJSON(ctx, "/oauth/device/poll", map[string]string{"clientId": socialClientID, "deviceCode": deviceCode}, &result); err != nil {
		return nil, err
	}
	if strings.TrimSpace(result.AccessToken) == "" || strings.TrimSpace(result.RefreshToken) == "" {
		return nil, OIDCStatusError{Status: http.StatusBadGateway, Message: "Kiro returned incomplete GitHub tokens"}
	}
	if result.ExpiresIn <= 0 {
		result.ExpiresIn = 3600
	}
	if result.ExpiresIn > 86400 {
		return nil, OIDCStatusError{Status: http.StatusBadGateway, Message: "Kiro returned invalid GitHub token expiry"}
	}
	return &KiroTokenData{
		AccessToken: result.AccessToken, RefreshToken: result.RefreshToken, ProfileArn: result.ProfileARN,
		ExpiresAt:  time.Now().UTC().Add(time.Duration(result.ExpiresIn) * time.Second).Format(time.RFC3339),
		AuthMethod: "social", Provider: "Github", Region: defaultIDCRegion,
	}, nil
}

// Never include upstream response text in errors: it may contain token material.
// Disallow redirects so the device code cannot be forwarded to another origin.
func (c *SSOOIDCClient) socialJSON(ctx context.Context, path string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, socialAuthBase+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return OIDCStatusError{Status: http.StatusBadGateway, Message: "Kiro GitHub authentication service unavailable"}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSocialResponseBytes+1))
	if err != nil || len(raw) > maxSocialResponseBytes {
		return OIDCStatusError{Status: http.StatusBadGateway, Message: "Invalid Kiro GitHub authentication response"}
	}
	var progress struct {
		Error  string `json:"error"`
		Status string `json:"status"`
	}
	if json.Unmarshal(raw, &progress) != nil {
		return OIDCStatusError{Status: http.StatusBadGateway, Message: "Invalid Kiro GitHub authentication response"}
	}
	code := progress.Error
	if code == "" {
		code = progress.Status
	}
	if path == "/oauth/device/poll" {
		switch code {
		case "authorization_pending":
			return ErrAuthorizationPending
		case "slow_down":
			return ErrSlowDown
		case "access_denied", "expired_token", "authorization_declined", "invalid_grant":
			return OIDCStatusError{Status: http.StatusBadRequest, Message: "Kiro GitHub authorization was denied or expired; start a new sign-in"}
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || progress.Error != "" {
		status := resp.StatusCode
		if status < 400 || status > 599 {
			status = http.StatusBadGateway
		}
		return OIDCStatusError{Status: status, Message: fmt.Sprintf("Kiro GitHub authentication returned HTTP %d", status)}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return OIDCStatusError{Status: http.StatusBadGateway, Message: "Invalid Kiro GitHub authentication response"}
	}
	return nil
}
