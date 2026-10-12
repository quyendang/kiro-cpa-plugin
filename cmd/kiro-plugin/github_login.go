package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	kiroauth "github.com/nguyenha935/kiro-cpa-plugin/internal/auth/kiro"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var githubDeviceStarter = func(ctx context.Context) (*kiroauth.SocialDeviceAuthorization, error) {
	return kiroauth.NewSSOOIDCClient(pluginConfig).StartGitHubDeviceAuthorization(ctx)
}
var githubDevicePoller = func(ctx context.Context, code string) (*kiroauth.KiroTokenData, error) {
	return kiroauth.NewSSOOIDCClient(pluginConfig).PollGitHubDeviceToken(ctx, code)
}
var githubIdentityResolver = reconcileIdentityBestEffort
var githubModelLister = listAvailableModels

func connectGitHubLogin(state string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	started, err := githubDeviceStarter(ctx)
	if err == nil && started == nil {
		err = errors.New("Kiro GitHub authorization is unavailable")
	}
	if err != nil {
		_ = updateLoginFlow(state, func(flow *loginFlow) { flow.Used = false })
		return connectAPIError(http.StatusBadGateway, err.Error())
	}
	if err = kiroauth.ValidateSocialAuthorizationURL(started.VerificationURIComplete); err != nil {
		_ = updateLoginFlow(state, func(flow *loginFlow) { flow.Used = false })
		return connectAPIError(http.StatusBadGateway, err.Error())
	}
	if started.DeviceCode == "" || started.UserCode == "" {
		_ = updateLoginFlow(state, func(flow *loginFlow) { flow.Used = false })
		return connectAPIError(http.StatusBadGateway, "Kiro returned incomplete GitHub device authorization")
	}
	intervalMS := started.IntervalInMilliseconds
	if intervalMS > 600000 {
		intervalMS = 600000
	}
	interval := time.Duration(intervalMS) * time.Millisecond
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	// Cap upstream durations before converting to avoid overflow and retain
	// CPA's own ten-minute session lifetime.
	ttl := started.ExpiresInMilliseconds
	if ttl <= 0 {
		ttl = 300000
	}
	if ttl > 600000 {
		ttl = 600000
	}
	deadline := time.Now().UTC().Add(time.Duration(ttl) * time.Millisecond)
	err = updateLoginFlow(state, func(flow *loginFlow) {
		flow.AuthMethod = "social"
		flow.DeviceCode = started.DeviceCode
		flow.LoginURL = started.VerificationURIComplete
		flow.PollInterval = interval
		flow.NextPollAt = time.Now().Add(interval)
		if deadline.Before(flow.ExpiresAt) {
			flow.ExpiresAt = deadline
		}
	})
	if err != nil {
		return connectAPIError(http.StatusBadRequest, err.Error())
	}
	return connectAPIJSON(http.StatusOK, connectAPIResponse{Status: "authorization_required", URL: started.VerificationURIComplete, UserCode: started.UserCode})
}

// CPA's OAuth card owns polling and credential persistence. The resource
// page only opens the authorization URL, so there is one consumer per state.
func pollGitHubLogin(state string) ([]byte, error) {
	pending := func() ([]byte, error) {
		return okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusPending, Message: "Waiting for Kiro GitHub authorization"})
	}
	loginFlowsMu.Lock()
	flow, found := loginFlows[state]
	if !found || !time.Now().Before(flow.ExpiresAt) {
		loginFlowsMu.Unlock()
		return okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: "Kiro GitHub sign-in expired; start a new sign-in"})
	}
	if flow.Completed != nil || flow.Failure != "" {
		loginFlowsMu.Unlock()
		raw, _ := json.Marshal(pluginapi.AuthLoginPollRequest{State: state})
		return handleLoginPoll(raw)
	}
	if flow.Polling || time.Now().Before(flow.NextPollAt) {
		loginFlowsMu.Unlock()
		return pending()
	}
	flow.Polling = true
	loginFlows[state] = flow
	loginFlowsMu.Unlock()
	ctx, cancel := context.WithDeadline(context.Background(), flow.ExpiresAt)
	defer cancel()
	pollCtx, pollCancel := context.WithTimeout(ctx, 20*time.Second)
	token, err := githubDevicePoller(pollCtx, flow.DeviceCode)
	pollCancel()
	if err != nil {
		var status interface{ StatusCode() int }
		terminal := errors.As(err, &status) && status.StatusCode() >= 400 && status.StatusCode() < 500 && status.StatusCode() != 429
		_ = updateLoginFlow(state, func(current *loginFlow) {
			current.Polling = false
			if errors.Is(err, kiroauth.ErrSlowDown) {
				current.PollInterval += 5 * time.Second
			}
			current.NextPollAt = time.Now().Add(current.PollInterval)
			if terminal {
				current.Failure = err.Error()
			}
		})
		if terminal {
			return okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: err.Error()})
		}
		return pending()
	}
	if token == nil || token.AccessToken == "" || token.RefreshToken == "" {
		_ = updateLoginFlow(state, func(current *loginFlow) {
			current.Polling = false
			current.NextPollAt = time.Now().Add(current.PollInterval)
		})
		return pending()
	}
	token.AuthMethod, token.Provider, token.Region = "social", "Github", "us-east-1"
	// A stable per-login fallback keeps opaque-token accounts distinct if Kiro
	// omits both email and user ID. It is persisted and survives token rotation.
	fingerprint := sha256.Sum256([]byte(flow.DeviceCode))
	token.Identity = "github-" + hex.EncodeToString(fingerprint[:])[:12]
	identityCtx, identityCancel := context.WithTimeout(ctx, 10*time.Second)
	githubIdentityResolver(identityCtx, token)
	identityCancel()
	catalogCtx, catalogCancel := context.WithTimeout(ctx, modelListTimeout)
	if models, listErr := githubModelLister(catalogCtx, token); listErr == nil {
		storeModelCatalog(token, models, time.Now())
	}
	catalogCancel()
	if err = updateLoginFlow(state, func(current *loginFlow) { current.Polling = false; current.Completed = token }); err != nil {
		return okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: "Kiro GitHub sign-in expired; start a new sign-in"})
	}
	// Re-enter the common completion path to consume the state exactly once.
	raw, _ := json.Marshal(pluginapi.AuthLoginPollRequest{State: state})
	return handleLoginPoll(raw)
}
