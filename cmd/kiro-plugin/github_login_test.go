package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	kiroauth "github.com/nguyenha935/kiro-cpa-plugin/internal/auth/kiro"
	"github.com/nguyenha935/kiro-cpa-plugin/internal/kiroroute"
	kiroexecutor "github.com/nguyenha935/kiro-cpa-plugin/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func githubFixture(t *testing.T) string {
	t.Helper()
	starter, poller, identity, lister := githubDeviceStarter, githubDevicePoller, githubIdentityResolver, githubModelLister
	loginFlowsMu.Lock()
	oldFlows := loginFlows
	loginFlows = map[string]loginFlow{}
	loginFlowsMu.Unlock()
	t.Cleanup(func() {
		githubDeviceStarter, githubDevicePoller, githubIdentityResolver, githubModelLister = starter, poller, identity, lister
		loginFlowsMu.Lock()
		loginFlows = oldFlows
		loginFlowsMu.Unlock()
	})
	githubDeviceStarter = func(context.Context) (*kiroauth.SocialDeviceAuthorization, error) {
		return &kiroauth.SocialDeviceAuthorization{DeviceCode: "github-device", UserCode: "CODE", VerificationURIComplete: "https://app.kiro.dev/account/device?user_code=CODE&login_provider=Github", ExpiresInMilliseconds: 300000, IntervalInMilliseconds: 5000}, nil
	}
	githubDevicePoller = func(context.Context, string) (*kiroauth.KiroTokenData, error) {
		return nil, kiroauth.ErrAuthorizationPending
	}
	githubIdentityResolver = func(context.Context, *kiroauth.KiroTokenData) {}
	githubModelLister = func(_ context.Context, token *kiroauth.KiroTokenData) ([]controlPlaneModel, error) {
		if token.AuthMethod != "social" || token.Provider != "Github" {
			t.Fatalf("wrong catalog credential: %+v", token)
		}
		return []controlPlaneModel{{ModelID: "claude-haiku-4.5"}}, nil
	}
	raw, err := handleLoginStart([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	var started pluginapi.AuthLoginStartResponse
	decodeEnvelope(t, raw, &started)
	body, _ := json.Marshal(connectAPIRequest{State: started.State, Method: "github"})
	raw, err = handleConnectAPI(pluginapi.ManagementRequest{Method: http.MethodPost, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	var response pluginapi.ManagementResponse
	decodeEnvelope(t, raw, &response)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(response.Body), "authorization_required") {
		t.Fatalf("connect = %+v", response)
	}
	return started.State
}

func githubPoll(t *testing.T, state string) pluginapi.AuthLoginPollResponse {
	t.Helper()
	raw, _ := json.Marshal(pluginapi.AuthLoginPollRequest{State: state})
	out, err := handleLoginPoll(raw)
	if err != nil {
		t.Fatal(err)
	}
	var response pluginapi.AuthLoginPollResponse
	decodeEnvelope(t, out, &response)
	return response
}

func githubPollReady(t *testing.T, state string) {
	t.Helper()
	if err := updateLoginFlow(state, func(f *loginFlow) { f.NextPollAt = time.Time{} }); err != nil {
		t.Fatal(err)
	}
}

func TestGitHubLoginSharesCredentialModelRefreshAndUsageLifecycle(t *testing.T) {
	state := githubFixture(t)
	githubDevicePoller = func(_ context.Context, code string) (*kiroauth.KiroTokenData, error) {
		if code != "github-device" {
			t.Fatalf("code = %q", code)
		}
		return &kiroauth.KiroTokenData{AccessToken: "github-access", RefreshToken: "github-refresh", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, nil
	}
	githubPollReady(t, state)
	logged := githubPoll(t, state)
	if logged.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("login = %+v", logged)
	}
	stored, err := decodeToken(logged.Auth.StorageJSON)
	if err != nil {
		t.Fatal(err)
	}
	if stored.AuthMethod != "social" || stored.Provider != "Github" || logged.Auth.Provider != "kiro" || intValue(logged.Auth.Metadata[refreshIntervalKey], 0) != 1800 {
		t.Fatalf("auth = %+v, token = %+v", logged.Auth, stored)
	}
	if githubPoll(t, state).Status != pluginapi.AuthLoginStatusError {
		t.Fatal("completed state was reused")
	}
	catalog, err := modelsForAuth(t, logged.Auth.StorageJSON)
	if err != nil {
		t.Fatal(err)
	}
	if modelIDs(catalog) != "claude-haiku-4.5" {
		t.Fatalf("models = %s", modelIDs(catalog))
	}
	account := resolveAccount(stored)
	core, err := buildCoreAuth(pluginapi.ExecutorRequest{AuthID: logged.Auth.ID, StorageJSON: logged.Auth.StorageJSON, AuthMetadata: logged.Auth.Metadata, AuthAttributes: logged.Auth.Attributes})
	if err != nil {
		t.Fatal(err)
	}
	if routed := kiroroute.Resolve(kiroexecutor.RoutingCredential(core)); routed.Provider != kiroroute.ProviderGithub {
		t.Fatalf("executor lost GitHub provider: %+v", routed)
	}
	runtimeURL, err := account.RuntimeURL()
	if err != nil || runtimeURL != "https://runtime.us-east-1.kiro.dev/generateAssistantResponse" {
		t.Fatalf("runtime = %s: %v", runtimeURL, err)
	}
	usage, err := requestUsageLimits(context.Background(), httpDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer github-access" || req.URL.Query().Get("origin") != "AI_EDITOR" {
			t.Fatalf("usage request = %s %v", req.URL, req.Header)
		}
		return catalogResponse(http.StatusOK, `{"subscriptionInfo":{"subscriptionTitle":"KIRO PRO"},"usageBreakdownList":[]}`), nil
	}), stored)
	if err != nil || usage.SubscriptionInfo.SubscriptionTitle != "KIRO PRO" {
		t.Fatalf("usage = %+v: %v", usage, err)
	}
	oldRefresher := desktopTokenRefresher
	t.Cleanup(func() { desktopTokenRefresher = oldRefresher })
	desktopTokenRefresher = func(_ context.Context, refresh, region string) (*kiroauth.KiroTokenData, error) {
		if refresh != "github-refresh" || region != "us-east-1" {
			t.Fatalf("refresh input = %s/%s", refresh, region)
		}
		return &kiroauth.KiroTokenData{AccessToken: "rotated-access", RefreshToken: "rotated-refresh", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, nil
	}
	// Refresh must retain the same filename and all host-owned options.
	stubCatalog(t, func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer rotated-access" {
			t.Fatalf("catalog after refresh: %v", req.Header)
		}
		return catalogResponse(200, builderIDCatalog), nil
	})
	raw, _ := json.Marshal(pluginapi.AuthRefreshRequest{AuthID: logged.Auth.ID, StorageJSON: logged.Auth.StorageJSON, Attributes: map[string]string{"path": "/auths/" + logged.Auth.FileName}, Metadata: map[string]any{"disabled": true, "priority": 4, "note": "keep", "disable_cooling": true}})
	out, err := handleRefreshAuth(raw)
	if err != nil {
		t.Fatal(err)
	}
	var refreshed pluginapi.AuthRefreshResponse
	decodeEnvelope(t, out, &refreshed)
	rotated, err := decodeToken(refreshed.Auth.StorageJSON)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.AccessToken != "rotated-access" || rotated.RefreshToken != "rotated-refresh" || rotated.AuthMethod != "social" || rotated.Provider != "Github" || rotated.Identity != stored.Identity || !rotated.Disabled || !rotated.DisableCooling || rotated.Priority != 4 {
		t.Fatalf("rotated = %+v", rotated)
	}
	if refreshed.Auth.FileName != logged.Auth.FileName || refreshed.Auth.Attributes["path"] != "/auths/"+logged.Auth.FileName || string(rotated.Extra["note"]) != `"keep"` || refreshed.NextRefreshAfter.IsZero() {
		t.Fatalf("refresh lost host state: %+v", refreshed)
	}
}

func TestGitHubPollingPacesSlowDownAndTerminalErrors(t *testing.T) {
	state := githubFixture(t)
	calls := 0
	githubDevicePoller = func(context.Context, string) (*kiroauth.KiroTokenData, error) {
		calls++
		return nil, kiroauth.ErrSlowDown
	}
	if githubPoll(t, state).Status != pluginapi.AuthLoginStatusPending || calls != 0 {
		t.Fatal("polled before interval")
	}
	githubPollReady(t, state)
	if githubPoll(t, state).Status != pluginapi.AuthLoginStatusPending || calls != 1 {
		t.Fatal("slow_down did not stay pending")
	}
	loginFlowsMu.Lock()
	flow := loginFlows[state]
	loginFlowsMu.Unlock()
	if flow.PollInterval != 10*time.Second || flow.Polling {
		t.Fatalf("slow_down flow = %+v", flow)
	}
	githubPoll(t, state)
	if calls != 1 {
		t.Fatal("ignored increased interval")
	}
	githubPollReady(t, state)
	githubDevicePoller = func(context.Context, string) (*kiroauth.KiroTokenData, error) {
		calls++
		return nil, kiroauth.OIDCStatusError{Status: 400, Message: "authorization denied"}
	}
	if githubPoll(t, state).Status != pluginapi.AuthLoginStatusError {
		t.Fatal("denial not terminal")
	}
	githubPoll(t, state)
	if calls != 2 {
		t.Fatal("repolling denied authorization")
	}
}

func TestGitHubPollingRecoversTransientFailure(t *testing.T) {
	state := githubFixture(t)
	githubPollReady(t, state)
	githubDevicePoller = func(context.Context, string) (*kiroauth.KiroTokenData, error) {
		return nil, errors.New("network unavailable")
	}
	if githubPoll(t, state).Status != pluginapi.AuthLoginStatusPending {
		t.Fatal("transient failure ended login")
	}
	loginFlowsMu.Lock()
	f := loginFlows[state]
	loginFlowsMu.Unlock()
	if f.Polling || !f.NextPollAt.After(time.Now()) {
		t.Fatalf("retry not scheduled: %+v", f)
	}
}

func TestGitHubConcurrentPollDoesNotDuplicateExchange(t *testing.T) {
	state := githubFixture(t)
	githubPollReady(t, state)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	githubDevicePoller = func(context.Context, string) (*kiroauth.KiroTokenData, error) {
		close(entered)
		<-release
		return nil, kiroauth.ErrAuthorizationPending
	}
	go func() { defer close(done); githubPoll(t, state) }()
	<-entered
	if githubPoll(t, state).Status != pluginapi.AuthLoginStatusPending {
		t.Fatal("concurrent poll did not wait")
	}
	close(release)
	<-done
}

func TestGitHubOpaqueAccountsHaveDistinctPersistentFilenames(t *testing.T) {
	first := kiroFileName(&kiroauth.KiroTokenData{AuthMethod: "social", Identity: "github-first"})
	second := kiroFileName(&kiroauth.KiroTokenData{AuthMethod: "social", Identity: "github-second"})
	if first == second {
		t.Fatal("opaque GitHub accounts collide")
	}
}

func TestGitHubExpiredSessionNeverExchangesDeviceCode(t *testing.T) {
	state := githubFixture(t)
	githubDevicePoller = func(context.Context, string) (*kiroauth.KiroTokenData, error) {
		t.Fatal("polled expired session")
		return nil, nil
	}
	if err := updateLoginFlow(state, func(f *loginFlow) { f.ExpiresAt = time.Now().Add(-time.Second) }); err != nil {
		t.Fatal(err)
	}
	if githubPoll(t, state).Status != pluginapi.AuthLoginStatusError {
		t.Fatal("expired session remained pending")
	}
}
