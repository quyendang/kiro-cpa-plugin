package kiro

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGitHubDeviceAuthorizationContract(t *testing.T) {
	client, req := desktopClient(t, 200, `{"deviceCode":"device","userCode":"CODE","verificationUriComplete":"https://app.kiro.dev/account/device?user_code=CODE&login_provider=Github","expiresInMilliseconds":300000,"intervalInMilliseconds":5000}`)
	result, err := client.StartGitHubDeviceAuthorization(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.String() != socialAuthBase+"/oauth/device/authorization" || req.Method != "POST" {
		t.Fatalf("request = %s %s", req.Method, req.URL)
	}
	var payload map[string]string
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["clientId"] != "kiro-cli" || payload["loginProvider"] != "Github" || len(payload) != 2 {
		t.Fatalf("payload = %v", payload)
	}
	if result.ExpiresInMilliseconds != 300000 || result.IntervalInMilliseconds != 5000 {
		t.Fatalf("durations = %+v", result)
	}
}

func TestGitHubPollUnderstandsStatusAndErrorProgress(t *testing.T) {
	for _, body := range []string{`{"status":"authorization_pending"}`, `{"error":"authorization_pending"}`, `{"status":"slow_down"}`, `{"error":"slow_down"}`} {
		for _, status := range []int{200, 400} {
			client, req := desktopClient(t, status, body)
			_, err := client.PollGitHubDeviceToken(context.Background(), "device")
			want := ErrAuthorizationPending
			if strings.Contains(body, "slow_down") {
				want = ErrSlowDown
			}
			if !errors.Is(err, want) {
				t.Fatalf("HTTP %d %s: %v", status, body, err)
			}
			if req.URL.String() != socialAuthBase+"/oauth/device/poll" {
				t.Fatalf("endpoint = %s", req.URL)
			}
			var payload map[string]string
			_ = json.NewDecoder(req.Body).Decode(&payload)
			if payload["deviceCode"] != "device" || payload["clientId"] != socialClientID || len(payload) != 2 {
				t.Fatalf("payload = %v", payload)
			}
		}
	}
}

func TestGitHubPollRequiresRefreshableCredential(t *testing.T) {
	for _, body := range []string{`{}`, `{"accessToken":"access"}`, `{"refreshToken":"refresh"}`, `{"accessToken":"access","refreshToken":" "}`, `not json`} {
		client, _ := desktopClient(t, 200, body)
		if _, err := client.PollGitHubDeviceToken(context.Background(), "device"); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	client, _ := desktopClient(t, 200, `{"accessToken":"access","refreshToken":"refresh","profileArn":"profile"}`)
	token, err := client.PollGitHubDeviceToken(context.Background(), "device")
	if err != nil {
		t.Fatal(err)
	}
	if token.AuthMethod != "social" || token.Provider != "Github" || token.Region != "us-east-1" || token.ProfileArn != "profile" {
		t.Fatalf("credential = %+v", token)
	}
	expires, _ := time.Parse(time.RFC3339, token.ExpiresAt)
	if time.Until(expires) < 59*time.Minute {
		t.Fatalf("expiry = %v", expires)
	}
}

func TestGitHubAuthorizationRejectsUnsafeOrIncompleteReplies(t *testing.T) {
	for _, u := range []string{"http://app.kiro.dev/account/device", "https://app.kiro.dev.evil.test/account/device", "https://app.kiro.dev:8443/account/device", "https://user@app.kiro.dev/account/device", "https://app.kiro.dev/other", "javascript:alert(1)"} {
		body, _ := json.Marshal(map[string]string{"deviceCode": "device", "userCode": "CODE", "verificationUriComplete": u})
		client, _ := desktopClient(t, 200, string(body))
		if _, err := client.StartGitHubDeviceAuthorization(context.Background()); err == nil {
			t.Fatalf("accepted %s", u)
		}
	}
	client, _ := desktopClient(t, 200, `{"verificationUriComplete":"https://app.kiro.dev/account/device"}`)
	if _, err := client.StartGitHubDeviceAuthorization(context.Background()); err == nil {
		t.Fatal("accepted missing codes")
	}
}

func TestGitHubErrorsAreBoundedAndDoNotExposeSecrets(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{
		{400, `{"error":"access_denied","accessToken":"secret-value"}`},
		{200, `{"status":"expired_token"}`},
		{429, `{"error":"throttled","refreshToken":"secret-value"}`},
		{500, strings.Repeat("secret-value", maxSocialResponseBytes)},
	} {
		client, _ := desktopClient(t, tc.status, tc.body)
		_, err := client.PollGitHubDeviceToken(context.Background(), "device")
		if err == nil || strings.Contains(err.Error(), "secret-value") {
			t.Fatalf("unsafe error: %v", err)
		}
	}
}

func TestGitHubDeviceCodeIsNeverSentThroughRedirect(t *testing.T) {
	calls := 0
	client := &SSOOIDCClient{httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls > 1 {
			t.Fatal("followed redirect carrying device code")
		}
		return &http.Response{StatusCode: 307, Header: http.Header{"Location": {"https://evil.test/"}}, Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
	})}}
	if _, err := client.PollGitHubDeviceToken(context.Background(), "device"); err == nil {
		t.Fatal("accepted redirect")
	}
}
