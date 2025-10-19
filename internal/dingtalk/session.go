package dingtalk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DingTalk API endpoints (current as of 2025; adjust if DingTalk changes)
const (
	userAccessTokenURL = "https://api.dingtalk.com/v1.0/oauth2/userAccessToken"
	userProfileURL     = "https://api.dingtalk.com/v1.0/contact/users/me" // requires user access token
	appAccessTokenURL  = "https://api.dingtalk.com/v1.0/oauth2/accessToken"
	getByUnionIDURL    = "https://oapi.dingtalk.com/topapi/user/getbyunionid" // ?access_token= appended
	corpUserGetURL     = "https://oapi.dingtalk.com/topapi/v2/user/get"       // ?access_token= appended
)

// Provider holds DingTalk app credentials.
type Provider struct {
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
}

func (p *Provider) client() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return http.DefaultClient
}

// User represents the merged DingTalk user information we expose to OIDC.
type User struct {
	UnionID   string `json:"unionId"`
	Nick      string `json:"nick"`
	OpenID    string `json:"openId"`
	Email     string `json:"email,omitempty"`
	Mobile    string `json:"mobile,omitempty"`
	AvatarURL string `json:"avatarUrl,omitempty"`
}

// Session manages a single DingTalk login exchange.
type Session struct {
	provider     *Provider
	dtCode       string
	clientID     string // same as provider.ClientID, kept for clarity
	clientSecret string
	accessToken  string
	expiresAt    time.Time
}

func NewSession(p *Provider, dingTalkAuthCode string) *Session {
	return &Session{provider: p, dtCode: dingTalkAuthCode, clientID: p.ClientID, clientSecret: p.ClientSecret}
}

// FetchUser runs the DingTalk custom flow and returns a merged user.
func (s *Session) FetchUser(ctx context.Context) (*User, error) {
	at, err := s.getUserAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get user access token: %w", err)
	}
	user, err := s.getUserInfo(ctx, at)
	if err != nil {
		return nil, fmt.Errorf("get user info: %w", err)
	}
	// Try enrich with corp info (best effort)
	if corpEmail, corpMobile, err := s.getCorpEmailAndMobile(ctx, user.UnionID); err == nil {
		if corpEmail != "" {
			user.Email = corpEmail
		}
		if corpMobile != "" {
			user.Mobile = corpMobile
		}
	}
	return user, nil
}

// getUserAccessToken exchanges the DingTalk code for a user access token.
func (s *Session) getUserAccessToken(ctx context.Context) (string, error) {
	if s.accessToken != "" && time.Now().Before(s.expiresAt) {
		return s.accessToken, nil
	}
	body := map[string]any{
		"clientId":     s.clientID,
		"clientSecret": s.clientSecret,
		"code":         s.dtCode,
		"grantType":    "authorization_code",
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, userAccessTokenURL, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.provider.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("user access token status %d: %s", resp.StatusCode, string(data))
	}
	var tr struct {
		AccessToken string `json:"accessToken"`
		ExpireIn    int    `json:"expireIn"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode user access token: %w", err)
	}
	if tr.AccessToken == "" {
		return "", errors.New("empty access token")
	}
	s.accessToken = tr.AccessToken
	if tr.ExpireIn > 0 {
		s.expiresAt = time.Now().Add(time.Duration(tr.ExpireIn) * time.Second)
	} else {
		s.expiresAt = time.Now().Add(55 * time.Minute)
	}
	return s.accessToken, nil
}

func (s *Session) getUserInfo(ctx context.Context, accessToken string) (*User, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userProfileURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-acs-dingtalk-access-token", accessToken)
	resp, err := s.provider.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("profile status %d: %s", resp.StatusCode, string(data))
	}
	var u User
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, fmt.Errorf("decode user profile: %w", err)
	}
	return &u, nil
}

func (s *Session) getCorpEmailAndMobile(ctx context.Context, unionID string) (string, string, error) {
	appToken, err := s.getAppAccessToken(ctx)
	if err != nil {
		return "", "", err
	}
	userID, err := s.getUserIDByUnionID(ctx, unionID, appToken)
	if err != nil {
		return "", "", err
	}
	return s.getUserCorpDetails(ctx, userID, appToken)
}

func (s *Session) getAppAccessToken(ctx context.Context) (string, error) {
	body := map[string]string{"appKey": s.clientID, "appSecret": s.clientSecret}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, appAccessTokenURL, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.provider.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("app token status %d: %s", resp.StatusCode, string(data))
	}
	var tr struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", err
	}
	return tr.AccessToken, nil
}

func (s *Session) getUserIDByUnionID(ctx context.Context, unionID, appToken string) (string, error) {
	payload := map[string]string{"unionid": unionID}
	b, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s?access_token=%s", getByUnionIDURL, appToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.provider.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("getByUnionID status %d: %s", resp.StatusCode, string(data))
	}
	var r struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
		Result  struct {
			UserID string `json:"userid"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	if r.ErrCode != 0 {
		return "", fmt.Errorf("dingtalk error: %s", r.ErrMsg)
	}
	return r.Result.UserID, nil
}

func (s *Session) getUserCorpDetails(ctx context.Context, userID, appToken string) (string, string, error) {
	payload := map[string]string{"userid": userID}
	b, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s?access_token=%s", corpUserGetURL, appToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.provider.client().Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("corp user status %d: %s", resp.StatusCode, string(data))
	}
	var r struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
		Result  struct {
			Email  string `json:"email"`
			Mobile string `json:"mobile"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", "", err
	}
	if r.ErrCode != 0 {
		return "", "", fmt.Errorf("dingtalk error: %s", r.ErrMsg)
	}
	return r.Result.Email, r.Result.Mobile, nil
}
