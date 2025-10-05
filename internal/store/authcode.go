package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"
)

// AuthCodeData holds data associated with an authorization code.
type AuthCodeData struct {
	UserSub  string
	User     any // full user object (dingtalk.User) for claims
	ClientID string
	Nonce    string
	Expiry   time.Time
}

type AuthCodeStore struct {
	mu   sync.RWMutex
	data map[string]AuthCodeData
}

func NewAuthCodeStore() *AuthCodeStore {
	return &AuthCodeStore{data: make(map[string]AuthCodeData)}
}

// Create stores a new auth code and returns the code.
func (s *AuthCodeStore) Create(d AuthCodeData) string {
	code := secureRandomString(32) // 32 bytes -> 43 char URL-safe
	s.mu.Lock()
	s.data[code] = d
	s.mu.Unlock()
	return code
}

// Consume returns and deletes the code if valid.
func (s *AuthCodeStore) Consume(code string) (AuthCodeData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.data[code]
	if !ok {
		return AuthCodeData{}, errors.New("invalid_code")
	}
	delete(s.data, code)
	if time.Now().After(d.Expiry) {
		return AuthCodeData{}, errors.New("expired_code")
	}
	return d, nil
}

func (s *AuthCodeStore) Cleanup() {
	cut := time.Now()
	s.mu.Lock()
	for k, v := range s.data {
		if cut.After(v.Expiry) {
			delete(s.data, k)
		}
	}
	s.mu.Unlock()
}

// secureRandomString returns a base64url (no padding) encoded string of n bytes of
// cryptographically secure randomness. n is the number of raw bytes (after decoding
// length will be ~4/3*n). We trim padding for URL safety per RFC 4648 §5.
func secureRandomString(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// In the unlikely event of failure, fall back to time-based seedless empty code.
		return ""
	}
	// Use RawURLEncoding to avoid '+' '/' '=' characters.
	return base64.RawURLEncoding.EncodeToString(b)
}
