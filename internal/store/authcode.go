package store

import (
	"errors"
	"math/rand"
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
	code := randomString(40)
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

// randomString creates a URL-safe random string (not cryptographically strong for simplicity).
func randomString(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
