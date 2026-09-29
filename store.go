package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	maxStoreBytes      = 1 << 20
	tokenBytes         = 32
	encodedTokenLength = 43
	maxInvitations     = 1000
	modeClosed         = "closed"
	modePreview        = "preview"
	modePublic         = "public"
)

type invitation struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	TokenHash string    `json:"token_hash"`
	ExpiresAt time.Time `json:"expires_at"`
}

type invitationStore struct {
	Mode        string       `json:"mode"`
	Invitations []invitation `json:"invitations"`
}

func validMode(mode string) bool {
	return mode == modeClosed || mode == modePreview || mode == modePublic
}

func loadStore(dir string) (invitationStore, error) {
	f, err := os.Open(filepath.Join(dir, "invitations.json"))
	if err != nil {
		return invitationStore{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStoreBytes+1))
	if err != nil {
		return invitationStore{}, err
	}
	var s invitationStore
	if len(data) > maxStoreBytes {
		return s, errors.New("invitation store too large")
	}
	if err = json.Unmarshal(data, &s); err != nil {
		return s, errors.New("invalid invitation store")
	}
	if !validMode(s.Mode) || len(s.Invitations) > maxInvitations {
		return s, errors.New("invalid invitation store")
	}
	seen := map[string]bool{}
	for _, i := range s.Invitations {
		hash, decodeErr := hex.DecodeString(i.TokenHash)
		if decodeErr != nil || len(hash) != tokenBytes || i.ID == "" || len(i.ID) > 64 || seen[i.ID] ||
			i.ExpiresAt.IsZero() {
			return s, errors.New("invalid invitation record")
		}
		seen[i.ID] = true
	}
	return s, nil
}

func withStoreLock(dir string, fn func() error) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	return fn()
}

func saveStore(dir string, s invitationStore) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if len(raw) > maxStoreBytes {
		return errors.New("invitation store too large")
	}
	f, err := os.CreateTemp(dir, ".invitations-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(append(raw, '\n')); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, "invitations.json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func initializeStore(dir string) error {
	return withStoreLock(dir, func() error {
		_, err := os.Stat(filepath.Join(dir, "invitations.json"))
		if !os.IsNotExist(err) {
			return errors.New("invitation store already exists or cannot be inspected")
		}
		return saveStore(dir, invitationStore{Mode: modeClosed, Invitations: []invitation{}})
	})
}

func setMode(dir, mode string) error {
	if !validMode(mode) {
		return errors.New("mode must be closed, preview, or public")
	}
	return withStoreLock(dir, func() error {
		s, err := loadStore(dir)
		if err != nil {
			return err
		}
		s.Mode = mode
		return saveStore(dir, s)
	})
}

func issueInvitation(dir, label string, ttl time.Duration, now time.Time) (invitation, string, error) {
	var i invitation
	if strings.TrimSpace(label) == "" || len(label) > 120 || strings.ContainsAny(label, "\r\n\x00") || ttl <= 0 ||
		ttl > 30*24*time.Hour {
		return i, "", errors.New("label is required; expiry must be between 1 second and 720 hours")
	}
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return i, "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	i = invitation{
		ID:        hex.EncodeToString(hash[:8]),
		Label:     label,
		TokenHash: hex.EncodeToString(hash[:]),
		ExpiresAt: now.Add(ttl).UTC(),
	}
	err := withStoreLock(dir, func() error {
		s, err := loadStore(dir)
		if err != nil {
			return err
		}
		active := s.Invitations[:0]
		for _, existing := range s.Invitations {
			if existing.ExpiresAt.After(now) {
				active = append(active, existing)
			}
		}
		s.Invitations = active
		if len(s.Invitations) >= maxInvitations {
			return errors.New("too many invitations")
		}
		s.Invitations = append(s.Invitations, i)
		return saveStore(dir, s)
	})
	return i, token, err
}

func revokeInvitation(dir, id string) error {
	return withStoreLock(dir, func() error {
		s, err := loadStore(dir)
		if err != nil {
			return err
		}
		for n, i := range s.Invitations {
			if i.ID == id {
				s.Invitations = append(s.Invitations[:n], s.Invitations[n+1:]...)
				return saveStore(dir, s)
			}
		}
		return errors.New("invitation not found")
	})
}
