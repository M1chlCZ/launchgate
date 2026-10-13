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
	maxInvitationUses  = 100000
	modeClosed         = "closed"
	modePreview        = "preview"
	modePublic         = "public"
)

type invitation struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	TokenHash  string    `json:"token_hash"`
	ExpiresAt  time.Time `json:"expires_at"`
	MaxUses    int       `json:"max_uses,omitempty"`
	Uses       int       `json:"uses,omitempty"`
	LastUsedAt time.Time `json:"last_used_at,omitzero"`
	TOTPSecret string    `json:"totp_secret,omitempty"`
	TOTPStep   int64     `json:"totp_step,omitempty"`
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
			i.ExpiresAt.IsZero() || i.Uses < 0 || i.MaxUses < 0 || i.MaxUses > maxInvitationUses ||
			(i.MaxUses > 0 && i.Uses > i.MaxUses) || i.TOTPStep < 0 || !validTOTPSecret(i.TOTPSecret) {
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
	return issueInvitationWithLimit(dir, label, ttl, 0, now)
}

func issueInvitationWithLimit(dir, label string, ttl time.Duration, maxUses int, now time.Time) (invitation, string, error) {
	return issueInvitationWithOptions(dir, issueOptions{Label: label, TTL: ttl, MaxUses: maxUses}, now)
}

type issueOptions struct {
	Label   string
	TTL     time.Duration
	MaxUses int
	TOTP    bool
}

func issueInvitationWithOptions(dir string, options issueOptions, now time.Time) (invitation, string, error) {
	var i invitation
	if strings.TrimSpace(options.Label) == "" || len(options.Label) > 120 ||
		strings.ContainsAny(options.Label, "\r\n\x00") || options.TTL <= 0 || options.TTL > 30*24*time.Hour {
		return i, "", errors.New("label is required; expiry must be between 1 second and 720 hours")
	}
	if options.MaxUses < 0 || options.MaxUses > maxInvitationUses {
		return i, "", errors.New("max uses must be between 0 and 100000")
	}
	secret := ""
	if options.TOTP {
		var err error
		if secret, err = newTOTPSecret(); err != nil {
			return i, "", err
		}
	}
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return i, "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	i = invitation{
		ID:         hex.EncodeToString(hash[:8]),
		Label:      options.Label,
		TokenHash:  hex.EncodeToString(hash[:]),
		ExpiresAt:  now.Add(options.TTL).UTC(),
		MaxUses:    options.MaxUses,
		TOTPSecret: secret,
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

type admissionResult int

const (
	admissionInvalid admissionResult = iota
	admissionExhausted
	admissionCodeMissing
	admissionCodeRejected
	admissionLocked
	admissionOK
)

type invitationLock func(id string) (time.Duration, bool)

func admitInvitation(dir, token, code string, now time.Time, locked invitationLock) (invitation, admissionResult, error) {
	var admitted invitation
	result := admissionInvalid
	err := withStoreLock(dir, func() error {
		s, loadErr := loadStore(dir)
		if loadErr != nil {
			return loadErr
		}
		found, ok := validInvitation(s, token, now)
		if !ok {
			return nil
		}
		admitted = found
		if found.MaxUses > 0 && found.Uses >= found.MaxUses {
			result = admissionExhausted
			return nil
		}
		if found.TOTPSecret != "" {
			if code == "" {
				result = admissionCodeMissing
				return nil
			}
			if locked != nil {
				if _, blocked := locked(found.ID); blocked {
					result = admissionLocked
					return nil
				}
			}
			step, matches := matchTOTPStep(found.TOTPSecret, code, now, found.TOTPStep)
			if !matches {
				result = admissionCodeRejected
				return nil
			}
			for n := range s.Invitations {
				if s.Invitations[n].ID == found.ID {
					s.Invitations[n].TOTPStep = step
					break
				}
			}
		}
		for n := range s.Invitations {
			if s.Invitations[n].ID == found.ID {
				s.Invitations[n].Uses++
				s.Invitations[n].LastUsedAt = now.UTC()
				admitted = s.Invitations[n]
				break
			}
		}
		if saveErr := saveStore(dir, s); saveErr != nil {
			return saveErr
		}
		result = admissionOK
		return nil
	})
	return admitted, result, err
}
