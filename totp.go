package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	totpIssuer      = "launchgate"
	totpDigits      = 6
	totpPeriod      = 30
	totpDrift       = 1
	totpSecretBytes = 20
	totpSecretMin   = 10
	totpSecretMax   = 64
)

func newTOTPSecret() (string, error) {
	raw := make([]byte, totpSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	normalized = strings.TrimRight(normalized, "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil {
		return nil, errors.New("invalid TOTP secret")
	}
	return key, nil
}

func validTOTPSecret(secret string) bool {
	if secret == "" {
		return true
	}
	key, err := decodeTOTPSecret(secret)
	return err == nil && len(key) >= totpSecretMin && len(key) <= totpSecretMax
}

func totpCode(secret string, step int64) (string, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := uint32(digest[offset]&0x7f)<<24 | uint32(digest[offset+1])<<16 |
		uint32(digest[offset+2])<<8 | uint32(digest[offset+3])
	modulo := uint32(1)
	for range totpDigits {
		modulo *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%modulo), nil
}

func matchTOTPStep(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return 0, false
		}
	}
	current := now.Unix() / totpPeriod
	for offset := int64(-totpDrift); offset <= totpDrift; offset++ {
		step := current + offset
		if step <= lastStep {
			continue
		}
		expected, err := totpCode(secret, step)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

func totpURI(label, secret string) string {
	return "otpauth://totp/" + url.PathEscape(totpIssuer+":"+label) + "?secret=" + secret +
		"&issuer=" + url.QueryEscape(totpIssuer) + "&algorithm=SHA1&digits=" + strconv.Itoa(totpDigits) +
		"&period=" + strconv.Itoa(totpPeriod)
}
