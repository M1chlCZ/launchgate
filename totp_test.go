package main

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTOTPCodesMatchRFC6238Vectors(t *testing.T) {
	t.Parallel()
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, tc := range []struct {
		step int64
		code string
	}{
		{1, "287082"},
		{37037036, "081804"},
	} {
		code, err := totpCode(secret, tc.step)
		if err != nil || code != tc.code {
			t.Fatalf("step %d code = %q, err = %v", tc.step, code, err)
		}
	}
	if _, err := totpCode("not base32!", 1); err == nil {
		t.Fatal("invalid secret accepted")
	}
	if !validTOTPSecret(secret) || !validTOTPSecret("") {
		t.Fatal("valid secret rejected")
	}
	if validTOTPSecret("tooshort") || validTOTPSecret("not base32!") {
		t.Fatal("invalid secret accepted")
	}
}

func TestTOTPURIEncodesLabelAndIssuer(t *testing.T) {
	t.Parallel()
	uri := totpURI("Comgate reviewer", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	want := "otpauth://totp/launchgate:Comgate%20reviewer?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" +
		"&issuer=launchgate&algorithm=SHA1&digits=6&period=30"
	if uri != want {
		t.Fatalf("uri = %q", uri)
	}
}

func TestAccessRequiresAndVerifiesTOTPCode(t *testing.T) {
	t.Parallel()
	g, dir, _ := fixture(t)
	invite, token, err := issueInvitationWithOptions(
		dir,
		issueOptions{Label: "reviewer", TTL: time.Hour, TOTP: true},
		time.Now(),
	)
	if err != nil || invite.TOTPSecret == "" {
		t.Fatal("TOTP invitation not issued")
	}
	if w := request(g, "POST", accessPath, `{"token":"`+token+`"}`, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("missing code: %d", w.Code)
	}
	if w := request(g, "POST", accessPath, `{"token":"`+token+`","code":"000000"}`, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", w.Code)
	}
	step := time.Now().Unix() / totpPeriod
	code, err := totpCode(invite.TOTPSecret, step)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(g, "POST", accessPath, `{"token":"`+token+`","code":"`+code+`"}`, nil); w.Code != http.StatusNoContent {
		t.Fatalf("valid code: %d %s", w.Code, w.Body.String())
	}
	if w := request(g, "POST", accessPath, `{"token":"`+token+`","code":"`+code+`"}`, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("replayed code: %d", w.Code)
	}
}

func TestTOTPCodeIgnoresCodeOnPlainInvitation(t *testing.T) {
	t.Parallel()
	g, dir, _ := fixture(t)
	_, token, err := issueInvitation(dir, "plain", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if w := request(g, "POST", accessPath, `{"token":"`+token+`","code":"123456"}`, nil); w.Code != http.StatusNoContent {
		t.Fatalf("plain invitation with code: %d %s", w.Code, w.Body.String())
	}
}

func TestIssueCommandTOTPFlagAndListColumn(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := initializeStore(dir); err != nil {
		t.Fatal(err)
	}
	cfg := config{Origin: "https://example.test", StateDir: dir}
	var out bytes.Buffer
	if err := issueCommand(cfg, []string{"-label", "reviewer", "-totp"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "TOTP: otpauth://totp/launchgate:reviewer?secret=") {
		t.Fatalf("issue output: %q", out.String())
	}
	s, err := loadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Invitations) != 1 || s.Invitations[0].TOTPSecret == "" {
		t.Fatalf("invitations: %+v", s.Invitations)
	}
	out.Reset()
	if err := listCommand(dir, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "\ttotp\n") {
		t.Fatalf("list output: %q", out.String())
	}
}

func TestStoreRejectsInvalidTOTPRecords(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("ab", tokenBytes)
	expiry := "2030-01-01T00:00:00Z"
	cases := []string{
		`{"mode":"preview","invitations":[{"id":"a","label":"l","token_hash":"` + hash +
			`","expires_at":"` + expiry + `","totp_secret":"not base32!"}]}`,
		`{"mode":"preview","invitations":[{"id":"a","label":"l","token_hash":"` + hash +
			`","expires_at":"` + expiry + `","totp_step":-1}]}`,
	}
	for _, content := range cases {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "invitations.json"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadStore(dir); err == nil {
			t.Errorf("invalid TOTP record accepted: %s", content)
		}
	}
	dir := t.TempDir()
	content := `{"mode":"preview","invitations":[{"id":"a","label":"l","token_hash":"` + hash +
		`","expires_at":"` + expiry + `","totp_secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","totp_step":42}]}`
	if err := os.WriteFile(filepath.Join(dir, "invitations.json"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := loadStore(dir)
	if err != nil || len(s.Invitations) != 1 || s.Invitations[0].TOTPStep != 42 {
		t.Fatalf("valid TOTP record: %+v, %v", s.Invitations, err)
	}
}
