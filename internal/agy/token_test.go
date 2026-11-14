package agy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func makeIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + ".signature"
}

func makeTokenFile(t *testing.T, email, subject, refresh, expiry string) []byte {
	t.Helper()
	document := map[string]any{
		"token": map[string]any{
			"access_token":  "access-token",
			"token_type":    "Bearer",
			"refresh_token": refresh,
			"expiry":        expiry,
		},
		"auth_method": "consumer",
		"id_token":    makeIDToken(t, map[string]any{"email": email, "sub": subject}),
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseTokenFile(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Format(time.RFC3339Nano)
	raw := makeTokenFile(t, "user@example.com", "subject-1", "refresh-1", expiry)

	tokenFile, err := ParseTokenFile(raw)
	if err != nil {
		t.Fatalf("ParseTokenFile: %v", err)
	}
	if tokenFile.Email() != "user@example.com" {
		t.Errorf("email = %q", tokenFile.Email())
	}
	if tokenFile.Subject() != "subject-1" {
		t.Errorf("subject = %q", tokenFile.Subject())
	}
	if !tokenFile.HasRefreshToken() {
		t.Error("expected refresh token")
	}
	if tokenFile.Expired(time.Now()) {
		t.Error("token should not be expired")
	}
	if tokenFile.Fingerprint() == "" {
		t.Error("expected fingerprint")
	}
}

func TestParseTokenFileRejectsInvalid(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte(""),
		[]byte("not json"),
		[]byte(`{"token":{}}`),
	}
	for _, raw := range cases {
		if _, err := ParseTokenFile(raw); err == nil {
			t.Errorf("expected error for %q", string(raw))
		}
	}
}

func TestExpiryTime(t *testing.T) {
	tokenFile := &TokenFile{Token: Token{Expiry: "2026-10-20T23:02:46.46381726+07:00"}}
	expiry, ok := tokenFile.ExpiryTime()
	if !ok {
		t.Fatal("expected expiry")
	}
	if expiry.Year() != 2026 {
		t.Errorf("year = %d", expiry.Year())
	}
	if _, ok := (&TokenFile{Token: Token{Expiry: "nonsense"}}).ExpiryTime(); ok {
		t.Error("expected invalid expiry to fail")
	}
}

func TestParseIDTokenAudienceForms(t *testing.T) {
	raw := makeIDToken(t, map[string]any{
		"iss":            "https://accounts.google.com",
		"aud":            []string{"client-a", "client-b"},
		"azp":            "client-a",
		"email":          "user@example.com",
		"email_verified": true,
		"sub":            "subject-1",
	})
	claims, err := ParseIDToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Audience) != 2 || claims.Audience[1] != "client-b" {
		t.Errorf("audience = %v", claims.Audience)
	}
	if !claims.EmailVerified {
		t.Error("expected verified email")
	}

	single := makeIDToken(t, map[string]any{"aud": "client-a"})
	claims, err = ParseIDToken(single)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "client-a" {
		t.Errorf("audience = %v", claims.Audience)
	}
}

func TestPhoneLikeTokensWithoutIDToken(t *testing.T) {
	document := `{"token":{"access_token":"a","refresh_token":"r"},"auth_method":"consumer"}`
	tokenFile, err := ParseTokenFile([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	if tokenFile.Email() != "" || tokenFile.Subject() != "" {
		t.Error("expected empty claims without id_token")
	}
	if tokenFile.Fingerprint() == "" {
		t.Error("expected fingerprint from refresh token")
	}
}

func TestTokenFilePreservesUnknownFieldsOnMarshal(t *testing.T) {
	raw := []byte(`{"token":{"access_token":"a","token_type":"Bearer","refresh_token":"r","expiry":"2099-01-01T00:00:00Z","scope":"openid"},"auth_method":"consumer","id_token":"","enterprise_org":"acme"}`)
	tf, err := ParseTokenFile(raw)
	if err != nil {
		t.Fatalf("ParseTokenFile: %v", err)
	}
	tf.Token.AccessToken = "a2"
	marshaled, err := json.Marshal(tf)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var check map[string]any
	if err := json.Unmarshal(marshaled, &check); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if check["enterprise_org"] != "acme" {
		t.Errorf("lost top-level unknown field: %+v", check)
	}
	tokenMap, _ := check["token"].(map[string]any)
	if tokenMap["scope"] != "openid" || tokenMap["access_token"] != "a2" {
		t.Errorf("unexpected token map: %+v", tokenMap)
	}
}

func TestValidateProjectAndRegion(t *testing.T) {
	if got, err := ValidateProjectID("sample-gcp-project"); err != nil || got != "sample-gcp-project" {
		t.Fatalf("ValidateProjectID valid = %q, %v", got, err)
	}
	for _, invalid := range []string{"", "   ", "bad project", "bad/project"} {
		_, err := ValidateProjectID(invalid)
		if err == nil {
			t.Errorf("expected invalid project ID %q to fail", invalid)
			continue
		}
		if strings.Contains(invalid, "/") && !strings.Contains(err.Error(), "slashes") {
			t.Errorf("expected slash error for %q, got %q", invalid, err.Error())
		}
	}
	if got, err := ValidateRegion(""); err != nil || got != RegionGlobal {
		t.Fatalf("ValidateRegion empty = %q, %v", got, err)
	}
	for _, valid := range []string{"global", "US", " eu "} {
		if _, err := ValidateRegion(valid); err != nil {
			t.Errorf("ValidateRegion(%q) = %v", valid, err)
		}
	}
	if _, err := ValidateRegion("asia"); err == nil {
		t.Error("expected invalid region to fail")
	}
}

func TestWithGCPOptionsPreservesUnknownFieldsAndLargeIntegers(t *testing.T) {
	raw := []byte(`{"token":{"access_token":"a","refresh_token":"r"},"auth_method":"consumer","custom_field":"keep","user_tier":"g1-pro-tier","big_num":9007199254740993}`)
	updated, err := WithGCPOptions(raw, AuthMethodGCP, "sample-gcp-project", "us")
	if err != nil {
		t.Fatal(err)
	}
	tf, err := ParseTokenFile(updated)
	if err != nil {
		t.Fatal(err)
	}
	if tf.AuthMethod != AuthMethodGCP || tf.ProjectID != "sample-gcp-project" || tf.Region != RegionUS {
		t.Fatalf("unexpected GCP token fields: %+v", tf)
	}
	if tf.UserTier != "" {
		t.Errorf("expected user_tier to be cleared for PayGo, got %q", tf.UserTier)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(updated, &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc["custom_field"]) != `"keep"` {
		t.Errorf("unknown field lost: %+v", doc)
	}
	if !bytes.Equal(doc["big_num"], []byte("9007199254740993")) {
		t.Errorf("big_num precision lost: %s", doc["big_num"])
	}
}

func TestTokenFileMarshalRoundTripsGCPFieldsAndExtra(t *testing.T) {
	raw := []byte(`{"token":{"access_token":"a","token_type":"Bearer","refresh_token":"r","expiry":"2099-01-01T00:00:00Z"},"auth_method":"gcp","project_id":"sample-gcp-project","region":"eu","id_token":"e30.e30.sig","id_token_email":"fallback@example.com","custom_meta":"keep"}`)
	tf, err := ParseTokenFile(raw)
	if err != nil {
		t.Fatalf("ParseTokenFile: %v", err)
	}
	if tf.Email() != "fallback@example.com" {
		t.Fatalf("Email() = %q, want fallback@example.com", tf.Email())
	}
	tf.Token.AccessToken = "a2"
	marshaled, err := json.Marshal(tf)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	reloaded, err := ParseTokenFile(marshaled)
	if err != nil {
		t.Fatalf("ParseTokenFile reloaded: %v", err)
	}
	if reloaded.ProjectID != "sample-gcp-project" || reloaded.Region != RegionEU || reloaded.IDTokenEmail != "fallback@example.com" {
		t.Errorf("reloaded fields = %+v", reloaded)
	}
	var check map[string]any
	if err := json.Unmarshal(marshaled, &check); err != nil {
		t.Fatal(err)
	}
	if check["custom_meta"] != "keep" {
		t.Errorf("lost custom_meta after marshal: %+v", check)
	}
}
