package custodian

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/grpc/metadata"
)

func TestClaimedMDSummaryQuotesValues(t *testing.T) {
	md := metadata.Pairs("cwb-subject", `evil org=carriedworld`, "cwb-org", "testorg")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	got := claimedMDSummary(ctx)
	if !strings.Contains(got, `sub="evil org=carriedworld"`) {
		t.Fatalf("expected quoted subject, got %q", got)
	}
	if !strings.Contains(got, `org="testorg"`) {
		t.Fatalf("expected quoted org, got %q", got)
	}
}

func TestClaimedMDSummaryEmpty(t *testing.T) {
	if got := claimedMDSummary(context.Background()); got != "" {
		t.Fatalf("expected empty summary for no metadata, got %q", got)
	}
}

// TestTruncateRunesIsRuneSafe — a 200-byte cutoff landing mid-rune must not
// split the rune; the result must always be valid UTF-8.
func TestTruncateRunesIsRuneSafe(t *testing.T) {
	// "é" is 2 bytes (0xC3 0xA9); build a string whose 200th byte falls
	// inside a multi-byte rune when naively byte-sliced.
	s := strings.Repeat("a", 199) + strings.Repeat("é", 10) // byte 199 is the first byte of an 'é'

	got := truncateRunes(s, 200)
	if !utf8.ValidString(strings.TrimSuffix(got, "…")) {
		t.Fatalf("truncateRunes produced invalid UTF-8: %q", got)
	}
	if !strings.HasPrefix(got, strings.Repeat("a", 199)) {
		t.Fatalf("unexpected truncation: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("expected ellipsis marker, got %q", got)
	}

	// Short strings pass through untouched.
	if got := truncateRunes("short", 200); got != "short" {
		t.Fatalf("short string should be unmodified, got %q", got)
	}

	// Exactly-n-byte strings pass through untouched (no ellipsis).
	exact := strings.Repeat("x", 200)
	if got := truncateRunes(exact, 200); got != exact {
		t.Fatalf("exact-length string should be unmodified, got %q", got)
	}
}
