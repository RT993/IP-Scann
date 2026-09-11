package scanner

import "testing"

func TestGuessOS_TTLBuckets(t *testing.T) {
	cases := []struct {
		ttl  int
		want string
	}{
		{60, "Linux / macOS / Unix"},
		{64, "Linux / macOS / Unix"},
		{120, "Windows"},
		{128, "Windows"},
		{200, "Network device"},
		{0, "Unknown"},
	}
	for _, c := range cases {
		g := GuessOS(c.ttl, "", nil)
		if g.Label != c.want {
			t.Errorf("GuessOS(ttl=%d) label = %q, want %q", c.ttl, g.Label, c.want)
		}
	}
}

func TestGuessOS_AppleVendorOverridesLabel(t *testing.T) {
	g := GuessOS(128, "Apple", nil) // even with a Windows-range TTL
	if g.Label != "macOS / iOS (Apple device)" {
		t.Errorf("got label %q", g.Label)
	}
	if g.Confidence != "high" {
		t.Errorf("expected high confidence, got %q", g.Confidence)
	}
}

func TestGuessOS_RDPPortImpliesWindows(t *testing.T) {
	g := GuessOS(64, "", []int{3389})
	if g.Label != "Windows" || g.Confidence != "high" {
		t.Errorf("got %+v", g)
	}
}

func TestGuessOS_UnknownWithNoSignals(t *testing.T) {
	g := GuessOS(0, "", nil)
	if g.Label != "Unknown" {
		t.Errorf("got label %q", g.Label)
	}
	if len(g.Signals) != 0 {
		t.Errorf("expected no signals, got %v", g.Signals)
	}
}
