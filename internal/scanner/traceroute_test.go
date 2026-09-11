package scanner

import "testing"

func TestParseHopLine(t *testing.T) {
	cases := []struct {
		line string
		want Hop
		ok   bool
	}{
		{" 1  192.168.1.1  1.234 ms", Hop{Number: 1, IP: "192.168.1.1", RTTMs: 1.234}, true},
		{" 2  10.0.0.1  0.512 ms  0.498 ms  0.501 ms", Hop{Number: 2, IP: "10.0.0.1", RTTMs: 0.512}, true},
		{" 3  * * *", Hop{Number: 3, TimedOut: true}, true},
		{"traceroute to 8.8.8.8 (8.8.8.8), 20 hops max", Hop{}, false},
		{"", Hop{}, false},
	}
	for _, c := range cases {
		got, ok := parseHopLine(c.line)
		if ok != c.ok {
			t.Errorf("parseHopLine(%q) ok = %v, want %v", c.line, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.Number != c.want.Number || got.IP != c.want.IP || got.TimedOut != c.want.TimedOut || got.RTTMs != c.want.RTTMs {
			t.Errorf("parseHopLine(%q) = %+v, want %+v", c.line, got, c.want)
		}
	}
}
