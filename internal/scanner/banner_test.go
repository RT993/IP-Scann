package scanner

import "testing"

func TestGuessServiceFromBanner(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_9.6":                "SSH",
		"220 mail.example.com ESMTP Postfix": "SMTP",
		"220 (vsFTPd 3.0.5)":                 "FTP",
		"+OK POP3 server ready":              "POP3",
		"* OK IMAP4rev1 Service Ready":       "IMAP",
		"5.7.8 mysql_native_password":        "MySQL/MariaDB",
		"totally unrecognized banner text":   "",
	}
	for banner, want := range cases {
		if got := guessServiceFromBanner(banner); got != want {
			t.Errorf("guessServiceFromBanner(%q) = %q, want %q", banner, got, want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("got %q", got)
	}
	if got := truncate("this is way too long", 7); got != "this is…" {
		t.Errorf("got %q", got)
	}
}
