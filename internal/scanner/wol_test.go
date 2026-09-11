package scanner

import (
	"bytes"
	"testing"
)

func TestMacToBytes(t *testing.T) {
	want := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	cases := []string{"aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff"}
	for _, mac := range cases {
		got, err := macToBytes(mac)
		if err != nil {
			t.Fatalf("macToBytes(%q): %v", mac, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("macToBytes(%q) = %x, want %x", mac, got, want)
		}
	}
}

func TestMacToBytes_Invalid(t *testing.T) {
	if _, err := macToBytes("not-a-mac"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := macToBytes("aa:bb:cc:dd:ee"); err == nil {
		t.Fatal("expected error for short MAC")
	}
}

func TestWakeOnLAN_InvalidMAC(t *testing.T) {
	if err := WakeOnLAN("not-a-mac", ""); err == nil {
		t.Fatal("expected error for invalid MAC")
	}
}

func TestBuildMagicPacket(t *testing.T) {
	p, err := buildMagicPacket("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 102 {
		t.Fatalf("expected 102-byte packet, got %d", len(p))
	}
	for i := 0; i < 6; i++ {
		if p[i] != 0xFF {
			t.Errorf("byte %d = %#x, want 0xFF", i, p[i])
		}
	}
	want := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	for rep := 0; rep < 16; rep++ {
		got := p[6+rep*6 : 6+rep*6+6]
		if !bytes.Equal(got, want) {
			t.Errorf("MAC repetition %d = %x, want %x", rep, got, want)
		}
	}
}
