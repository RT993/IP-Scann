package scanner

import (
	"reflect"
	"testing"
)

func TestDetectConflicts_DuplicateIP(t *testing.T) {
	passes := []map[string]string{
		{"192.168.1.5": "aa:aa:aa:aa:aa:aa", "192.168.1.6": "bb:bb:bb:bb:bb:bb"},
		{"192.168.1.5": "cc:cc:cc:cc:cc:cc", "192.168.1.6": "bb:bb:bb:bb:bb:bb"},
	}
	report := DetectConflicts(passes)

	want := []string{"aa:aa:aa:aa:aa:aa", "cc:cc:cc:cc:cc:cc"}
	if got := report.DuplicateIPs["192.168.1.5"]; !reflect.DeepEqual(got, want) {
		t.Errorf("DuplicateIPs[192.168.1.5] = %v, want %v", got, want)
	}
	if _, ok := report.DuplicateIPs["192.168.1.6"]; ok {
		t.Error("192.168.1.6 should not be flagged: MAC never changed")
	}
	if len(report.DuplicateMACs) != 0 {
		t.Errorf("expected no duplicate MACs, got %v", report.DuplicateMACs)
	}
}

func TestDetectConflicts_DuplicateMAC(t *testing.T) {
	passes := []map[string]string{
		{"192.168.1.5": "aa:aa:aa:aa:aa:aa", "192.168.1.9": "aa:aa:aa:aa:aa:aa"},
	}
	report := DetectConflicts(passes)

	want := []string{"192.168.1.5", "192.168.1.9"}
	if got := report.DuplicateMACs["aa:aa:aa:aa:aa:aa"]; !reflect.DeepEqual(got, want) {
		t.Errorf("DuplicateMACs = %v, want %v", got, want)
	}
	if len(report.DuplicateIPs) != 0 {
		t.Errorf("expected no duplicate IPs, got %v", report.DuplicateIPs)
	}
}

func TestDetectConflicts_NoConflicts(t *testing.T) {
	passes := []map[string]string{
		{"192.168.1.1": "aa:aa:aa:aa:aa:aa"},
		{"192.168.1.1": "aa:aa:aa:aa:aa:aa"},
	}
	report := DetectConflicts(passes)
	if len(report.DuplicateIPs) != 0 || len(report.DuplicateMACs) != 0 {
		t.Errorf("expected no conflicts, got %+v", report)
	}
}
