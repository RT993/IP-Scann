package scanner

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed data/oui.json
var ouiData []byte

var ouiTable map[string]string

func init() {
	ouiTable = make(map[string]string)
	_ = json.Unmarshal(ouiData, &ouiTable)
}

// VendorLookup returns a manufacturer name for a MAC address using a
// bundled offline snapshot of the IEEE MA-L (24-bit) OUI registry
// (internal/scanner/data/oui.json, regenerate with `make update-oui`).
// Newer MA-M/MA-S (28-/36-bit) allocations and unrecognized prefixes
// return "Unknown".
func VendorLookup(mac string) string {
	clean := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	clean = strings.ReplaceAll(clean, "-", "")
	if len(clean) < 6 {
		return "Unknown"
	}
	if v, ok := ouiTable[clean[:6]]; ok {
		return v
	}
	return "Unknown"
}
