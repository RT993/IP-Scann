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

// VendorLookup returns a best-effort manufacturer name for a MAC address
// using a small, bundled offline OUI reference table (not the full IEEE
// registry). Unrecognized prefixes return "Unknown".
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
