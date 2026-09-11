package scanner

import "strings"

// skipDNSName advances past a (possibly compressed) DNS name starting at
// off and returns the offset of the byte right after it, without
// decoding the name itself.
func skipDNSName(buf []byte, off int) (next int, ok bool) {
	if off >= len(buf) {
		return 0, false
	}
	b := buf[off]
	if b&0xC0 == 0xC0 {
		if off+1 >= len(buf) {
			return 0, false
		}
		return off + 2, true
	}
	for {
		if off >= len(buf) {
			return 0, false
		}
		l := int(buf[off])
		if l == 0 {
			return off + 1, true
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(buf) {
				return 0, false
			}
			return off + 2, true
		}
		off += 1 + l
	}
}

// readDNSName decodes a (possibly compressed) DNS name starting at off. It
// returns the dotted name, the offset in buf right after the name *as
// encoded at off* (i.e. after a compression pointer, not after whatever it
// points to), and whether decoding succeeded.
func readDNSName(buf []byte, off int) (name string, next int, ok bool) {
	var labels []string
	cur := off
	jumped := false
	for guard := 0; guard < 128; guard++ {
		if cur >= len(buf) {
			return "", 0, false
		}
		b := buf[cur]
		if b == 0 {
			cur++
			if !jumped {
				next = cur
			}
			return strings.Join(labels, "."), next, true
		}
		if b&0xC0 == 0xC0 {
			if cur+1 >= len(buf) {
				return "", 0, false
			}
			ptr := int(b&0x3F)<<8 | int(buf[cur+1])
			if !jumped {
				next = cur + 2
				jumped = true
			}
			cur = ptr
			continue
		}
		l := int(b)
		cur++
		if cur+l > len(buf) {
			return "", 0, false
		}
		labels = append(labels, string(buf[cur:cur+l]))
		cur += l
	}
	return "", 0, false
}
