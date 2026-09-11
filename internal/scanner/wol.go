package scanner

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"syscall"
)

// wolPorts are the two UDP ports Wake-on-LAN listeners conventionally
// listen on. The packet is identical either way; sending to both costs
// nothing and covers whichever the target expects.
var wolPorts = []int{9, 7}

// WakeOnLAN sends a Wake-on-LAN "magic packet" for mac as a UDP broadcast
// to broadcastIP (or the limited broadcast address 255.255.255.255, which
// reaches every host on the local link, if broadcastIP is empty). Like the
// rest of this package it needs no root/admin privileges: broadcasting a
// plain UDP datagram only needs the SO_BROADCAST socket option, not a raw
// socket.
//
// This only sends the packet; it can't confirm the target actually woke up
// (Wake-on-LAN itself is fire-and-forget UDP, so no real scanner tool can).
func WakeOnLAN(mac string, broadcastIP string) error {
	packet, err := buildMagicPacket(mac)
	if err != nil {
		return err
	}

	if broadcastIP == "" {
		broadcastIP = "255.255.255.255"
	}
	ip := net.ParseIP(broadcastIP)
	if ip == nil {
		return fmt.Errorf("invalid broadcast address %q", broadcastIP)
	}

	var lastErr error
	sent := false
	for _, port := range wolPorts {
		addr := net.UDPAddr{IP: ip, Port: port}
		if err := sendUDPBroadcast(addr, packet); err != nil {
			lastErr = err
			continue
		}
		sent = true
	}
	if sent {
		return nil
	}
	return lastErr
}

// buildMagicPacket builds the standard 102-byte Wake-on-LAN payload: six
// 0xFF bytes followed by the target MAC address repeated 16 times.
func buildMagicPacket(mac string) ([]byte, error) {
	hw, err := macToBytes(mac)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		packet = append(packet, 0xFF)
	}
	for i := 0; i < 16; i++ {
		packet = append(packet, hw...)
	}
	return packet, nil
}

func macToBytes(mac string) ([]byte, error) {
	clean := strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac)
	if len(clean) != 12 {
		return nil, fmt.Errorf("invalid MAC address %q", mac)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address %q: %w", mac, err)
	}
	return b, nil
}

// sendUDPBroadcast sends payload to addr with SO_BROADCAST set on the
// socket. Go's net.UDPConn has no method for this, so it's set directly via
// the raw socket fd -- the standard, minimal way to send a broadcast
// datagram without a third-party dependency.
func sendUDPBroadcast(addr net.UDPAddr, payload []byte) error {
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	}); err != nil {
		return err
	}
	if sockErr != nil {
		return sockErr
	}

	_, err = conn.WriteToUDP(payload, &addr)
	return err
}
