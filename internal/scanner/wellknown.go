package scanner

import "sort"

// ExtendedPorts is a broader set of well-known ports than DefaultPorts,
// used by the on-demand per-host "port scanner" tool where scanning one
// host thoroughly is cheap, rather than the whole-network sweep where speed
// matters more.
var ExtendedPorts = buildExtendedPorts()

// portNames maps a port number to the service that's conventionally
// registered on it, shown as a hint alongside any live banner grab.
var portNames = map[int]string{
	20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
	53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
	88: "Kerberos", 110: "POP3", 111: "RPCbind", 123: "NTP",
	135: "MS-RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
	143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 179: "BGP", 389: "LDAP",
	443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE/VPN", 514: "Syslog",
	515: "LPD/Printer", 548: "AFP", 554: "RTSP", 587: "SMTP-Submission",
	623: "IPMI", 631: "IPP/AirPrint", 636: "LDAPS", 873: "rsync",
	902: "VMware", 989: "FTPS-DATA", 990: "FTPS", 993: "IMAPS", 995: "POP3S",
	1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle DB",
	1701: "L2TP", 1723: "PPTP", 1883: "MQTT", 2049: "NFS", 2181: "ZooKeeper",
	2375: "Docker", 2379: "etcd", 2483: "Oracle DB", 3000: "Dev server",
	3128: "Squid Proxy", 3306: "MySQL", 3389: "RDP", 3690: "Subversion",
	4040: "Spark UI", 5000: "UPnP/AirPlay/Synology", 5001: "Synology DSM",
	5222: "XMPP", 5353: "mDNS", 5432: "PostgreSQL", 5601: "Kibana",
	5672: "AMQP", 5900: "VNC", 5901: "VNC-1", 6379: "Redis",
	6443: "Kubernetes API", 6666: "IRC", 7000: "AirPlay", 7070: "RTSP-Alt",
	8000: "HTTP-Alt", 8006: "Proxmox", 8080: "HTTP-Proxy", 8081: "HTTP-Alt",
	8083: "HTTP-Alt", 8086: "InfluxDB", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
	9000: "HTTP-Alt/Portainer", 9090: "Prometheus", 9092: "Kafka",
	9100: "JetDirect/Printer", 9200: "Elasticsearch", 9999: "HTTP-Alt",
	10000: "Webmin", 27017: "MongoDB", 27018: "MongoDB", 32400: "Plex",
}

// PortName returns the conventional service name for a port, or "" if this
// tool has no opinion about it.
func PortName(port int) string {
	return portNames[port]
}

func buildExtendedPorts() []int {
	ports := make([]int, 0, len(portNames))
	for p := range portNames {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}
