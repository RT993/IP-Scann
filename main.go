// Command ip-scann runs a local web server that serves a browser-based UI
// for discovering every device on the local network and flagging duplicate
// IP address conflicts. It is a single self-contained binary: the frontend
// is embedded, and it builds natively for both Intel and Apple Silicon Macs.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/rt993/ip-scann/internal/api"
	"github.com/rt993/ip-scann/internal/scanner"
)

// version is set via -ldflags "-X main.version=..." by release builds.
var version = "dev"

func main() {
	host := flag.String("host", "127.0.0.1", "address to bind the local web server to")
	port := flag.Int("port", 7890, "port to listen on")
	openBrowser := flag.Bool("open", true, "open the UI in your default browser on start")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("ip-scanner " + version)
		return
	}

	handler := api.NewRouter()
	addr := fmt.Sprintf("%s:%d", *host, *port)
	url := fmt.Sprintf("http://%s:%d", *host, *port)
	if *host == "0.0.0.0" {
		url = fmt.Sprintf("http://127.0.0.1:%d", *port)
	}

	if *openBrowser {
		go func() {
			time.Sleep(300 * time.Millisecond)
			openInBrowser(url)
		}()
	}

	log.Printf("IP Scanner listening on %s", url)
	log.Printf("Scan only networks you own or are authorized to test.")
	logDeepScanCapability()

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func logDeepScanCapability() {
	if !scanner.NmapAvailable() {
		log.Printf(`nmap not found on PATH: the optional "Deep scan" tool will be unavailable (install with "brew install nmap" to enable it).`)
		return
	}
	if scanner.IsRoot() {
		log.Printf("nmap found and running as root: full deep-scan OS detection is available.")
	} else {
		log.Printf(`nmap found: deep-scan service/version detection is available; OS detection needs "sudo".`)
	}
}

func openInBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
