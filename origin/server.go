// Package origin configures an http.Server to only accept legitimate TLS requests from Cloudflare.
//
// The server will only accept SNI requests matching one of the provided certificates.
// It can also be configured to only accept requests from Cloudflare IP ranges,
// and to authenticate origin pulls.
//
// If the above checks fail, TLS handshake fails without leaking server certificates.
//
// See:
//   https://www.cloudflare.com/ips/
//   https://origin-pull.cloudflare.com/
//
// Usage:
//	func main() {
//		server, err := origin.NewServer("cert.pem", "key.pem", "origin-pull-ca.pem", true)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
//			io.WriteString(w, "Hello, TLS!\n")
//		})
//		log.Fatal(server.ListenAndServeTLS("", ""))
//	}
package origin

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	ips     []*net.IPNet
	mutex   sync.Mutex
	refresh time.Time
)

// NewServer creates a Cloudflare origin http.Server.
//
// Filenames containing a certificate and matching private key for the server must be provided.
// The filename to the origin pull CA certificate is optional.
func NewServer(certFile, keyFile, pullCAFile string, filterIPs bool) (*http.Server, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	var pool *x509.CertPool

	if pullCAFile != "" {
		pull, err := ioutil.ReadFile(pullCAFile)
		if err != nil {
			return nil, err
		}

		pool = x509.NewCertPool()
		pool.AppendCertsFromPEM(pull)
	}

	return NewServerWithCerts(filterIPs, pool, cert), nil
}

// NewServerWithCerts creates a Cloudflare origin http.Server from loaded certificates.
//
// At least one server certificate must be provided.
// The origin pull CA certificate is optional.
func NewServerWithCerts(filterIPs bool, pullCA *x509.CertPool, cert ...tls.Certificate) *http.Server {
	config := &tls.Config{MinVersion: tls.VersionTLS13}

	// validate client IP
	if filterIPs {
		config.GetCertificate = checkIP
	}

	// validate client certificate against origin pull certificate
	if pullCA != nil {
		config.ClientCAs = pullCA
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	// prepend invalid certificate so we don't leak first certificate for no/unknown SNI
	invalidCert := tls.Certificate{Certificate: [][]byte{[]byte{}}}
	config.Certificates = append([]tls.Certificate{invalidCert}, cert...)
	config.BuildNameToCertificate()

	// default port
	return &http.Server{
		TLSConfig: config,
		Addr:      ":https",
	}
}

func checkIP(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var ip net.IP
	switch addr := info.Conn.RemoteAddr().(type) {
	case *net.TCPAddr:
		ip = addr.IP
	case *net.UDPAddr:
		ip = addr.IP
	case *net.IPAddr:
		ip = addr.IP
	}

	for _, ipnet := range ips {
		if ipnet.Contains(ip) {
			return nil, nil
		}
	}
	// update on failure: maybe it's a new IP?
	if updateIPs() {
		for _, ipnet := range ips {
			if ipnet.Contains(ip) {
				return nil, nil
			}
		}
	}

	return nil, errors.New("not a Cloudflare IP")
}

func updateIPs() bool {
	// shared state
	mutex.Lock()
	defer mutex.Unlock()

	// update at most once an hour, even if it fails
	if time.Since(refresh) > time.Hour {
		refresh = time.Now()

		ipv4, err := loadIPs("https://www.cloudflare.com/ips-v4")
		if err != nil {
			if ips == nil {
				// fatal because we've never done it
				log.Fatalln("failed to fecth Cloudflare IPv4s:", err)
			}
			log.Println("failed to update Cloudflare IPv4s:", err)
			return false
		}
		ipv6, err := loadIPs("https://www.cloudflare.com/ips-v6")
		if err != nil {
			if ips == nil {
				// fatal because we've never done it
				log.Fatalln("failed to fecth Cloudflare IPv6s:", err)
			}
			log.Println("failed to update Cloudflare IPv6s:", err)
			return false
		}
		ips = append(ipv4, ipv6...)
		return true
	}
	return false
}

func loadIPs(url string) ([]*net.IPNet, error) {
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, errors.New(http.StatusText(res.StatusCode))
	}

	var ips []*net.IPNet
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		_, n, err := net.ParseCIDR(scanner.Text())
		if err != nil {
			return nil, err
		}
		ips = append(ips, n)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ips, err
}
