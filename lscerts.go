// Copyright 2023 Andrew Flint arnhemcr@gmail.com
//
// This program is free software: you can redistribute it and/or modify it under the terms of
// the GNU General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

// Lscerts lists certificates for URLs.
// It reads HTTPS URLs from standard input, one URL per line,
// fetches and validates the list of X509 certificates from each URL
// then writes details of the leaf certificate to standard output, one certificate per line.
// Input lines that are blank or comment (starting '#') are ignored.
// Errors about reading or parsing URLs and fetching or validating certificates are 
// written to standard error.
// To be valid, certificates must be signed by a certificate authority (CA)
// trusted by the operating system running lscerts.

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"
)

const exec = "lscerts"
const comment = '#'

// GetHostPort parses str as an HTTPS URL 
// returning hostPort == "<hostName>:<portNumber>" and err == nil.
// If failed to parse a URL, getHostPort returns hostPort == "" and err != nil.
func getHostPort(str string) (hostPort string, err error) {
	url, err := url.Parse(str)
	switch {
	case err != nil:
		return "", fmt.Errorf("%s %w", exec, err)
	case url.Scheme != "https":
		return "", errors.New(fmt.Sprintf("%s \"%s\": url scheme not https", exec, str))
	}

	hostPort = url.Hostname()
	if url.Port() == "" {
		const httpsPort = 443
		hostPort = fmt.Sprintf("%s:%d", hostPort, httpsPort)
	}
	return hostPort, nil
}

// FetchCert fetches and validates X509 certificates from URL https://<hostPort> 
// returning cert == valid leaf certificate and err == nil.
// If failed to fetch or validate the certificates, 
// fetchCert returns cert == nil and err != nil.
func fetchCert(hostPort string) (cert *x509.Certificate, err error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, 
					"tcp", hostPort, nil)
	if err != nil {
		// failed to either connect to hostPort within timeout or validate certificates
		return nil, fmt.Errorf("%s \"%s\": %w", exec, hostPort, err)
	}
	defer conn.Close()

	const leafCertI = 0
	cert = conn.ConnectionState().PeerCertificates[leafCertI]
	return cert, nil
}

// GetToExpiry returns how long from now to expiry time.
func getToExpiry(expiry time.Time) (toExpiry string) {
	const hoursPerDay = 24
	const hoursPerWeek = hoursPerDay * 7
	hours := int64(time.Until(expiry).Hours())
	switch {
	case hours <= 0:
		toExpiry = "expired"
	case hours <= hoursPerDay:
		toExpiry = fmt.Sprintf("%dh", hours)
	case hours <= hoursPerWeek:
		days := int(hours / hoursPerDay)
		toExpiry = fmt.Sprintf("%dd", days)
	default:
		weeks := int(hours / hoursPerWeek)
		toExpiry = fmt.Sprintf("%dw", weeks)
	}
	return toExpiry
}

func main() {
	fmt.Printf("%c expires toExpiry serialNumber URL issuer\n", comment)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if (line == "") || (line[0] == comment) {
			continue // ignore blank or comment line
		}
		hostPort, err := getHostPort(line)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		url := line
		cert, err := fetchCert(hostPort)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}

		// cert is valid X509 leaf certificate for url fetched from hostPort
		expiryTime := cert.NotAfter
		expiryDate := expiryTime.Format(time.DateOnly)
		toExpiry := getToExpiry(expiryTime)
		fmt.Println(expiryDate, toExpiry, cert.SerialNumber, url, cert.Issuer)
	}
	err := scanner.Err()
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("%s: %w", exec, err))
	}
}
