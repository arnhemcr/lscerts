// Copyright 2023 Andrew Flint arnhemcr@gmail.com
//
// This program is free software: you can redistribute it and/or modify it 
// under the terms of the GNU General Public License as published by the 
// Free Software Foundation, either version 3 of the License, 
// or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, 
// but WITHOUT ANY WARRANTY;  without even the implied warranty of 
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License 
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Lscerts lists certificates for URLs.
// It reads HTTPS URLs from standard input, one per line.
// Then it fetches and validates the list of X509 certificates from each URL,
// and writes details of each leaf certificate 
// sorted by expiry date ascending.
// Errors about reading or parsing URLs and fetching or 
// validating certificates are written to standard error.
// Input lines that are blank or comment (starting '#') are ignored.
// Lscerts trusts certificates issued by the same set of 
// certificate authorities as the operating system on which it runs.

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const exec = "lscerts"
const comment = '#'
const fetchTimeout = 5 // for certificates in seconds

// GetHostPort parses str as an HTTPS URL
// returning hostPort == "<hostName>:<portNumber>" and err == nil.
// If failed to parse a URL, getHostPort returns hostPort == "" and err != nil.
func getHostPort(str string) (hostPort string, err error) {
	url, err := url.Parse(str)
	switch {
	case err != nil:
		return "", fmt.Errorf("%s %w", exec, err)
	case url.Scheme != "https":
		return "", errors.New(fmt.Sprintf(
			"%s \"%s\": url scheme not https", exec, str))
	}

	hostPort = url.Host
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
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: fetchTimeout * time.Second}, 
		"tcp", hostPort, nil)
	if err != nil {
		// failed to connect to hostPort in timeout 
		// or validate certificates
		return nil, fmt.Errorf("%s \"%s\": %w", exec, hostPort, err)
	}
	defer conn.Close()

	const leafCertI = 0
	cert = conn.ConnectionState().PeerCertificates[leafCertI]
	return cert, nil
}

// GetToExpiry returns how long from now to expiry
// rounded down to an integer number of hours, weeks or years.
func getToExpiry(expiry time.Time) (toExpiry string) {
	const hoursPerDay = 24
	const hoursPerWeek = hoursPerDay * 7
	const hoursPerYear = hoursPerWeek * 52
	hours := int64(time.Until(expiry).Hours())
	switch {
	case hours < 0:
		toExpiry = "expired"
	case hours < 1:
		toExpiry = "<1h"
	case hours <= hoursPerDay:
		toExpiry = fmt.Sprintf("%dh", hours)
	case hours <= hoursPerWeek:
		days := int(hours / hoursPerDay)
		toExpiry = fmt.Sprintf("%dd", days)
	case hours <= hoursPerYear:
		weeks := int(hours / hoursPerWeek)
		toExpiry = fmt.Sprintf("%dw", weeks)
	default:
		years := int(hours / hoursPerYear)
		toExpiry = fmt.Sprintf("%dy", years)
	}
	return toExpiry
}

func main() {
	var noHeader bool
	flag.BoolVar(&noHeader, "n", false, "no output header")
	flag.Parse()

	details := []string{}
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
		toExpiry := getToExpiry(expiryTime)
		fields := []string{expiryTime.Format(time.DateOnly), toExpiry, url, 
			cert.SerialNumber.String(), cert.Issuer.String()}
		record :=  strings.Join(fields, " ")
		details = append(details, record)
	}
	err := scanner.Err()
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("%s: %w", exec, err))
	}

	if noHeader == false {
		fmt.Printf("%cexpires toExpiry URL serialNumber issuerCA\n", 
			comment)
	}
	sort.Strings(details)
	for _, detail := range details {
		fmt.Println(detail)
	}
}
