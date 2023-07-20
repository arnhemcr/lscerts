/*
Copyright 2023 Andrew Flint arnhemcr@gmail.com

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License,
or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY;  without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

/*
Lscerts lists certificates in the order they will expire.

It is a command line program that reads a list of HTTPS URLs
from file or standard input, one URL per line.
Lines that are blank or comment, starting "#", are ignored.
For each URL, lscerts fetches and validates the list of
X.509 certificates then writes the following details for the leaf certificate:

  - expires:      expiry date of this certificate
  - toExpiry:     time until this certificate expires:
    hours, days, weeks or years rounded down to a whole number
  - URL:          this certificate was fetched from
  - serialNumber: of this certificate
  - issuerCN:     common name (CN) of the CA that issued this certificate

Certificate details are sorted by expiry date ascending.
Failures to read or parse URLs and fetch or validate certificates
are written to standard error.
Lscerts trusts certificates issued by the same set of
certificate authorities (CAs) as the operating system on which it runs.

For help in using the program, run "lscerts -h".
*/
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

const comment = '#' // start of input comment and output header lines

const noHeaderFlag = "n"
const noHeaderText = "do not write header for certificate details"

var noHeader bool
var input *os.File // stream to read URLs from

// Init processes the command line setting input and noHeader.
// If a flag is undefined, help was requested,
// there are too many arguments or the file argument cannot be read,
// Init will exit lscerts.
func init() {
	const helpFlag = "h"
	const helpText = "write this help text then exit"
	var help bool
	flag.BoolVar(&help, helpFlag, false, helpText)
	flag.BoolVar(&noHeader, noHeaderFlag, false, noHeaderText)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nUsage: %s [-%s][-%s] [file]\n",
			os.Args[0], helpFlag, noHeaderFlag)
		fmt.Fprintln(os.Stderr, `
Lscerts lists certificates in the order they will expire.
It reads a list of HTTPS URLs from file or standard input, one URL per line.
For each URL, it writes details of the leaf certificate or an error.
			`)
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr)
	}
	flag.Parse()

	if help {
		flag.Usage()
		os.Exit(0)
	}
	switch flag.NArg() {
	case 0:
		input = os.Stdin
	case 1:
		var err error
		input, err = os.Open(flag.Arg(0))
		if err != nil {
			fmt.Fprintln(os.Stderr,
				fmt.Errorf("%s: %w", os.Args[0], err))
			os.Exit(3)
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
}

// GetHostPort parses str as an HTTPS URL
// returning hostPort == "<hostName>:<portNumber>" and err == nil.
// If failed to parse a URL, getHostPort returns hostPort == "" and err != nil.
func getHostPort(str string) (hostPort string, err error) {
	url, err := url.Parse(str)
	switch {
	case err != nil:
		return "", fmt.Errorf("%s %w", os.Args[0], err)
	case url.Scheme != "https":
		return "", errors.New(fmt.Sprintf(
			"%s \"%s\": url scheme not https", os.Args[0], str))
	}

	hostPort = url.Host
	if url.Port() == "" {
		const httpsPort = 443
		hostPort = fmt.Sprintf("%s:%d", hostPort, httpsPort)
	}
	return hostPort, nil
}

// FetchCert fetches and validates certificates from URL https://<hostPort>
// returning cert == valid leaf certificate and err == nil.
// If failed to fetch or validate the certificates,
// fetchCert returns cert == nil and err != nil.
func fetchCert(hostPort string) (cert *x509.Certificate, err error) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp", hostPort, nil)
	if err != nil {
		// failed to connect to hostPort in timeout
		// or validate certificates
		return nil,
			fmt.Errorf("%s \"%s\": %w", os.Args[0], hostPort, err)
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
		// cannot get here, 
		// expired certificates are invalid so listed as errors
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
	var err error
	details := []string{}
	scanner := bufio.NewScanner(input)
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

		// cert is valid leaf certificate for url fetched from hostPort
		expiryTime := cert.NotAfter
		toExpiry := getToExpiry(expiryTime)
		fields := []string{expiryTime.Format(time.DateOnly),
			toExpiry, url,
			cert.SerialNumber.String(),
			cert.Issuer.CommonName}
		record := strings.Join(fields, ",")
		details = append(details, record)
	}
	err = scanner.Err()
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("%s: %w", os.Args[0], err))
		os.Exit(4)
	}

	if (noHeader == false) && (1 <= len(details)) {
		fmt.Printf("%c expires,toExpiry,URL,serialNumber,issuerCN\n",
			comment)
	}
	sort.Strings(details)
	for _, detail := range details {
		fmt.Println(detail)
	}
}
