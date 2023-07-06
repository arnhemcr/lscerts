# lscerts

Lscerts lists certificates for URLs.
It reads HTTPS URLs from standard input, one per line.
It fetches and validates the list of X509 certificates from each URL,
then writes details of each leaf certificate sorted by expiry date ascending.
Errors about reading or parsing URLs and fetching or
validating certificates are written to standard error.
Input lines that are blank or comment (starting '#') are ignored.
Lscerts trusts certificates issued by the same set of
certificate authorities (CAs) as the operating system on which it runs.

For example, to list certificates on a couple of URLs from a 
Unix-like command line:

    $ ./lscerts <<+
    https://example.org
    https://wikipedia.org/
    +
    # expires,toExpiry,URL,serialNumber,issuerCN
    2023-09-21,10w,https://wikipedia.org/,42...13,R3
    2024-02-13,31w,https://example.org,16...93,DigiCert TLS RSA SHA256 2020 CA1
    $

Each valid X509 leaf certificate fetched from a URL is listed with
the following details:

 * expires:      date this certificate expires
 * toExpiry:     time until this certificate expires:
                 hours, days, weeks or years rounded down to a whole number
 * URL:          this certificate was fetched from
 * serialNumber: of this certificate 
 * issuerCN:     common name (CN) of the CA that issued this certificate

Lscerts is free software (see [LICENSE](LICENSE)) written in Go.
arnhemcr made lscerts 
[for the flow of it](https://en.wikipedia.org/wiki/Flow_%28psychology%29).

