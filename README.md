# lscerts

Lscerts lists certificates for URLs.
It reads HTTPS URLs from standard input, one per line.
Then it fetches and validates the list of X509 certificates from each URL,
and writes details of each leaf certificate
sorted by expiry date ascending.
Errors about reading or parsing URLs and fetching or
validating certificates are written to standard error.
Input lines that are blank or comment (starting '#') are ignored.
Lscerts trusts certificates issued by the same set of
certificate authorities as the operating system on which it runs.

For example, to list certificates on a couple of URLs from a Unix-like command line:

    $ ./lscerts <<+
    https://example.org
    https://wikipedia.org/
    +
    # expires,toExpiry,URL,serialNumber,issuerCN
    2023-09-21,10w,https://wikipedia.org/,428452211737671437765269124768876865453113,R3
    2024-02-13,31w,https://example.org,16115816404043435608139631424403370993,DigiCert TLS RSA SHA256 2020 CA1
    $

Output fields are:

 * expires: date this certificate expires (YYYY-MM-DD format)
 * toExpiry: hours, days, weeks or years until this certificate expires,
             rounded down to the nearest whole number so usually an underestimate
 * URL
 * serialNumber: of this certificate 
 * issuerCA: certificate authority (CA) that issued this certificate

Lscerts is free software (see [LICENSE](LICENSE)) written in Go.
arnhemcr made lscerts [for the flow of it](https://en.wikipedia.org/wiki/Flow_%28psychology%29).

