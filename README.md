# lscerts

Lscerts lists certificates for URLs.
It reads HTTPS URLs from standard input, one per line, 
fetches and validates the list of X509 certificates from each URL
then writes details of the leaf certificate to standard output.
Errors about reading or parsing URLs and fetching or validating certificates are
written to standard error.
Input lines that are blank or comment (starting '#') are ignored.
Lscerts trusts certificates issued by the same set of certificate authorities (CAs)
as the operating system on which it is running.

For example, to list certificates on a couple of URLs from a Unix-like command line:

    $ ./lscerts <<+
    https://example.org
    https://wikipedia.org/
    +
    # expires toExpiry URL serialNumber issuerCA
    2024-02-13 33w https://example.com 16...93 CN=DigiCert TLS RSA SHA256 2020 CA1, ...
    2023-07-23 3w https://wikipedia.org/ 26...53 CN=R3, ...
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

