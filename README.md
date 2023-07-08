# lscerts

Lscerts lists certificates for URLs.

Lscerts reads HTTPS URLs from standard input, one per line.
It fetches and validates the list of X.509 certificates from each URL,
then writes details about each leaf certificate sorted by expiry date ascending.
Errors about reading or parsing URLs and fetching or
validating certificates are written to standard error.
Input lines that are blank or comment (starting '#') are ignored.
Lscerts trusts certificates issued by the same set of
certificate authorities (CAs) as the operating system on which it runs.

Lscerts is free software (see [LICENSE](LICENSE)), written in Go and hosted at
[https://github.com/arnhemcr/lscerts](https://github.com/arnhemcr/lscerts).
arnhemcr made lscerts
[for the flow of it](https://en.wikipedia.org/wiki/Flow_%28psychology%29).

## Example

Run ``./lscerts <testURLs`` for some example errors and certificates:

    $ ./lscerts <testURLs
    lscerts "expired.badssl.com:443": tls: failed to verify certificate: ...
    ...
    lscerts "http://example.com": url scheme not https
    # expires,toExpiry,URL,serialNumber,issuerCN
    2023-07-21,1w,https://test-ev-rsa.ssl.com,1206...1585,SSL.com ...
    ...
    2023-09-05,8w,https://test-ev-ecc.ssl.com:443,1005...2992,SSL.com ...
    $

For each certificate, the following details are listed:

 * ``expires``:      date this certificate expires
 * ``toExpiry``:     time until this certificate expires:
                     hours, days, weeks or years rounded down to a whole number
 * ``URL``:          this certificate was fetched from
 * ``serialNumber``: of this certificate
 * ``issuerCN``:     common name (CN) of the CA that issued this certificate
