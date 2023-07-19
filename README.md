# lscerts

Lscerts checks that certificates on a list of HTTPS URLs are
accessible and valid then lists those certificates in the order they expire.
It is a command line program written in
[Go](https://en.wikipedia.org/wiki/Go_\(programming_language\))
and is free software (see [LICENSE](LICENSE)).

## Get started

[Download the latest release of lscerts](https://github.com/arnhemcr/lscerts/releases/latest/).
Assuming the latest release is version 1.0.0 and
lscerts will be running from a Unix-like command line,
follow these steps and `commands`:

1. unpack the release into a directory with `tar xzf lscerts-1.0.0.tar.gz`
2. change into the release directory with `cd lscerts-1.0.0`
3. compile the program with `go build`
4. run the program on some test URLs with `./lscerts testURLs`
   expecting errors followed by the list of certificates

## Further information

In the lscerts release directory:

* get help in using the program with `./lscerts -h`
* get the documentation with `go doc`

## Maker

arnhemcr made lscerts
[for the flow of it](https://en.wikipedia.org/wiki/Flow_%28psychology%29).
