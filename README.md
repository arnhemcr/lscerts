# Lscerts

Lscerts lists certificates in the order they will expire.

It is a command line program that reads a list of HTTPS URLs.
For each URL, lscerts writes details of the leaf certificate or an error.
Administrators can use the list of details to plan future certificate renewals.
And the errors show current issues including invalid certificates and
unresponsive URLs.

Lscerts is free software (see [LICENSE](LICENSE)) written in
[Go](https://en.wikipedia.org/wiki/Go_\(programming_language\)).

## Get started

[Download the latest release of lscerts](https://github.com/arnhemcr/lscerts/releases/latest/).
Assuming the latest release is version 1.0.0 and
a Unix-like command line being used,
follow these steps with `commands`:

1. unpack the release into a directory with `tar xzf lscerts-1.0.0.tar.gz`
2. change into the release directory with `cd lscerts-1.0.0`
3. compile the program with `go build`
4. run the program on a list of test URLs with `./lscerts testURLs`
   expecting various errors followed by a list of valid certificates
   in the order they will expire
5. (optional) install the program with `go install`

## Further information

In the lscerts release directory:

* get help in using the program with `./lscerts -h`
* get the documentation with `go doc`

## Maker

arnhemcr made lscerts
[for the flow of it](https://en.wikipedia.org/wiki/Flow_%28psychology%29).
