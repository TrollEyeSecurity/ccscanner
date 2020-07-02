# command center scanner #
*command center scanner* is a client application designed to perform tasks during penetration tests and security audits using
Docker containers.

## Build the binary files ##
`make clean && make build`


## Linking to the Centralized Scan Manager ##

`cclink-$(VERSION) --url=BASEURL --token=LINKING_TOKEN`