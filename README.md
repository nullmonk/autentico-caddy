# autentico-caddy
Caddy plugin for [autentico](https://github.com/nullmonk/autentico/tree/dev).


## Goals
Take an API token and host and allow roles based authorization for caddy.

* allow server blocks and routing based on user roles
* advanced mtls cert routing (tie certs to users to roles)
* mtls redirect based on role/failure
* redirect auth to autentico
* auto configure autentico client based on the domains configured

## Future work
ACME from autentico
