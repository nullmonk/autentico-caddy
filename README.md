# autentico-caddy
Caddy plugin for [autentico](https://github.com/nullmonk/autentico/tree/dev).


## Goals
Take an API token and host and allow roles based authorization for caddy.

* allow server blocks and routing based on user roles
* advanced mtls cert routing (tie certs to users to roles)
* mtls redirect based on role/failure
* redirect auth to autentico
* auto configure autentico client based on the domains configured

## Important: MTLS Configuration

If you intend to use the `mtls` directive (`mtls optional`, `mtls require`, or `mtls both`), you **must** manually configure your Caddy site block to request client certificates using Caddy's standard `tls` directive.

Example:
```caddyfile
example.com {
    tls {
        client_auth {
            mode request
        }
    }

    route /audit/* {
        autentico {
            allow groups admin
            mtls require
        }
    }
}
```

## Future work
ACME from autentico
