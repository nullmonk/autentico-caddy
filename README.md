# autentico-caddy

Caddy plugin for [autentico](https://github.com/nullmonk/autentico/tree/dev).

## Goals

Take an API token and host and allow roles based authorization for caddy.

* allow server blocks and routing based on user groups (roles)
* advanced mtls cert routing (tie certs to users to groups)
* mtls redirect based on role/failure
* redirect auth to autentico
* auto configure autentico client based on the domains configured

## Installation

The easiest way to use the `autentico` Caddy plugin is by using the pre-built Docker image.

```yaml
services:
  caddy:
    image: ghcr.io/nullmonk/autentico-caddy:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config

volumes:
  caddy_data:
  caddy_config:
```

## Global Configuration

The `autentico` Caddy plugin requires a global app configuration to define the connection to your autentico server(s). This is done in the global options block of your `Caddyfile`.

```caddyfile
{
    # The order directive is required if using autentico outside of a route block
    order autentico before reverse_proxy

    autentico {
        # Configure the 'default' server
        server default {
            url http://autentico:9999
            client_id my_caddy_client
            client_mode pkce
            api_token my_api_token
        }

        # You can define multiple servers and reference them by name
        server other_server {
            url http://autentico-other:9999
            client_id other_client
            client_mode confidential
            client_secret other_secret
            api_token other_token
        }
    }
}
```

### Global Server Options

* `url`: The base URL of the autentico server.
* `client_id`: The OIDC client ID. If it does not exist, the plugin will attempt to create it. (Defaults to `caddy.plugin.autentico`)
* `client_mode`: The OIDC client mode. Valid values are `pkce` (the default) or `confidential`.
* `client_secret`: The OIDC client secret used for token requests (required only if `client_mode` is `confidential`).
* `api_token` (or `API token`): The API token used to authenticate with the autentico API for health checks, group lookups, and dynamic client registration.

## HTTP Handler Directive (`autentico`)

Inside your site blocks, you use the `autentico` directive to protect routes. The directive supports both inline and block syntax.

### Available Options

* `server_name`: Which server configuration to use from the global block. Defaults to `default`.
* `allow groups <group...>`: Restricts access to users belonging to any of the specified groups (roles).
* `callback_path`: Custom path for the OIDC callback. Defaults to `/oauth2/callback`.
* `mtls`: Enables MTLS authentication. Valid values are `optional`, `require`, `both`. (See MTLS Configuration below).
* `cookie_domain`: The domain to set on the authentication cookie.

### Examples

**Inline syntax:**

```caddyfile
example.internal {
    route {
        # Allows users in the 'admin' group. Uses the 'default' server.
        # auto listens on domain + /oauth2/callback
        # sets cookie for domain example.internal
        autentico allow groups admin
    }
    respond "you have logged in" 200
}
```

**Block syntax:**

```caddyfile
other.internal {
    route {
        autentico {
            server_name other_server
            allow groups user admin
            callback_path /customcallback
            cookie_domain other.internal
        }
    }
    respond "you have logged in" 200
}
```

## MTLS Configuration

If you intend to use the `mtls` directive (`mtls optional`, `mtls require`, or `mtls both`), you **must** manually configure your Caddy site block to request client certificates using Caddy's standard `tls` directive.

MTLS Modes:

* `require`: Client certificate is strictly required to pass authentication.
* `optional`: Will authenticate via client certificate if valid, otherwise falls back to OIDC token authentication.
* `both`: Requires both a valid OIDC token and a valid client certificate.

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

## Exported Caddy Variables

After successful authentication, the `autentico` handler sets several variables in the request context that you can use in subsequent directives (like `respond`, `templates`, or `reverse_proxy header_up`).

* `{http.vars.autentico.user}`: The authenticated user's name (either the OIDC preferred username/sub or the MTLS certificate Common Name).
* `{http.vars.autentico.groups}`: A comma-separated list of the user's groups.
* `{http.vars.autentico.auth_method}`: The method used for authentication (`token`, `mtls`, or `both`).
* `{http.vars.autentico.json}`: A JSON object containing all the identity information (subject, user, groups, auth_method).

## Advanced Examples

### Overriding callback and returning JSON Identity

In this example, we configure a `/whoami` route that overrides the callback path just for this route, and responds with the user's identity as JSON.

```caddyfile
auth.wb.localhost {
    # Ask the client for a cert during the TLS handshake, but don't reject
    tls {
        client_auth {
            mode request
        }
    }

    route /whoami* {
        # Override the route for the callback just for this one
        autentico {
            mtls optional
            callback_path /whoami/callback
        }
        respond "{http.vars.autentico.json}" 200
    }

    route {
        reverse_proxy http://autentico:9999
    }
}
```

### Split routing depending on auth method

You can use Caddy's expression matchers against the raw `autentico.auth_method` variable to route traffic differently depending on how the user authenticated.

```caddyfile
example.com {
    tls {
        client_auth {
            mode request
        }
    }

    route /api* {
        autentico {
            mtls optional
        }

        # Matches the raw variable autentico sets via caddyhttp.SetVar - no
        # {} needed here, that's only for placeholder-string values.
        @mtls vars autentico.auth_method mtls
        @token vars autentico.auth_method token both

        handle @mtls {
            respond "cert auth: {http.vars.autentico.user}" 200
        }
        handle @token {
            respond "token auth: {http.vars.autentico.user}" 200
        }
    }
}
```

## Future work

ACME from autentico
