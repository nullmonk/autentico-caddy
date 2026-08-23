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
* `api_token`: The API token used to authenticate with the autentico API for health checks, group lookups, and dynamic client registration.
* `scopes`: The OIDC scopes Caddy requests at login and requires the client to have registered on ACO. Defaults to `openid profile groups` (`email` is not requested by default - add it explicitly if you need it, e.g. `scopes openid profile email groups`).

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

After successful authentication, the `autentico` handler sets several placeholders that you can use in subsequent directives (like `respond`, `templates`, `reverse_proxy header_up`, or matcher expressions).

* `{http.auth.autentico.user}`: The authenticated user's name (either the OIDC preferred username/sub or the MTLS certificate Common Name).
* `{http.auth.autentico.groups}`: A comma-separated list of the user's groups.
* `{http.auth.autentico.method}`: The method used for authentication (`token`, `mtls`, or `both`).
* `{http.auth.autentico.json}`: A JSON object containing all the identity information (subject, user, groups, method, external).
* `{http.auth.autentico.external}`: A boolean string (`"true"` or `"false"`) indicating whether the request was authenticated via an external token source.

## External Token Configuration

The `external` directive lets `autentico` validate tokens managed by an external application, without intercepting requests to redirect to the OAuth flow or enforcing internal policies. This is useful for passing through externally-managed authentication checks for upstream routing.

When `external` is active, the plugin simply acts as an identity extractor and populates the Caddy variables.

### External Options

* `external cookie <cookie_name>`: Extracts the token from the specified cookie (or the Authorization header).
* `external bearer`: Extracts the token exclusively from the Authorization header.

### Examples

**Block syntax:**

```caddyfile
books.localhost {
    autentico {
        external cookie openid_id_token
    }
    reverse_proxy http://audiobookshelf
}
```

**Inline syntax:**

```caddyfile
books.localhost {
    autentico external cookie openid_id_token
    reverse_proxy http://audiobookshelf
}
```

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
        respond "{http.auth.autentico.json}" 200
    }

    route {
        reverse_proxy http://autentico:9999
    }
}
```

### Split routing depending on auth method

You can use Caddy's `expression` matcher against the `{http.auth.autentico.method}` placeholder to route traffic differently depending on how the user authenticated.

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

        @mtls expression {http.auth.autentico.method} == "mtls"
        @token expression {http.auth.autentico.method} in ["token", "both"]

        handle @mtls {
            respond "cert auth: {http.auth.autentico.user}" 200
        }
        handle @token {
            respond "token auth: {http.auth.autentico.user}" 200
        }
    }
}
```

## Future work

ACME from autentico
