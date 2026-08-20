package autentico

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Autentico{})
	httpcaddyfile.RegisterHandlerDirective("autentico", parseCaddyfile)
}

// Autentico implements an HTTP handler that validates requests with an Autentico service.
type Autentico struct {
	AllowedGroups []string `json:"allowed_groups,omitempty"`
	CallbackPath  string   `json:"callback_path,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Autentico) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.autentico",
		New: func() caddy.Module { return new(Autentico) },
	}
}

// Provision implements caddy.Provisioner.
func (a *Autentico) Provision(ctx caddy.Context) error {
	if a.CallbackPath == "" {
		a.CallbackPath = "/oauth2/callback"
	}
	return nil
}

// Validate implements caddy.Validator.
func (a *Autentico) Validate() error {
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (a Autentico) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// For now this is just a stub that passes the request through
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (a *Autentico) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// allow inline arguments like "allow groups admin"
		args := d.RemainingArgs()
		if len(args) > 0 {
			if args[0] == "allow" {
				if len(args) > 1 && args[1] == "groups" {
					a.AllowedGroups = append(a.AllowedGroups, args[2:]...)
				} else {
					return d.Err("expected 'groups' after 'allow'")
				}
			} else {
				return d.Errf("unrecognized inline argument: %s", args[0])
			}
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "allow":
				if !d.NextArg() || d.Val() != "groups" {
					return d.Err("expected 'groups' after 'allow'")
				}
				a.AllowedGroups = append(a.AllowedGroups, d.RemainingArgs()...)
			case "callback_path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.CallbackPath = d.Val()
			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var a Autentico
	err := a.UnmarshalCaddyfile(h.Dispenser)
	return a, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Autentico)(nil)
	_ caddy.Validator             = (*Autentico)(nil)
	_ caddyhttp.MiddlewareHandler = (*Autentico)(nil)
	_ caddyfile.Unmarshaler       = (*Autentico)(nil)
)
