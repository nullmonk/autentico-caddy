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
	// For now we don't need to provision anything since healthcheck happens in global app
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
		// skip the "autentico" token
		for d.NextBlock(0) {
			// for now we don't parse any subdirectives
			// this is just to allow `autentico` in the Caddyfile
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
