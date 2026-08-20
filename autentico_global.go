package autentico

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
	httpcaddyfile.RegisterGlobalOption("autentico", parseAutenticoGlobal)
}

// App implements the global Caddy app for Autentico
type App struct {
	APIKey string `json:"api_key,omitempty"`
	Host   string `json:"host,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "apps.autentico",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision implements caddy.Provisioner
func (a *App) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()
	return nil
}

// Start implementing caddy.App
func (a *App) Start() error {
	// Simple health check at caddy start up
	if a.Host != "" {
		// Run in a background goroutine so it doesn't block Caddy's start up
		go func() {
			req, err := http.NewRequest("GET", a.Host+"/healthz", nil)
			if err != nil {
				a.logger.Error("failed to create autentico health check request", zap.Error(err))
				return
			}

			if a.APIKey != "" {
				req.Header.Set("Authorization", "Bearer "+a.APIKey)
			}

			// Use a custom client with a short timeout
			client := &http.Client{
				Timeout: 5 * time.Second,
			}

			resp, err := client.Do(req)
			if err != nil {
				a.logger.Error("autentico health check failed", zap.Error(err))
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				a.logger.Warn("autentico health check returned non-200 status", zap.String("status", resp.Status))
				return
			}

			a.logger.Info("autentico health check successful")
		}()
	}
	return nil
}

// Stop implementing caddy.App
func (a *App) Stop() error {
	return nil
}

// parseAutenticoGlobal parses the global autentico directive
func parseAutenticoGlobal(d *caddyfile.Dispenser, existingVal any) (any, error) {
	app := new(App)
	if existingVal != nil {
		app = existingVal.(*App)
	}

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "api_key":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.APIKey = d.Val()
			case "host":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				app.Host = d.Val()
			default:
				return nil, d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}

	appJSON, err := json.Marshal(app)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal autentico config: %v", err)
	}

	return httpcaddyfile.App{
		Name:  "autentico",
		Value: json.RawMessage(appJSON),
	}, nil
}

// Interface guards
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
