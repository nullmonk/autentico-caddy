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

// ServerConfig defines the configuration for an autentico server
type ServerConfig struct {
	URL          string `json:"url,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	APIToken     string `json:"api_token,omitempty"`
}

// App implements the global Caddy app for Autentico
type App struct {
	Servers map[string]ServerConfig `json:"servers,omitempty"`

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
	for serverName, serverConfig := range a.Servers {
		if serverConfig.URL != "" {
			name := serverName
			config := serverConfig
			// Run in a background goroutine so it doesn't block Caddy's start up
			go func() {
				req, err := http.NewRequest("GET", config.URL+"/healthz", nil)
				if err != nil {
					a.logger.Error("failed to create autentico health check request", zap.Error(err), zap.String("server", name))
					return
				}

				if config.APIToken != "" {
					req.Header.Set("Authorization", "Bearer "+config.APIToken)
				}

				// Use a custom client with a short timeout
				client := &http.Client{
					Timeout: 5 * time.Second,
				}

				resp, err := client.Do(req)
				if err != nil {
					a.logger.Error("autentico health check failed", zap.Error(err), zap.String("server", name))
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					a.logger.Warn("autentico health check returned non-200 status", zap.String("status", resp.Status), zap.String("server", name))
					return
				}

				a.logger.Info("autentico health check successful", zap.String("server", name))
			}()
		}
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

	if app.Servers == nil {
		app.Servers = make(map[string]ServerConfig)
	}

	for d.Next() {
		for d.NextBlock(0) {
			if d.Val() != "server" {
				return nil, d.Errf("unrecognized subdirective: %s, expected 'server'", d.Val())
			}

			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			serverName := d.Val()

			var sc ServerConfig
			for d.NextBlock(1) {
				switch d.Val() {
				case "url":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					sc.URL = d.Val()
				case "client_id":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					sc.ClientID = d.Val()
				case "client_secret":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					sc.ClientSecret = d.Val()
				case "api_token", "API":
					if d.Val() == "API" {
						if !d.NextArg() || d.Val() != "token" {
							return nil, d.Err("expected 'token' after 'API'")
						}
					}
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					sc.APIToken = d.Val()
				default:
					return nil, d.Errf("unrecognized server option: %s", d.Val())
				}
			}
			app.Servers[serverName] = sc
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
