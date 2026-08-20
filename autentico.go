package autentico

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func init() {
	caddy.RegisterModule(Autentico{})
	httpcaddyfile.RegisterHandlerDirective("autentico", parseCaddyfile)
}

// Autentico implements an HTTP handler that validates requests with an Autentico service.
type Autentico struct {
	ServerName    string   `json:"server_name,omitempty"`
	AllowedGroups []string `json:"allowed_groups,omitempty"`
	CallbackPath  string   `json:"callback_path,omitempty"`

	app    *App
	logger *zap.Logger
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
	if a.ServerName == "" {
		a.ServerName = "default"
	}
	if a.CallbackPath == "" {
		a.CallbackPath = "/oauth2/callback"
	}
	a.logger = ctx.Logger()

	app, err := ctx.App("autentico")
	if err != nil {
		return fmt.Errorf("getting autentico app: %v", err)
	}
	a.app = app.(*App)

	return nil
}

// Validate implements caddy.Validator.
func (a *Autentico) Validate() error {
	return nil
}

// generateState generates a random state string for OAuth2 flow
func generateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (a Autentico) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	callbackURL := ""
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if r.Header.Get("X-Forwarded-Host") != "" {
		host = r.Header.Get("X-Forwarded-Host")
	}
	callbackURL = fmt.Sprintf("%s://%s%s", scheme, host, a.CallbackPath)

	state, err := a.app.GetServerState(r.Context(), a.ServerName)
	if err != nil {
		a.logger.Error("failed to get server state", zap.Error(err))
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// Clone the config and set the dynamic RedirectURL
	oauthConfig := state.Config
	oauthConfig.RedirectURL = callbackURL

	// Handle OAuth2 callback
	if r.URL.Path == a.CallbackPath {
		return a.handleCallback(w, r, state, oauthConfig)
	}

	// Extract token
	token := ""
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else if cookie, err := r.Cookie("autentico_token"); err == nil {
		token = cookie.Value
	}

	// If no token, start OAuth2 flow (unless API client, then return 401)
	if token == "" {
		if !strings.Contains(r.Header.Get("Accept"), "text/html") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="autentico"`)
			return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("unauthorized"))
		}

		oauthState := generateState()
		// Store the original URL to redirect back to after login
		originalURL := r.URL.String()
		http.SetCookie(w, &http.Cookie{
			Name:     "autentico_oauth_state",
			Value:    fmt.Sprintf("%s|%s", oauthState, originalURL),
			Path:     "/",
			HttpOnly: true,
			Secure:   scheme == "https",
			MaxAge:   300,
		})

		url := oauthConfig.AuthCodeURL(oauthState)
		http.Redirect(w, r, url, http.StatusFound)
		return nil
	}

	// Validate token and check groups
	// 1. Check cache first
	groups, ok := a.app.GetCachedGroups(token)
	if !ok {
		// 2. Fetch UserInfo from OIDC provider
		oauth2Token := &oauth2.Token{
			AccessToken: token,
			TokenType:   "Bearer",
		}
		userInfo, err := state.Provider.UserInfo(r.Context(), oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			a.logger.Warn("failed to fetch userinfo", zap.Error(err))
			// Token might be invalid/expired, clear cookie if it came from one
			http.SetCookie(w, &http.Cookie{
				Name:     "autentico_token",
				Value:    "",
				Path:     "/",
				Expires:  time.Unix(0, 0),
				HttpOnly: true,
			})
			return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("invalid token"))
		}

		var claims struct {
			Groups []string `json:"groups"`
		}
		if err := userInfo.Claims(&claims); err != nil {
			a.logger.Error("failed to unmarshal userinfo claims", zap.Error(err))
			return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("invalid userinfo response"))
		}
		groups = claims.Groups

		// Cache it
		a.app.SetCachedGroups(token, groups, 5*time.Minute)
	}

	// 3. Check if user's groups match allowed groups
	if len(a.AllowedGroups) > 0 {
		allowed := false
		for _, userGroup := range groups {
			for _, allowedGroup := range a.AllowedGroups {
				if userGroup == allowedGroup {
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}

		if !allowed {
			return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("forbidden"))
		}
	}

	return next.ServeHTTP(w, r)
}

func (a *Autentico) handleCallback(w http.ResponseWriter, r *http.Request, state *ServerState, oauthConfig oauth2.Config) error {
	ctx := context.Background()

	cookieState, err := r.Cookie("autentico_oauth_state")
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("missing state cookie"))
	}

	parts := strings.SplitN(cookieState.Value, "|", 2)
	if len(parts) != 2 {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid state cookie format"))
	}
	expectedState, originalURL := parts[0], parts[1]

	if r.URL.Query().Get("state") != expectedState {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid oauth state"))
	}

	oauth2Token, err := oauthConfig.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("failed to exchange token: %v", err))
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("no id_token field in oauth2 token"))
	}

	// Verify ID Token to make sure it's valid
	_, err = state.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("failed to verify ID token: %v", err))
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "autentico_oauth_state",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})

	// Set auth cookie
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}

	maxAge := 3600 // default 1 hour if expiry is not present
	if !oauth2Token.Expiry.IsZero() {
		maxAge = int(time.Until(oauth2Token.Expiry).Seconds())
	}
	if maxAge < 0 {
		maxAge = 3600 // fallback if already expired (shouldn't happen on fresh token)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "autentico_token",
		Value:    oauth2Token.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   scheme == "https",
		MaxAge:   maxAge,
	})

	http.Redirect(w, r, originalURL, http.StatusFound)
	return nil
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
			case "server_name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.ServerName = d.Val()
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
