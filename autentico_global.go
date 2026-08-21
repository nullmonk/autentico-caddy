package autentico

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func init() {
	caddy.RegisterModule(App{})
	httpcaddyfile.RegisterGlobalOption("autentico", parseAutenticoGlobal)
}

// ServerState holds runtime state for an autentico server
type ServerState struct {
	Provider *oidc.Provider
	Config   oauth2.Config
	Verifier *oidc.IDTokenVerifier
	CertPool *x509.CertPool
	mu       sync.Mutex
  CertsInstalled bool
	Client   *http.Client

	RedirectURIs []string
}

// ServerConfig defines the configuration for an autentico server
type ServerConfig struct {
	URL           string   `json:"url,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	ClientSecret  string   `json:"client_secret,omitempty"`
	APIToken      string   `json:"api_token,omitempty"`
	Features      []string `json:"features,omitempty"`
	InsecureHTTPS bool     `json:"insecure_https,omitempty"`
}

// TokenCacheEntry stores a cached group resolution
type TokenCacheEntry struct {
	Groups    []string
	ExpiresAt time.Time
}

// App implements the global Caddy app for Autentico
type App struct {
	Servers map[string]ServerConfig `json:"servers,omitempty"`

	ctx          caddy.Context
	logger       *zap.Logger
	serverStates map[string]*ServerState
	tokenCache   sync.Map // Token (string) -> *TokenCacheEntry
	mu           sync.Mutex
}

// RegisterFeature adds a feature to the server config if it doesn't already exist
func (a *App) RegisterFeature(serverName, feature string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	config, ok := a.Servers[serverName]
	if !ok {
		return
	}

	for _, f := range config.Features {
		if f == feature {
			return
		}
	}

	config.Features = append(config.Features, feature)
	a.Servers[serverName] = config
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "autentico",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision implements caddy.Provisioner
func (a *App) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.logger = ctx.Logger()
	a.serverStates = make(map[string]*ServerState)
	for name, config := range a.Servers {
		client := &http.Client{
			Timeout: 5 * time.Second,
		}

		if config.InsecureHTTPS {
			client.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}

		a.serverStates[name] = &ServerState{
			Client: client,
		}
	}
	return nil
}

// GetServerState returns the OIDC configuration and provider for the server, initializing it if necessary
func (a *App) GetServerState(ctx context.Context, serverName string) (*ServerState, error) {
	state, ok := a.serverStates[serverName]
	if !ok {
		return nil, fmt.Errorf("server configuration %q not found", serverName)
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	if state.Provider != nil {
		return state, nil
	}

	config, ok := a.Servers[serverName]
	if !ok {
		return nil, fmt.Errorf("server configuration %q not found", serverName)
	}

	// We use InsecureIssuerURLContext to bypass the issuer validation mismatch.
	// Since the server URL (config.URL) may differ from the `issuer` returned in the
	// discovery document (e.g. `http://autentico` vs `http://localhost`), we must
	// fetch the expected issuer ourselves first to inform go-oidc of what to accept.
	wellKnown := strings.TrimSuffix(config.URL, "/") + "/.well-known/openid-configuration"

	reqCtx := context.WithValue(ctx, oauth2.HTTPClient, state.Client)
	reqCtx = oidc.ClientContext(reqCtx, state.Client)

	req, err := http.NewRequestWithContext(reqCtx, "GET", wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := state.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery document returned status: %d", resp.StatusCode)
	}

	var p struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}

	providerCtx := oidc.InsecureIssuerURLContext(reqCtx, p.Issuer)
	provider, err := oidc.NewProvider(providerCtx, config.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OIDC provider: %w", err)
	}

	state.Provider = provider
	state.Config = oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}
	state.Verifier = provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	return state, nil
}

// GetCachedGroups retrieves groups from the cache if not expired
func (a *App) GetCachedGroups(token string) ([]string, bool) {
	if val, ok := a.tokenCache.Load(token); ok {
		entry := val.(*TokenCacheEntry)
		if time.Now().Before(entry.ExpiresAt) {
			return entry.Groups, true
		}
		a.tokenCache.Delete(token)
	}
	return nil, false
}

// SetCachedGroups sets groups in the cache with a TTL
func (a *App) SetCachedGroups(token string, groups []string, ttl time.Duration) {
	a.tokenCache.Store(token, &TokenCacheEntry{
		Groups:    groups,
		ExpiresAt: time.Now().Add(ttl),
	})
}

// LookupUserGroups fetches user groups from the Autentico admin API
func (a *App) LookupUserGroups(ctx context.Context, serverName, username string) ([]string, error) {
	config, ok := a.Servers[serverName]
	if !ok {
		return nil, fmt.Errorf("server configuration %q not found", serverName)
	}
	state, ok := a.serverStates[serverName]
	if !ok {
		return nil, fmt.Errorf("server state %q not found", serverName)
	}
	if config.APIToken == "" {
		return nil, fmt.Errorf("APIToken is required for MTLS group resolution")
	}

	payload := map[string]interface{}{
		"usernames": []string{username},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal lookup request: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", config.URL+"/admin/api/users/lookup", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create lookup request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+config.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := state.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lookup request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lookup request returned status %s", resp.Status)
	}

	var result struct {
		Data struct {
			Items []struct {
				Username string   `json:"username"`
				Groups   []string `json:"groups"`
			} `json:"items"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode lookup response: %v", err)
	}

	if len(result.Data.Items) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	return result.Data.Items[0].Groups, nil
}

// RegisterRedirectURI dynamically registers a new callback URL for the OIDC client
func (a *App) RegisterRedirectURI(ctx context.Context, serverName, callbackURL string) error {
	config, ok := a.Servers[serverName]
	if !ok {
		return fmt.Errorf("server configuration %q not found", serverName)
	}

	state, ok := a.serverStates[serverName]
	if !ok {
		return fmt.Errorf("server state %q not found", serverName)
	}

	clientID := config.ClientID
	if clientID == "" {
		clientID = "caddy.plugin.autentico"
	}

	state.mu.Lock()
	// Double-check under lock
	for _, u := range state.RedirectURIs {
		if u == callbackURL {
			state.mu.Unlock()
			return nil
		}
	}

	// Optimistically append to cache immediately so concurrent requests don't all trigger this
	state.RedirectURIs = append(state.RedirectURIs, callbackURL)
	currentURIs := make([]string, len(state.RedirectURIs))
	copy(currentURIs, state.RedirectURIs)
	state.mu.Unlock()

	payload := map[string]interface{}{
		"redirect_uris": currentURIs,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal redirect_uris update: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", config.URL+"/admin/api/clients/"+clientID, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create client update request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+config.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := state.Client.Do(req)
	if err != nil {
		return fmt.Errorf("client update request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("client update request returned status %s", resp.Status)
	}

	a.logger.Info("dynamically registered new redirect URI", zap.String("server", serverName), zap.String("uri", callbackURL))
	return nil
}

// Start implementing caddy.App
func (a *App) Start() error {
	// Log enabled features for each server at debug level
	for serverName, serverConfig := range a.Servers {
		if len(serverConfig.Features) > 0 {
			a.logger.Debug("autentico features enabled",
				zap.String("server", serverName),
				zap.Strings("features", serverConfig.Features))
		}
	}

	// Simple health check at caddy start up
	for serverName, serverConfig := range a.Servers {
		if serverConfig.URL != "" {
			name := serverName
			config := serverConfig
			// Run in a background goroutine so it doesn't block Caddy's start up
			go func() {
				// 1. Health check
				req, err := http.NewRequest("GET", config.URL+"/ca.crt", nil)
				if err != nil {
					a.logger.Error("failed to create autentico health check request", zap.Error(err), zap.String("server", name))
					return
				}

				if config.APIToken != "" {
					req.Header.Set("Authorization", "Bearer "+config.APIToken)
				}

				var resp *http.Response
				var client *http.Client

				// Retry mechanism: 3s, 5s, 10s, 30s, 1m, 1.5m, 2m max wait
				delays := []time.Duration{
					3 * time.Second,
					5 * time.Second,
					10 * time.Second,
					30 * time.Second,
					1 * time.Minute,
					90 * time.Second,
					2 * time.Minute,
				}

				success := false
				for i, delay := range delays {
					// Reload system cert pool on each retry to pick up new Caddy CA
					pool, _ := x509.SystemCertPool()
TODO fix-insecure-https-10660734649392729994

					tlsConfig := &tls.Config{RootCAs: pool}
					if config.InsecureHTTPS {
						tlsConfig.InsecureSkipVerify = true
=======
					if pool == nil {
						pool = x509.NewCertPool()
					}

					// Get Caddy's internal PKI certificates
					pkiAppIface, err := a.ctx.App("pki")
					if err == nil && pkiAppIface != nil {
						pkiApp := pkiAppIface.(*caddypki.PKI)
						for _, ca := range pkiApp.CAs {
							if ca.RootCertificate() != nil {
								pool.AddCert(ca.RootCertificate())
							}
						}
TODO dev
					}

					client = &http.Client{
						Timeout: 5 * time.Second,
						Transport: &http.Transport{
							TLSClientConfig: tlsConfig,
						},
					}

					resp, err = client.Do(req)
					if err == nil && resp.StatusCode < 500 {
						success = true

						if resp.StatusCode == http.StatusOK && resp.Body != nil {
							caBytes, readErr := io.ReadAll(resp.Body)
							if readErr == nil {
								state := a.serverStates[name]
								state.mu.Lock()
								if state.CertPool == nil {
									state.CertPool = x509.NewCertPool()
								}
								if ok := state.CertPool.AppendCertsFromPEM(caBytes); ok {
									state.CertsInstalled = true

									// Check intermediaries for expiration
									caBytesCopy := caBytes
									for len(caBytesCopy) > 0 {
										var block *pem.Block
										block, caBytesCopy = pem.Decode(caBytesCopy)
										if block == nil {
											break
										}
										if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
											continue
										}

										cert, err := x509.ParseCertificate(block.Bytes)
										if err != nil {
											continue
										}

										// check if within a year of expiring
										if cert.NotAfter.Sub(time.Now()) < 365*24*time.Hour {
											a.logger.Warn("CA certificate within a year of expiring",
												zap.String("server", name),
												zap.String("subject", cert.Subject.CommonName),
												zap.Time("expires", cert.NotAfter))
										}
									}
								} else {
									a.logger.Warn("failed to parse ca.crt PEM during health check", zap.String("server", name))
								}
								state.mu.Unlock()
							}
						}

						if resp.Body != nil {
							resp.Body.Close()
						}
						break
					}

					if resp != nil && resp.Body != nil {
						resp.Body.Close()
					}

					a.logger.Warn("autentico health check failed, retrying...", zap.Error(err), zap.String("server", name), zap.Duration("next_retry", delay))
					if i < len(delays)-1 {
						time.Sleep(delay)
					}
				}

				if !success {
					a.logger.Error("autentico health check failed after max retries", zap.String("server", name))
					return
				}

				// 1.5 Validate API Token and Routes if APIToken is provided
				if config.APIToken != "" {
					parts := strings.Split(config.APIToken, ".")
					if len(parts) == 3 {
						payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
						if err != nil {
							a.logger.Error("failed to decode APIToken payload", zap.Error(err), zap.String("server", name))
							return
						}

						var claims struct {
							Routes []string `json:"routes"`
						}
						if err := json.Unmarshal(payloadBytes, &claims); err != nil {
							a.logger.Error("failed to unmarshal APIToken claims", zap.Error(err), zap.String("server", name))
							return
						}

						// Map features to required routes
						requiredRoutes := []string{}
						for _, f := range config.Features {
							if f == "oidc" {
								requiredRoutes = append(requiredRoutes, "/admin/api/clients:POST", "/admin/api/clients/{id}:GET", "/admin/api/clients/{id}:PUT")
							} else if f == "groups" {
								requiredRoutes = append(requiredRoutes, "/admin/api/users/lookup:POST")
							}
						}

						// Verify required routes are in the token
						hasWildcard := false
						for _, r := range claims.Routes {
							if r == "*:*" || r == "/*:*" || r == "*" {
								hasWildcard = true
								break
							}
						}

						if !hasWildcard && len(requiredRoutes) > 0 {
							for _, reqRoute := range requiredRoutes {
								reqPathMethod := strings.SplitN(reqRoute, ":", 2)
								reqPath := reqPathMethod[0]
								reqMethod := ""
								if len(reqPathMethod) > 1 {
									reqMethod = reqPathMethod[1]
								}

								found := false
								for _, tokenRoute := range claims.Routes {
									trParts := strings.SplitN(tokenRoute, ":", 2)
									trPath := trParts[0]
									trMethod := ""
									if len(trParts) > 1 {
										trMethod = trParts[1]
									}

									// Check if token route is a prefix of required route and methods match or wildcard
									if strings.HasPrefix(reqPath, trPath) {
										if trMethod == "*" || trMethod == "" || reqMethod == "" || trMethod == reqMethod {
											found = true
											break
										}
									}
								}
								if !found {
									a.logger.Error("APIToken missing required route for enabled features",
										zap.String("server", name), zap.String("required_route", reqRoute))
									return
								}
							}
						}

						// Cryptographic verification by calling API
						verifyReq, err := http.NewRequest("GET", config.URL+"/admin/api/settings", nil)
						if err != nil {
							a.logger.Error("failed to create APIToken verification request", zap.Error(err), zap.String("server", name))
							return
						}
						verifyReq.Header.Set("Authorization", "Bearer "+config.APIToken)

						verifyResp, err := client.Do(verifyReq)
						if err != nil {
							a.logger.Error("failed to verify APIToken against API", zap.Error(err), zap.String("server", name))
							return
						}
						defer verifyResp.Body.Close()

						if verifyResp.StatusCode != http.StatusOK {
							a.logger.Error("APIToken verification failed (invalid token or unauthorized)", zap.String("status", verifyResp.Status), zap.String("server", name))
							return
						}
						a.logger.Info("autentico APIToken validated successfully", zap.String("server", name))

					} else {
						a.logger.Error("invalid APIToken format (expected JWT)", zap.String("server", name))
						return
					}
				}

				a.logger.Info("autentico health check successful", zap.String("server", name))

				// 3. Feature-Specific Checks
				for _, feature := range config.Features {
					if feature == "oidc" {
						// Test client secret
						clientID := config.ClientID
						if clientID == "" {
							clientID = "caddy.plugin.autentico"
						}

						data := url.Values{}
						data.Set("grant_type", "client_credentials")
						data.Set("client_id", clientID)
						if config.ClientSecret != "" {
							data.Set("client_secret", config.ClientSecret)
						}

						tokenReq, err := http.NewRequest("POST", config.URL+"/oauth2/token", strings.NewReader(data.Encode()))
						if err != nil {
							a.logger.Error("failed to create token request for oidc check", zap.Error(err), zap.String("server", name))
							return
						}
						tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

						tokenResp, err := client.Do(tokenReq)
						if err != nil {
							a.logger.Error("failed to execute token request for oidc check", zap.Error(err), zap.String("server", name))
							return
						}
						defer tokenResp.Body.Close()

						if tokenResp.StatusCode == http.StatusOK {
							a.logger.Info("autentico oidc client verified", zap.String("server", name))

							// Fetch client details to populate RedirectURIs
							clientReq, _ := http.NewRequest("GET", config.URL+"/admin/api/clients/"+clientID, nil)
							clientReq.Header.Set("Authorization", "Bearer "+config.APIToken)
							clientResp, err := client.Do(clientReq)
							if err == nil && clientResp.StatusCode == http.StatusOK {
								var clientData struct {
									RedirectURIs []string `json:"redirect_uris"`
								}
								if err := json.NewDecoder(clientResp.Body).Decode(&clientData); err == nil {
									state := a.serverStates[name]
									state.mu.Lock()
									state.RedirectURIs = clientData.RedirectURIs
									state.mu.Unlock()
								}
								clientResp.Body.Close()
							}
						} else if tokenResp.StatusCode == http.StatusUnauthorized || tokenResp.StatusCode == http.StatusBadRequest {
							// Client exists but secret might be wrong, OR it doesn't exist
							// Let's check if it exists
							clientReq, _ := http.NewRequest("GET", config.URL+"/admin/api/clients/"+clientID, nil)
							clientReq.Header.Set("Authorization", "Bearer "+config.APIToken)
							clientResp, err := client.Do(clientReq)

							if err == nil && clientResp.StatusCode == http.StatusOK {
								// Client exists, but secret was wrong
								a.logger.Error("oidc client secret is invalid", zap.String("server", name), zap.String("client_id", clientID))
								clientResp.Body.Close()
								return
							}
							if clientResp != nil && clientResp.Body != nil {
								clientResp.Body.Close()
							}

							// Client doesn't exist, create it
							a.logger.Info("oidc client not found, attempting to create", zap.String("server", name), zap.String("client_id", clientID))
							// ACO rejects a blank redirect_uris list on creation. The real
							// callback URL isn't known until a request arrives (it's derived
							// from the request Host), so seed a placeholder here and let
							// RegisterRedirectURI append the real one dynamically.
							placeholderRedirectURI := "http://localhost/oauth2/callback"
							createPayload := map[string]interface{}{
								"client_id":                  clientID,
								"client_name":                "Caddy Autentico Plugin",
								"client_secret":              config.ClientSecret,
								"redirect_uris":              []string{placeholderRedirectURI},
								"grant_types":                []string{"authorization_code", "client_credentials"},
								"response_types":             []string{"code"},
								"token_endpoint_auth_method": "client_secret_post",
							}
							createBody, _ := json.Marshal(createPayload)
							createReq, err := http.NewRequest("POST", config.URL+"/admin/api/clients", bytes.NewReader(createBody))
							if err == nil {
								createReq.Header.Set("Authorization", "Bearer "+config.APIToken)
								createReq.Header.Set("Content-Type", "application/json")
								createResp, err := client.Do(createReq)
								if err == nil {
									defer createResp.Body.Close()
									if createResp.StatusCode == http.StatusCreated {
										a.logger.Info("oidc client created successfully", zap.String("server", name))
										state := a.serverStates[name]
										state.mu.Lock()
										state.RedirectURIs = []string{placeholderRedirectURI}
										state.mu.Unlock()
									} else {
										body, _ := io.ReadAll(createResp.Body)
										a.logger.Error("failed to create oidc client", zap.String("server", name), zap.String("status", createResp.Status), zap.ByteString("response", body))
										return
									}
								}
							}
						}
					} else if feature == "mtls" || feature == "tls" {
						state := a.serverStates[name]
						state.mu.Lock()
						certsInstalled := state.CertsInstalled
						state.mu.Unlock()

						if certsInstalled {
							a.logger.Info("autentico CA chain loaded successfully for mtls/tls", zap.String("server", name))
						} else {
							a.logger.Warn("CA certificates are missing, mtls might not work", zap.String("server", name))
						}
					}
				}
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
				case "insecure_https":
					sc.InsecureHTTPS = true
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
