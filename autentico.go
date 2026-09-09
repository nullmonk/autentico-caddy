package autentico

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func init() {
	caddy.RegisterModule(Autentico{})
	httpcaddyfile.RegisterHandlerDirective("autentico", parseCaddyfile)
}

// Rule defines a single allow or deny rule.
type Rule struct {
	Action string   `json:"action,omitempty"` // "allow" or "deny"
	Type   string   `json:"type,omitempty"`   // "group", "groups", "user", "users", "method", "" (empty allow)
	Values []string `json:"values,omitempty"` // e.g. ["admin", "dev"], or ["mtls"]
}

// Policy defines a list of rules that can optionally be evaluated with logical AND.
type Policy struct {
	Rules      []Rule `json:"rules,omitempty"`
	RequireAll bool   `json:"require_all,omitempty"`
}

// Autentico implements an HTTP handler that validates requests with an Autentico service.
type Autentico struct {
	ServerName          string   `json:"server_name,omitempty"`
	Policies            []Policy `json:"policies,omitempty"`
	CallbackPath        string   `json:"callback_path,omitempty"`
	CookieDomain        string   `json:"cookie_domain,omitempty"`
	ErrorRespondBody    string   `json:"error_respond_body,omitempty"`
	ErrorRespondStatus  int      `json:"error_respond_status,omitempty"`
	IsExternal          bool     `json:"is_external,omitempty"`
	ExternalTokenSource string   `json:"external_token_source,omitempty"`
	ExternalCookieName  string   `json:"external_cookie_name,omitempty"`
	// ExternalExcludeGlobs are path.Match glob patterns (e.g. "/api/*") that
	// bypass the token check entirely when IsExternal is set - for paths an
	// external service must serve without a token (health checks, public
	// assets, etc).
	ExternalExcludeGlobs []string `json:"external_exclude_globs,omitempty"`

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
	if a.ServerName == "default" {
		a.ServerName = "" // "" is the default server alias
	}

	if a.CallbackPath == "" {
		a.CallbackPath = "/oauth2/callback"
	}

	for _, pattern := range a.ExternalExcludeGlobs {
		if _, err := path.Match(pattern, "/"); err != nil {
			return fmt.Errorf("invalid external exclude glob %q: %v", pattern, err)
		}
	}

	appIface, err := ctx.App("autentico")
	if err != nil {
		return fmt.Errorf("autentico app not configured: %v", err)
	}
	a.app = appIface.(*App)
	a.logger = ctx.Logger()

	// Ensure the server exists in global config
	if _, ok := a.app.Servers[a.ServerName]; !ok {
		if a.ServerName == "" {
			return fmt.Errorf("autentico default server not found in global config")
		}
		return fmt.Errorf("autentico server %q not found in global config", a.ServerName)
	}

	// Register necessary features based on this handler's requirements
	a.app.RegisterFeature(a.ServerName, "oidc")

	hasGroups := false
	hasMTLS := false
	for _, p := range a.Policies {
		for _, r := range p.Rules {
			if r.Type == "group" || r.Type == "groups" {
				hasGroups = true
			}
			if r.Type == "method" {
				for _, v := range r.Values {
					if v == "mtls" || v == "both" {
						hasMTLS = true
					}
				}
			}
		}
	}

	if hasGroups {
		a.app.RegisterFeature(a.ServerName, "groups")

		// The "groups" claim on the userinfo response (used for token-based
		// auth) is only populated when the "groups" scope was requested (see
		// ServerConfig.Scopes) - without it, group rules always see an empty
		// group list for token-authenticated users.
		hasGroupsScope := false
		for _, s := range a.app.Servers[a.ServerName].Scopes {
			if s == "groups" {
				hasGroupsScope = true
				break
			}
		}
		if !hasGroupsScope {
			a.logger.Warn("policy uses group/groups rules but the 'groups' scope is not configured for this server; token-authenticated users will always have an empty group list",
				zap.String("server", a.ServerName))
		}
	}
	if hasMTLS {
		a.app.RegisterFeature(a.ServerName, "mtls")
	}

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

// generateCodeVerifier generates a PKCE code verifier
func generateCodeVerifier() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateCodeChallenge generates a PKCE code challenge from a verifier
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// accessTokenIdentity extracts the "sub", "preferred_username", and "role"
// claims from a JWT access token's payload without verifying its signature.
// This is safe to call here because the token has already been proven valid
// elsewhere (a successful login, or a successful call against the OIDC
// provider's userinfo endpoint) - this only reads claims (preferred_username,
// role) that the userinfo endpoint doesn't expose.
func accessTokenIdentity(token string) (sub, preferredUsername, role string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", ""
	}
	var claims struct {
		Subject           string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Role              string `json:"role"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", ""
	}
	return claims.Subject, claims.PreferredUsername, claims.Role
}

// matchesExternalExclude reports whether urlPath matches any of the
// configured external exclude globs.
func (a Autentico) matchesExternalExclude(urlPath string) bool {
	for _, pattern := range a.ExternalExcludeGlobs {
		if ok, _ := path.Match(pattern, urlPath); ok {
			return true
		}
	}
	return false
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

	if a.IsExternal && a.matchesExternalExclude(r.URL.Path) {
		return next.ServeHTTP(w, r)
	}

	// MTLS Validation logic
	var mtlsUsername string
	var mtlsCertSerial string
	mtlsValid := false

	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		clientCert := r.TLS.PeerCertificates[0]

		state.mu.Lock()
		pool := state.CertPool
		state.mu.Unlock()

		if pool != nil {
			opts := x509.VerifyOptions{
				Roots:     pool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			if _, err := clientCert.Verify(opts); err == nil {
				mtlsValid = true
				mtlsUsername = clientCert.Subject.CommonName
				mtlsCertSerial = clientCert.SerialNumber.String()
			} else {
				a.logger.Debug("mtls verification failed", zap.Error(err))
			}
		} else {
			a.logger.Warn("mtls CA pool is not initialized")
		}
	}

	// Extract Bearer token
	token := ""
	externalCookieFound := false
	fromCookie := false
	if a.IsExternal {
		if a.ExternalTokenSource == "cookie" {
			if cookie, err := r.Cookie(a.ExternalCookieName); err == nil {
				token = cookie.Value
				externalCookieFound = true
			}
		} else if a.ExternalTokenSource == "bearer" {
			if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}
	} else {
		if cookie, err := r.Cookie("autentico_token"); err == nil {
			token = cookie.Value
			fromCookie = true
		} else if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	tokenValid := token != ""

	var authMethod string
	var groups []string
	var username string
	var subject string

	if tokenValid && mtlsValid {
		authMethod = "both"
	} else if tokenValid {
		authMethod = "token"
	} else if mtlsValid {
		authMethod = "mtls"
	} else {
		authMethod = "missing_token"
	}

	if authMethod == "missing_token" && !a.IsExternal {
		if a.ErrorRespondBody != "" {
			w.WriteHeader(a.ErrorRespondStatus)
			w.Write([]byte(a.ErrorRespondBody))
			return nil
		}

		if !strings.Contains(r.Header.Get("Accept"), "text/html") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="autentico"`)
			return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("unauthorized"))
		}

		// Check and dynamically register the callback URL if needed
		state.mu.Lock()
		foundRedirect := false
		for _, u := range state.RedirectURIs {
			if u == callbackURL {
				foundRedirect = true
				break
			}
		}
		state.mu.Unlock()

		if !foundRedirect {
			err := a.app.RegisterRedirectURI(r.Context(), a.ServerName, callbackURL)
			if err != nil {
				a.logger.Error("failed to register redirect uri", zap.Error(err), zap.String("callbackURL", callbackURL))
				return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("failed to configure oauth2 client"))
			}
		}

		oauthState := generateState()
		var verifier string
		authOpts := []oauth2.AuthCodeOption{}

		a.app.mu.Lock()
		serverConfig := a.app.Servers[a.ServerName]
		a.app.mu.Unlock()

		if serverConfig != nil && serverConfig.ClientMode == "pkce" {
			verifier = generateCodeVerifier()
			challenge := generateCodeChallenge(verifier)
			authOpts = append(authOpts,
				oauth2.SetAuthURLParam("code_challenge", challenge),
				oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			)
		}

		// Store the original URL to redirect back to after login
		originalURL := r.URL.String()
		cookieValue := fmt.Sprintf("%s|%s", oauthState, originalURL)
		if verifier != "" {
			cookieValue = fmt.Sprintf("%s|%s|%s", oauthState, originalURL, verifier)
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "autentico_oauth_state",
			Value:    cookieValue,
			Path:     "/",
			HttpOnly: true,
			Secure:   scheme == "https",
			MaxAge:   300,
		})

		url := oauthConfig.AuthCodeURL(oauthState, authOpts...)
		http.Redirect(w, r, url, http.StatusFound)
		return nil
	}

	// Fetch groups
	if authMethod == "mtls" {
		username = mtlsUsername
		subject = mtlsCertSerial
		// Use MTLS cert to fetch groups
		cacheKey := fmt.Sprintf("mtls:%s:%s", mtlsCertSerial, a.ServerName)
		if cachedGroups, ok := a.app.GetCachedGroups(cacheKey); ok {
			groups = cachedGroups
		} else {
			fetchedGroups, err := a.app.LookupUserGroups(r.Context(), a.ServerName, mtlsUsername)
			if err != nil {
				a.logger.Warn("failed to fetch user groups via mtls", zap.Error(err), zap.String("username", mtlsUsername))
				return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("invalid mtls user"))
			}
			groups = fetchedGroups
			a.app.SetCachedGroups(cacheKey, groups, 5*time.Minute)
		}
	} else if authMethod == "token" || authMethod == "both" {
		// Use Token to fetch groups
		var tokenGroups []string

		tokenSub, tokenPreferredUsername, _ := accessTokenIdentity(token)
		tokenUsername := tokenPreferredUsername
		if tokenUsername == "" {
			tokenUsername = tokenSub
		}

		if cachedGroups, ok := a.app.GetCachedGroups(token); ok {
			tokenGroups = cachedGroups
		} else if a.IsExternal {
			// External tokens (e.g. an ID token from the app autentico sits
			// in front of) were issued to a different OAuth client, so
			// verify them locally instead of calling this provider's
			// userinfo endpoint - which many providers reject an ID token
			// against regardless of validity - and distinguish "expired"
			// from "genuinely invalid" while we're at it. There is no
			// userinfo fallback: a token this provider didn't issue is
			// simply invalid.
			_, expired, rawClaims, err := a.app.VerifyExternalIDToken(r.Context(), state, token)
			if err != nil {
				a.logger.Warn("external token failed local verification", zap.Error(err))
				authMethod = "invalid"
				tokenValid = false
				goto skip_token_processing
			}

			a.logger.Debug("verified external token locally",
				zap.String("server", a.ServerName),
				zap.Bool("expired", expired),
				zap.Any("claims", rawClaims))

			if expired {
				authMethod = "expired"
			}

			// Other clients' tokens generally don't carry a groups/roles
			// claim of their own (e.g. audiobookshelf's client doesn't), so
			// resolve real group membership via the admin API instead,
			// cached per username same as the MTLS path below.
			groupCacheKey := fmt.Sprintf("external:%s:%s", tokenUsername, a.ServerName)
			if cachedGroups, ok := a.app.GetCachedGroups(groupCacheKey); ok {
				tokenGroups = cachedGroups
			} else if fetchedGroups, err := a.app.LookupUserGroups(r.Context(), a.ServerName, tokenUsername); err != nil {
				a.logger.Warn("failed to fetch user groups for external token", zap.Error(err), zap.String("username", tokenUsername))
			} else {
				tokenGroups = fetchedGroups
				a.app.SetCachedGroups(groupCacheKey, tokenGroups, 5*time.Minute)
			}

			a.app.SetCachedGroups(token, tokenGroups, 5*time.Minute)
		} else {
			res, err := a.app.FetchUserInfoGroups(r.Context(), state.HTTPClient, state.Provider, token, 5*time.Minute)
			if err != nil {
				var unmarshalErr *unmarshalClaimsError
				if errors.As(err, &unmarshalErr) {
					a.logger.Error("failed to unmarshal userinfo claims", zap.Error(err))
					return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("invalid userinfo response"))
				}

				a.logger.Warn("failed to fetch userinfo", zap.Error(err))

				// Token might be invalid/expired, clear cookie if it came from one
				if fromCookie {
					http.SetCookie(w, &http.Cookie{
						Name:     "autentico_token",
						Value:    "",
						Path:     "/",
						Expires:  time.Unix(0, 0),
						HttpOnly: true,
					})
				}
				return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("invalid token"))
			}

			a.logger.Debug("dumping token claims for group check",
				zap.String("server", a.ServerName),
				zap.String("subject", res.Subject),
				zap.Any("claims", res.RawClaims))

			tokenGroups = res.Groups
		}

		if authMethod == "token" || authMethod == "expired" {
			groups = tokenGroups
			username = tokenUsername
			subject = tokenSub
		} else if authMethod == "both" {
			username = tokenUsername
			subject = tokenSub
			if username == "" {
				username = mtlsUsername
			}
			if subject == "" {
				subject = mtlsCertSerial
			}

			// Merge groups from MTLS and Token
			var mtlsGroups []string
			cacheKey := fmt.Sprintf("mtls:%s:%s", mtlsCertSerial, a.ServerName)
			if cachedGroups, ok := a.app.GetCachedGroups(cacheKey); ok {
				mtlsGroups = cachedGroups
			} else {
				fetchedGroups, err := a.app.LookupUserGroups(r.Context(), a.ServerName, mtlsUsername)
				if err != nil {
					a.logger.Warn("failed to fetch user groups via mtls", zap.Error(err), zap.String("username", mtlsUsername))
					return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("invalid mtls user"))
				}
				mtlsGroups = fetchedGroups
				a.app.SetCachedGroups(cacheKey, mtlsGroups, 5*time.Minute)
			}

			// Deduplicate merged groups
			groupMap := make(map[string]bool)
			for _, g := range tokenGroups {
				groupMap[g] = true
			}
			for _, g := range mtlsGroups {
				groupMap[g] = true
			}
			for g := range groupMap {
				groups = append(groups, g)
			}
		}
	}

skip_token_processing:

	// If external and token is missing or invalid, do not evaluate policies or reject.
	if a.IsExternal && (authMethod == "missing_token" || authMethod == "invalid") {
		if authMethod == "missing_token" {
			authMethod = "unauthenticated"
		}
		// Bypass policy evaluation and let the request continue
	} else if len(a.Policies) > 0 && !a.IsExternal {
		// 3. Evaluate Policies
		// If no policies exist, we should probably allow since it's just authentication.
		// But let's check policies. First-match-wins logic. Default is deny if they fall through.
		allowed := false
		matched := false

		for _, policy := range a.Policies {
			policyMatch := true

			for _, rule := range policy.Rules {
				ruleMatch := false

				if rule.Type == "" { // empty allow/deny matches everything
					ruleMatch = true
				} else if rule.Type == "group" || rule.Type == "groups" {
					for _, userGroup := range groups {
						for _, val := range rule.Values {
							if userGroup == val {
								ruleMatch = true
								break
							}
						}
						if ruleMatch {
							break
						}
					}
				} else if rule.Type == "user" || rule.Type == "users" {
					for _, val := range rule.Values {
						if username == val || subject == val {
							ruleMatch = true
							break
						}
					}
				} else if rule.Type == "method" {
					for _, val := range rule.Values {
						if authMethod == val || (authMethod == "both" && (val == "mtls" || val == "token")) {
							ruleMatch = true
							break
						}
					}
				}

				if policy.RequireAll {
					// "evaluates to true if all the allows and none of the denies match"
					if rule.Action == "allow" && !ruleMatch {
						policyMatch = false
						break
					} else if rule.Action == "deny" && ruleMatch {
						policyMatch = false
						break
					}
				} else {
					// standard rule policy block has exactly 1 rule
					if ruleMatch {
						matched = true
						allowed = (rule.Action == "allow")
						break
					}
				}
			}

			if matched {
				break
			}

			if policy.RequireAll && policyMatch {
				matched = true
				allowed = true // require_all implies allow if all pass
				break
			}
		}

		if !allowed {
			// Do not return Forbidden if external flag is set, instead just pass through
			if a.IsExternal {
				// We actually shouldn't hit this path because we bypass policies for missing/invalid token
				// but just in case, we still don't want to interrupt flow for external tokens that fail policy checks
				// Wait, if it IS external and the token IS valid, but it fails a policy... the user requested:
				// "Yes skip the policy enforement, just extract the variables"
				// So if IsExternal, we actually shouldn't evaluate policies at all.
			} else {
				if a.ErrorRespondBody != "" {
					w.WriteHeader(a.ErrorRespondStatus)
					w.Write([]byte(a.ErrorRespondBody))
					return nil
				}
				return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("forbidden"))
			}
		}
	}

	// Expose the resolved identity so later directives (respond, templates,
	// header, reverse_proxy header_up, matcher expressions, etc.) can
	// reference it via {http.auth.autentico.user}, {http.auth.autentico.groups},
	// and {http.auth.autentico.method} - or as a single JSON object via
	// {http.auth.autentico.json}.
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("http.auth.autentico.user", username)
	repl.Set("http.auth.autentico.groups", strings.Join(groups, ","))
	repl.Set("http.auth.autentico.method", authMethod)

	if a.IsExternal {
		repl.Set("http.auth.autentico.external", "true")
	} else {
		repl.Set("http.auth.autentico.external", "false")
	}

	jsonGroups := groups
	if jsonGroups == nil {
		jsonGroups = []string{}
	}
	identity := struct {
		Subject    string   `json:"sub"`
		User       string   `json:"user"`
		Groups     []string `json:"groups"`
		AuthMethod string   `json:"method"`
		External   bool     `json:"external"`
	}{
		Subject:    subject,
		User:       username,
		Groups:     jsonGroups,
		AuthMethod: authMethod,
		External:   a.IsExternal,
	}
	if identityJSON, err := json.Marshal(identity); err == nil {
		repl.Set("http.auth.autentico.json", string(identityJSON))
		if externalCookieFound {
			a.logger.Debug("external cookie found, resolved user info", zap.String("cookie_name", a.ExternalCookieName), zap.ByteString("autentico.json", identityJSON))
		}
	} else {
		a.logger.Warn("failed to marshal autentico identity", zap.Error(err))
	}

	return next.ServeHTTP(w, r)
}

func (a *Autentico) handleCallback(w http.ResponseWriter, r *http.Request, state *ServerState, oauthConfig oauth2.Config) error {
	ctx := oidc.ClientContext(context.Background(), state.HTTPClient)

	cookieState, err := r.Cookie("autentico_oauth_state")
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("missing state cookie"))
	}

	parts := strings.Split(cookieState.Value, "|")
	if len(parts) < 2 {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid state cookie format"))
	}
	expectedState, originalURL := parts[0], parts[1]

	var verifier string
	if len(parts) == 3 {
		verifier = parts[2]
	}

	if r.URL.Query().Get("state") != expectedState {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid oauth state"))
	}

	authOpts := []oauth2.AuthCodeOption{}
	if verifier != "" {
		authOpts = append(authOpts, oauth2.SetAuthURLParam("code_verifier", verifier))
	}

	oauth2Token, err := oauthConfig.Exchange(ctx, r.URL.Query().Get("code"), authOpts...)
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
		Domain:   a.CookieDomain,
	})

	http.Redirect(w, r, originalURL, http.StatusFound)
	return nil
}

func parseRuleFromArgs(action string, args []string) (Rule, error) {
	rule := Rule{Action: action}
	if len(args) == 0 {
		return rule, nil
	}

	rule.Type = args[0]
	if rule.Type != "group" && rule.Type != "groups" && rule.Type != "user" && rule.Type != "users" && rule.Type != "method" {
		return rule, fmt.Errorf("invalid rule type '%s', expected group(s), user(s), or method", rule.Type)
	}

	rule.Values = args[1:]
	if len(rule.Values) == 0 {
		return rule, fmt.Errorf("expected values after '%s'", rule.Type)
	}

	if rule.Type == "method" {
		for _, v := range rule.Values {
			if v != "mtls" && v != "token" && v != "both" {
				return rule, fmt.Errorf("invalid method '%s', expected mtls, token, or both", v)
			}
		}
	}

	return rule, nil
}

func parseRule(d *caddyfile.Dispenser, action string) (Rule, error) {
	var args []string
	if d.NextArg() {
		args = append(args, d.Val())
		args = append(args, d.RemainingArgs()...)
	}
	rule, err := parseRuleFromArgs(action, args)
	if err != nil {
		return rule, d.Err(err.Error())
	}
	return rule, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (a *Autentico) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		var args []string
		if d.NextArg() {
			args = append(args, d.Val())
			args = append(args, d.RemainingArgs()...)
		}

		if len(args) > 0 {
			// First argument could be server_name, allow, deny, external, etc.
			firstArg := args[0]
			if firstArg != "allow" && firstArg != "deny" && firstArg != "require_all" && firstArg != "callback_path" && firstArg != "cookie_domain" && firstArg != "error_respond" && firstArg != "external" {
				a.ServerName = firstArg
				args = args[1:]
			}
		}

		if len(args) > 0 {
			action := args[0]
			if action == "allow" || action == "deny" {
				rule, err := parseRuleFromArgs(action, args[1:])
				if err != nil {
					return d.Errf("inline rule error: %v", err)
				}
				a.Policies = append(a.Policies, Policy{Rules: []Rule{rule}})
			} else if action == "external" {
				a.IsExternal = true
				rest := args[1:]
				if len(rest) == 0 {
					return d.Errf("expected 'cookie <name>' or 'bearer' after 'external'")
				}
				a.ExternalTokenSource = rest[0]
				rest = rest[1:]
				if a.ExternalTokenSource == "cookie" {
					if len(rest) == 0 {
						return d.Errf("expected cookie name after 'external cookie'")
					}
					a.ExternalCookieName = rest[0]
					rest = rest[1:]
				} else if a.ExternalTokenSource != "bearer" {
					return d.Errf("expected 'cookie <name>' or 'bearer' after 'external', got '%s'", a.ExternalTokenSource)
				}
				if len(rest) > 0 {
					if rest[0] != "exclude" {
						return d.Errf("unexpected argument after external directive: %s", rest[0])
					}
					rest = rest[1:]
					if len(rest) == 0 {
						return d.Errf("expected at least one glob after 'exclude'")
					}
					a.ExternalExcludeGlobs = append(a.ExternalExcludeGlobs, rest...)
				}
			} else {
				return d.Errf("unrecognized inline argument: %s", action)
			}
		}

		for d.NextBlock(0) {
			val := d.Val()
			switch val {
			case "allow", "deny":
				rule, err := parseRule(d, val)
				if err != nil {
					return err
				}
				a.Policies = append(a.Policies, Policy{Rules: []Rule{rule}})

			case "require_all":
				policy := Policy{RequireAll: true}
				for d.NextBlock(1) {
					innerVal := d.Val()
					if innerVal != "allow" && innerVal != "deny" {
						return d.Errf("expected 'allow' or 'deny' inside require_all, got '%s'", innerVal)
					}
					rule, err := parseRule(d, innerVal)
					if err != nil {
						return err
					}
					policy.Rules = append(policy.Rules, rule)
				}
				a.Policies = append(a.Policies, policy)

			case "callback_path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.CallbackPath = d.Val()

			case "cookie_domain":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.CookieDomain = d.Val()

			case "error_respond":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.ErrorRespondBody = d.Val()
				if d.NextArg() {
					var status int
					fmt.Sscanf(d.Val(), "%d", &status)
					if status < 100 || status > 599 {
						return d.Errf("invalid HTTP status code '%s'", d.Val())
					}
					a.ErrorRespondStatus = status
				} else {
					a.ErrorRespondStatus = 403 // Default to 403 Forbidden
				}

			case "external":
				if !d.NextArg() {
					return d.Errf("expected 'cookie <name>', 'bearer', or 'exclude <glob>' after 'external'")
				}
				mode := d.Val()
				if mode == "exclude" {
					globs := d.RemainingArgs()
					if len(globs) == 0 {
						return d.Errf("expected at least one glob after 'external exclude'")
					}
					a.ExternalExcludeGlobs = append(a.ExternalExcludeGlobs, globs...)
					break
				}

				a.IsExternal = true
				a.ExternalTokenSource = mode
				if a.ExternalTokenSource == "cookie" {
					if !d.NextArg() {
						return d.Errf("expected cookie name after 'external cookie'")
					}
					a.ExternalCookieName = d.Val()
				} else if a.ExternalTokenSource != "bearer" {
					return d.Errf("expected 'cookie <name>' or 'bearer' after 'external', got '%s'", a.ExternalTokenSource)
				}
				if d.NextArg() {
					if d.Val() != "exclude" {
						return d.Errf("unexpected argument after external directive: %s", d.Val())
					}
					globs := d.RemainingArgs()
					if len(globs) == 0 {
						return d.Errf("expected at least one glob after 'exclude'")
					}
					a.ExternalExcludeGlobs = append(a.ExternalExcludeGlobs, globs...)
				}

			default:
				return d.Errf("unrecognized subdirective: %s", val)
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
	_ caddyhttp.MiddlewareHandler = (Autentico{}) // ServeHTTP receives value, not pointer
	_ caddyfile.Unmarshaler       = (*Autentico)(nil)
)
