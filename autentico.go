package autentico

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
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
	ServerName         string   `json:"server_name,omitempty"`
	Policies           []Policy `json:"policies,omitempty"`
	CallbackPath       string   `json:"callback_path,omitempty"`
	CookieDomain       string   `json:"cookie_domain,omitempty"`
	ErrorRespondBody   string   `json:"error_respond_body,omitempty"`
	ErrorRespondStatus int      `json:"error_respond_status,omitempty"`

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
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else if cookie, err := r.Cookie("autentico_token"); err == nil {
		token = cookie.Value
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

	if authMethod == "missing_token" {
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
		if cachedGroups, ok := a.app.GetCachedGroups(token); ok {
			tokenGroups = cachedGroups
		} else {
			// Fetch UserInfo from OIDC provider
			oauth2Token := &oauth2.Token{
				AccessToken: token,
				TokenType:   "Bearer",
			}
			userInfo, err := state.Provider.UserInfo(oidc.ClientContext(r.Context(), state.HTTPClient), oauth2.StaticTokenSource(oauth2Token))
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

			if rawClaims := make(map[string]interface{}); userInfo.Claims(&rawClaims) == nil {
				a.logger.Debug("dumping token claims for group check",
					zap.String("server", a.ServerName),
					zap.String("subject", userInfo.Subject),
					zap.Any("claims", rawClaims))
			}

			var claims struct {
				Groups []string `json:"groups"`
			}
			if err := userInfo.Claims(&claims); err != nil {
				a.logger.Error("failed to unmarshal userinfo claims", zap.Error(err))
				return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("invalid userinfo response"))
			}
			tokenGroups = claims.Groups

			// ACO's userinfo endpoint doesn't expose the user's role, only the
			// access token's own claims do. Decode it directly (already proven
			// valid by the successful userinfo call above) and fold the role in
			// as an implicit group so `allow groups admin` matches on role as
			// well as explicit group membership.
			if _, _, role := accessTokenIdentity(token); role != "" {
				tokenGroups = append(tokenGroups, role)
			}

			// Cache it
			a.app.SetCachedGroups(token, tokenGroups, 5*time.Minute)
		}

		tokenSub, tokenPreferredUsername, _ := accessTokenIdentity(token)
		tokenUsername := tokenPreferredUsername
		if tokenUsername == "" {
			tokenUsername = tokenSub
		}

		if authMethod == "token" {
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

	// 3. Evaluate Policies
	// If no policies exist, we should probably allow since it's just authentication.
	// But let's check policies. First-match-wins logic. Default is deny if they fall through.
	if len(a.Policies) > 0 {
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
			if a.ErrorRespondBody != "" {
				w.WriteHeader(a.ErrorRespondStatus)
				w.Write([]byte(a.ErrorRespondBody))
				return nil
			}
			return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("forbidden"))
		}
	}

	// Expose the resolved identity so later directives (respond, templates,
	// header, reverse_proxy header_up, etc.) can reference it via
	// {http.vars.autentico.user}, {http.vars.autentico.groups}, and
	// {http.vars.autentico.auth_method} - or as a single JSON object via
	// {http.vars.autentico.json}.
	caddyhttp.SetVar(r.Context(), "autentico.user", username)
	caddyhttp.SetVar(r.Context(), "autentico.groups", strings.Join(groups, ","))
	caddyhttp.SetVar(r.Context(), "autentico.auth_method", authMethod)

	jsonGroups := groups
	if jsonGroups == nil {
		jsonGroups = []string{}
	}
	identity := struct {
		Subject    string   `json:"sub"`
		User       string   `json:"user"`
		Groups     []string `json:"groups"`
		AuthMethod string   `json:"auth_method"`
	}{
		Subject:    subject,
		User:       username,
		Groups:     jsonGroups,
		AuthMethod: authMethod,
	}
	if identityJSON, err := json.Marshal(identity); err == nil {
		caddyhttp.SetVar(r.Context(), "autentico.json", string(identityJSON))
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
			// First argument could be server_name, allow, deny, etc.
			firstArg := args[0]
			if firstArg != "allow" && firstArg != "deny" && firstArg != "require_all" && firstArg != "callback_path" && firstArg != "cookie_domain" && firstArg != "error_respond" {
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
