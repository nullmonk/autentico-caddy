package autentico

import (
    "bytes"
    "context"
    "crypto/x509"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "io"
    "net/http"

    "github.com/caddyserver/caddy/v2"
    "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
    "github.com/caddyserver/certmagic"
    "go.uber.org/zap"
)

func init() {
    caddy.RegisterModule(Issuer{})
}

// Issuer implements certmagic.Issuer to issue certificates using Autentico's CSR endpoint.
type Issuer struct {
    // Server is the name of the Autentico server configuration to use.
    Server string `json:"server,omitempty"`

    logger *zap.Logger
    ctx    caddy.Context
}

// CaddyModule returns the Caddy module information.
func (Issuer) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "tls.issuance.autentico",
        New: func() caddy.Module { return new(Issuer) },
    }
}

// Provision sets up the module.
func (i *Issuer) Provision(ctx caddy.Context) error {
    i.logger = ctx.Logger()
    i.ctx = ctx
    if i.Server == "" {
        return fmt.Errorf("server name is required for autentico issuer")
    }
    return nil
}

// UnmarshalCaddyfile sets up the issuer from Caddyfile tokens.
// Syntax:
//
//     autentico {
//         server <name>
//     }
//
func (i *Issuer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
    for d.Next() {
        if d.NextArg() {
            return d.ArgErr()
        }
        for d.NextBlock(0) {
            switch d.Val() {
            case "server":
                if !d.NextArg() {
                    return d.ArgErr()
                }
                i.Server = d.Val()
            default:
                return d.Errf("unrecognized subdirective '%s'", d.Val())
            }
        }
    }
    return nil
}

// Issue obtains a certificate for the given CSR using Autentico's CSR endpoint.
func (i *Issuer) Issue(ctx context.Context, request *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
    appAny, err := i.ctx.App("autentico")
    if err != nil {
        return nil, fmt.Errorf("failed to load autentico app: %v", err)
    }
    app, ok := appAny.(*App)
    if !ok {
        return nil, fmt.Errorf("autentico app is of wrong type")
    }

    config, ok := app.Servers[i.Server]
    if !ok {
        return nil, fmt.Errorf("autentico server configuration %q not found", i.Server)
    }
    if config.APIToken == "" {
        return nil, fmt.Errorf("API token is required for certificate issuance via Autentico")
    }

    // Convert CSR to PEM
    csrPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE REQUEST",
        Bytes: request.Raw,
    })

    // Call Autentico CSR endpoint
    payload, err := json.Marshal(map[string]string{
        "csr": string(csrPEM),
    })
    if err != nil {
        return nil, fmt.Errorf("failed to marshal CSR request: %v", err)
    }

    req, err := http.NewRequestWithContext(ctx, "POST", config.URL+"/admin/api/ca/server", bytes.NewReader(payload))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %v", err)
    }
    req.Header.Set("Authorization", "Bearer "+config.APIToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to execute request: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("autentico API error (status %d): %s", resp.StatusCode, string(body))
    }

    var certResp struct {
        CertPEM string `json:"cert_pem"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
        return nil, fmt.Errorf("failed to decode autentico API response: %v", err)
    }

    // CertMagic expects DER-encoded bytes for the IssuedCertificate.Certificate field? Let's check.
    // The struct doc says "The PEM-encoding of DER-encoded ASN.1 data. Certificate []byte". So it's PEM.
    return &certmagic.IssuedCertificate{
        Certificate: []byte(certResp.CertPEM),
    }, nil
}

// IssuerKey uniquely identifies this Issuer.
func (i *Issuer) IssuerKey() string {
    return "autentico_" + i.Server
}

var (
    _ caddy.Provisioner     = (*Issuer)(nil)
    _ certmagic.Issuer      = (*Issuer)(nil)
    _ caddyfile.Unmarshaler = (*Issuer)(nil)
)
