package autentico

import (
	"context"
	"testing"
	"github.com/caddyserver/caddy/v2"
)

func TestAppProvision(t *testing.T) {
	app := &App{}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := app.Provision(ctx); err != nil {
		t.Fatal(err)
	}
}
