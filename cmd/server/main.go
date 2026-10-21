// Command server is the fl-orchestrator entry point. It owns Azure/Terraform
// VM provisioning (device-code login + `terraform apply` against the
// terraform/ directory bundled alongside this service) and the post-flow
// that auto-starts FL training once every expected provider has connected —
// pulled out of p3dx-aaa into its own process/port (3002 by default).
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/config"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/httpapi"
)

func main() {
	config.LoadEnv()
	cfg := config.Load()
	if cfg.InternalServiceKey == "" {
		log.Fatal("[fl-orchestrator] INTERNAL_SERVICE_KEY must be set: VM credentials are handed over on the internal routes")
	}
	if cfg.KeycloakClientSecret == "" {
		log.Fatal("[fl-orchestrator] KEYCLOAK_CLIENT_SECRET must be set: the orchestrator's service account secures session gateways")
	}

	if len(cfg.DryRunVMs) > 0 {
		log.Printf("[fl-orchestrator] DRY RUN: no Azure sign-in or VM creation; using existing VMs %v", cfg.DryRunVMs)
	}

	api := httpapi.New(cfg)

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: api.Handler(),
	}

	go func() {
		log.Printf("[fl-orchestrator] running on port %s (terraform dir: %s)", cfg.Port, cfg.TerraformDir)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[ERROR] server failed: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	log.Println("[fl-orchestrator] shut down")
}
