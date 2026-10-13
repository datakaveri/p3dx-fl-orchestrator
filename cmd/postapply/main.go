// Command postapply runs the Flotilla join-gateway post-apply steps against
// an existing VM, without terraform or Azure — the same code path
// RunAutoProvision calls after `terraform apply`. For testing and manual
// recovery.
//
//	server VM:  postapply -role user -host 20.235.21.40 -submission <id> [-ca-out ca.pem]
//	client VM:  postapply -role data-provider -host 74.224.88.55 -submission <id> \
//	                -user prov-a -gateway-host 20.235.21.40 -ca-file ca.pem
//
// For a client VM it listens on PORT (default 3002) for p3dx-aaa's credential
// hand-over (exactly like the orchestrator), then claims, delivers and wipes
// it. Reads the same .env / environment as the server.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/config"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/flauto"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/keycloak"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/postapply"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmcred"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmsession"
)

// followSession runs the real flauto against the secured gateway: poll
// /client_status over HTTPS with the service token until -expect clients
// are connected, start the session, and print flauto's events until done.
func followSession(cfg *config.Config, tokens *keycloak.TokenSource, submission, ip, caPEM string, expect int, wait time.Duration) {
	store := vmsession.NewStore()
	flow := flauto.NewManager(store, tokens.Token, cfg.GatewayRESTPort)
	runToken := store.CreateToken("postapply", "user")
	if err := flow.SetGatewayCA(submission, caPEM); err != nil {
		log.Fatal(err)
	}
	flow.RegisterOwnerVM(submission, ip, runToken)
	flow.RegisterExpectedProviders(submission, expect)
	seen := 0
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		snap, _ := store.Get(runToken)
		for _, e := range snap.Events[seen:] {
			log.Printf("[flauto] %s: %s — %s", e.Step, e.Status, e.Message)
			if e.Step == "FL session" && (e.Status == "done" || e.Status == "error") {
				return
			}
		}
		seen = len(snap.Events)
		time.Sleep(2 * time.Second)
	}
	log.Fatal("FL session did not finish in time")
}

func main() {
	role := flag.String("role", "", "user (server VM) or data-provider (client VM)")
	host := flag.String("host", "", "VM address to SSH to")
	publicIP := flag.String("public-ip", "", "VM public IP (certificate SAN / sidecar address); default -host")
	startSession := flag.Bool("start-session", false, "user: then run flauto — wait for -expect clients and start training")
	expect := flag.Int("expect", 1, "user: number of providers flauto waits for")
	sessionWait := flag.Duration("session-wait", 2*time.Hour, "user: how long to follow the FL session")
	sshUser := flag.String("ssh-user", "", "SSH user (default VM_SSH_USER)")
	sshKey := flag.String("ssh-key", "", "SSH private key (default: your default identity)")
	submission := flag.String("submission", "", "FL submission id")
	user := flag.String("user", "", "data-provider: the provider whose credential to deliver")
	gatewayHost := flag.String("gateway-host", "", "data-provider: the session's server VM IP")
	caFile := flag.String("ca-file", "", "data-provider: gateway CA PEM (from the server run)")
	caOut := flag.String("ca-out", "", "user: write the gateway CA PEM here")
	wait := flag.Duration("wait", 10*time.Minute, "data-provider: how long to wait for the credential hand-over")
	flag.Parse()

	config.LoadEnv()
	cfg := config.Load()
	if *publicIP == "" {
		*publicIP = *host
	}
	if *sshUser != "" {
		cfg.SSHUser = *sshUser
	}
	tokens := keycloak.NewTokenSource(cfg.KeycloakBaseURL, cfg.KeycloakRealm, cfg.KeycloakClientID, cfg.KeycloakClientSecret)
	run := postapply.New(cfg, tokens)
	known, _ := os.MkdirTemp("", "postapply-")
	defer os.RemoveAll(known)
	target := postapply.SSHTarget{Host: *host, User: cfg.SSHUser, Port: cfg.SSHPort, KeyPath: *sshKey,
		KnownHosts: filepath.Join(known, "known_hosts")}
	emit := func(step, status, msg string) { log.Printf("[%s] %s: %s", status, step, msg) }

	switch *role {
	case "user":
		cert, err := run.SecureGateway(target, *publicIP, *submission, emit)
		if err != nil {
			log.Fatal(err)
		}
		if *caOut != "" {
			if err := os.WriteFile(*caOut, []byte(cert.CAPEM), 0o644); err != nil {
				log.Fatal(err)
			}
		}
		log.Printf("gateway secured: serial %s, contract %s, not after %s", cert.Serial, cert.ContractID, cert.NotAfter)
		if *startSession {
			followSession(cfg, tokens, *submission, *publicIP, cert.CAPEM, *expect, *sessionWait)
		}

	case "data-provider":
		ca, err := os.ReadFile(*caFile)
		if err != nil || *gatewayHost == "" || *user == "" {
			log.Fatal("data-provider needs -user, -gateway-host and -ca-file")
		}
		if cfg.InternalServiceKey == "" {
			log.Fatal("INTERNAL_SERVICE_KEY must be set")
		}
		creds := vmcred.NewStore(*wait)
		got := make(chan string, 1)
		mux := http.NewServeMux()
		mux.HandleFunc("/p3dx/internal/vm-credentials", handoff(cfg.InternalServiceKey, creds, got))
		srv := &http.Server{Addr: ":" + cfg.Port, Handler: mux}
		go func() { _ = srv.ListenAndServe() }()
		log.Printf("waiting up to %s for p3dx-aaa to hand over %s's VM credential on :%s …", *wait, *user, cfg.Port)
		var id string
		select {
		case id = <-got:
		case <-time.After(*wait):
			log.Fatal("no credential handed over")
		}
		_ = srv.Close()
		if _, err := creds.Claim(id, *user, *submission); err != nil {
			log.Fatal(err)
		}
		token, err := creds.Take(id)
		if err != nil {
			log.Fatal(err)
		}
		if err := run.DeliverClient(target, postapply.ClientInput{SubmissionID: *submission, CredentialID: id,
			Token: token, SelfIP: *publicIP, GatewayHost: *gatewayHost, CAPEM: string(ca)}, emit); err != nil {
			log.Fatal(err)
		}
		log.Printf("credential %s delivered to %s", id, *host)

	default:
		log.Fatal("-role must be user or data-provider")
	}
}
