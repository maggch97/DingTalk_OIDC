package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/maggch97/dingtalk-oidc/internal/oidc"
)

func main() {
	addr := os.Getenv("ADDRESS")
	if addr == "" {
		addr = ":8086"
	}
	s, err := oidc.NewServer()
	if err != nil {
		log.Fatalf("init server: %v", err)
	}
	mux := http.NewServeMux()
	s.RegisterHandlers(mux)
	// background cleanup
	go func() {
		for {
			time.Sleep(2 * time.Minute)
			s.AuthCodes.Cleanup()
			s.Pending.Cleanup()
		}
	}()
	log.Printf("DingTalk OIDC bridge listening on %s (issuer=%s)", addr, s.Issuer)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
