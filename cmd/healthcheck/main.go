package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := os.Getenv("ADDRESS")
	if addr == "" {
		addr = ":8086"
	}
	// Remove leading colon if present for URL construction
	port := addr
	if port[0] == ':' {
		port = port[1:]
	}
	
	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf("http://localhost:%s/.well-known/openid-configuration", port)
	resp, err := client.Get(url)
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		os.Exit(1)
	}
	os.Exit(0)
}
