package main

import (
	"context"
	"net/http"
	"os"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:8080/health", http.NoBody)
	if err != nil {
		cancel()
		os.Exit(1)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		os.Exit(1)
	}
	_ = resp.Body.Close()
	cancel()

	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}
