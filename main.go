package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	runtime, err := newAppRuntime()
	if err != nil {
		log.Fatalf("启动服务失败: %v", err)
	}
	defer runtime.shutdown()

	server := newAdminServer(runtime)
	log.Printf("web admin listening on http://%s", runtime.adminAddr)
	if runtime.providerRelay != nil {
		log.Printf("provider relay listening on http://%s", runtime.providerRelay.Addr())
	}

	serverErr := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("web admin server failed: %v", err)
		}
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("web admin shutdown failed: %v", err)
	}
}
