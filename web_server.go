package main

import (
	"bytes"
	"codeswitch/services"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var errorType = reflect.TypeOf((*error)(nil)).Elem()

type rpcRegistry struct {
	services map[string]any
}

func newRPCRegistry() *rpcRegistry {
	return &rpcRegistry{
		services: make(map[string]any),
	}
}

func (r *rpcRegistry) Register(name string, service any) {
	r.services[name] = service
}

func (r *rpcRegistry) Call(name string, args []json.RawMessage) (_ any, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("rpc panic: %v", recovered)
		}
	}()

	methodSep := strings.LastIndex(name, ".")
	if methodSep <= 0 || methodSep == len(name)-1 {
		return nil, fmt.Errorf("invalid rpc name: %s", name)
	}

	serviceName := name[:methodSep]
	methodName := name[methodSep+1:]
	service, ok := r.services[serviceName]
	if !ok {
		return nil, fmt.Errorf("unknown service: %s", serviceName)
	}

	method := reflect.ValueOf(service).MethodByName(methodName)
	if !method.IsValid() {
		return nil, fmt.Errorf("unknown method: %s", name)
	}

	methodType := method.Type()
	if len(args) != methodType.NumIn() {
		return nil, fmt.Errorf("invalid argument count for %s: expected %d, got %d", name, methodType.NumIn(), len(args))
	}

	callArgs := make([]reflect.Value, methodType.NumIn())
	for i := 0; i < methodType.NumIn(); i++ {
		value, decodeErr := decodeRPCArg(args[i], methodType.In(i))
		if decodeErr != nil {
			return nil, fmt.Errorf("decode argument %d for %s: %w", i, name, decodeErr)
		}
		callArgs[i] = value
	}

	return unpackRPCResults(method.Call(callArgs))
}

func decodeRPCArg(raw json.RawMessage, targetType reflect.Type) (reflect.Value, error) {
	if len(raw) == 0 {
		raw = json.RawMessage("null")
	}

	if bytes.Equal(raw, []byte("null")) {
		return reflect.Zero(targetType), nil
	}

	if targetType.Kind() == reflect.Interface {
		if targetType.NumMethod() > 0 {
			return reflect.Zero(targetType), fmt.Errorf("cannot decode into non-empty interface %s", targetType.String())
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return reflect.Zero(targetType), err
		}
		return reflect.ValueOf(value), nil
	}

	if targetType.Kind() == reflect.Pointer {
		value := reflect.New(targetType.Elem())
		if err := json.Unmarshal(raw, value.Interface()); err != nil {
			return reflect.Zero(targetType), err
		}
		return value, nil
	}

	value := reflect.New(targetType)
	if err := json.Unmarshal(raw, value.Interface()); err != nil {
		return reflect.Zero(targetType), err
	}
	return value.Elem(), nil
}

func unpackRPCResults(results []reflect.Value) (any, error) {
	switch len(results) {
	case 0:
		return nil, nil
	case 1:
		if results[0].Type().Implements(errorType) {
			if results[0].IsNil() {
				return nil, nil
			}
			return nil, results[0].Interface().(error)
		}
		return results[0].Interface(), nil
	default:
		last := results[len(results)-1]
		if last.Type().Implements(errorType) {
			if !last.IsNil() {
				return nil, last.Interface().(error)
			}
			if len(results) == 2 {
				return results[0].Interface(), nil
			}
			out := make([]any, 0, len(results)-1)
			for _, result := range results[:len(results)-1] {
				out = append(out, result.Interface())
			}
			return out, nil
		}

		out := make([]any, 0, len(results))
		for _, result := range results {
			out = append(out, result.Interface())
		}
		return out, nil
	}
}

type rpcCallRequest struct {
	Name string            `json:"name"`
	Args []json.RawMessage `json:"args"`
}

type rpcCallResponse struct {
	Data any `json:"data"`
}

type apiErrorResponse struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func newAdminServer(rt *appRuntime) *http.Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	registry := newRPCRegistry()
	rt.registerServices(registry)

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	router.GET("/readyz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	registerAdminAuthRoutes(router, rt)

	authRequired := requireAdminSession(rt.adminAuth)

	router.POST("/api/wails/call", authRequired, func(c *gin.Context) {
		var request rpcCallRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, apiErrorResponse{
				Error: apiError{Code: "invalid_request", Message: err.Error()},
			})
			return
		}

		result, err := registry.Call(request.Name, request.Args)
		if err != nil {
			c.JSON(http.StatusInternalServerError, apiErrorResponse{
				Error: apiError{Code: "rpc_error", Message: err.Error()},
			})
			return
		}

		c.JSON(http.StatusOK, rpcCallResponse{Data: result})
	})

	router.GET("/api/wails/events", authRequired, func(c *gin.Context) {
		streamEvents(c, rt.eventHub)
	})

	registerStaticRoutes(router, rt.staticDir)

	return &http.Server{
		Addr:    rt.adminAddr,
		Handler: router,
	}
}

func streamEvents(c *gin.Context, hub *services.EventHub) {
	if hub == nil {
		c.JSON(http.StatusServiceUnavailable, apiErrorResponse{
			Error: apiError{Code: "events_unavailable", Message: "event hub is not initialized"},
		})
		return
	}

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, apiErrorResponse{
			Error: apiError{Code: "stream_unsupported", Message: "streaming is not supported"},
		})
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)

	events, cancel := hub.Subscribe(32)
	defer cancel()

	keepAlive := time.NewTicker(25 * time.Second)
	defer keepAlive.Stop()

	flusher.Flush()

	for {
		select {
		case <-c.Request.Context().Done():
			return
		case <-keepAlive.C:
			_, _ = c.Writer.Write([]byte(": ping\n\n"))
			flusher.Flush()
		case event, ok := <-events:
			if !ok {
				return
			}
			payload, err := json.Marshal(event.Data)
			if err != nil {
				payload = []byte(`{"error":"failed to encode event payload"}`)
			}
			_, _ = fmt.Fprintf(c.Writer, "event: %s\n", event.Name)
			_, _ = fmt.Fprintf(c.Writer, "data: %s\n\n", payload)
			flusher.Flush()
		}
	}
}

func registerStaticRoutes(router *gin.Engine, staticDir string) {
	indexPath := filepath.Join(staticDir, "index.html")
	staticReady := false

	if info, err := os.Stat(indexPath); err == nil && !info.IsDir() {
		staticReady = true
	}

	router.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") || c.Request.URL.Path == "/healthz" || c.Request.URL.Path == "/readyz" {
			c.JSON(http.StatusNotFound, apiErrorResponse{
				Error: apiError{Code: "not_found", Message: "route not found"},
			})
			return
		}

		if !staticReady {
			c.Header("Content-Type", "text/plain; charset=utf-8")
			c.String(http.StatusServiceUnavailable,
				"Frontend build not found at %s.\nRun `cd frontend && npm install && npm run build` before starting the web UI.",
				staticDir,
			)
			return
		}

		relativePath := strings.TrimPrefix(filepath.Clean(c.Request.URL.Path), "/")
		if relativePath != "" && relativePath != "." {
			target := filepath.Join(staticDir, relativePath)
			if info, err := os.Stat(target); err == nil && !info.IsDir() {
				c.File(target)
				return
			}
		}

		c.File(indexPath)
	})
}
