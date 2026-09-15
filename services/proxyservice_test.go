package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daodao97/xgo/xrequest"
	"gopkg.in/yaml.v3"
)

func writeProxyTestReferenceConfigs(t *testing.T, reference string) {
	t.Helper()
	configYAML := []byte("proxies:\n  - name: reference-node\n    type: http\n    server: 127.0.0.1\n    port: 8080\n")
	for _, name := range []string{"xfltd.yaml", "liangxinyun.yaml"} {
		if err := os.WriteFile(filepath.Join(reference, name), configYAML, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProxyCatalogIgnoresReferenceConfigsAndUploadsSharedConfig(t *testing.T) {
	home := t.TempDir()
	reference := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODE_SWITCH_REFERENCE_PROXY_DIR", reference)
	writeProxyTestReferenceConfigs(t, reference)

	catalog, err := NewProxyCatalog()
	if err != nil {
		t.Fatalf("NewProxyCatalog: %v", err)
	}
	configs := catalog.List()
	if len(configs) != 0 {
		t.Fatalf("reference configs must not be materialized: %#v", configs)
	}

	upload := "proxies:\n  - name: Hong Kong 01\n    type: http\n    server: 127.0.0.1\n    port: 8081\n"
	if err := catalog.Upload("my-provider.yaml", upload, "alice"); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	configs = catalog.List()
	var uploaded *ProxyConfigSummary
	for index := range configs {
		if configs[index].Name == "my-provider" {
			uploaded = &configs[index]
		}
	}
	if uploaded == nil || uploaded.ID == "" || uploaded.Uploader != "alice" || uploaded.Nodes[0].Name != "my-provider-Hong Kong 01（来自alice）" {
		t.Fatalf("uploaded config = %#v", uploaded)
	}
	if err := catalog.Upload("my-provider.yml", upload, "bob"); err == nil {
		t.Fatal("duplicate config name was accepted")
	}
}

func TestLoadProxyYAMLRejectsInvalidConfig(t *testing.T) {
	if _, err := loadProxyYAMLFromBytes([]byte("proxy-groups: []\n"), "bad.yaml"); err == nil {
		t.Fatal("config without proxies was accepted")
	}
	if _, err := loadProxyYAMLFromBytes([]byte("proxies:\n  - name: same\n  - name: same\n"), "bad.yaml"); err == nil {
		t.Fatal("duplicate proxy names were accepted")
	}
	if _, err := loadProxyYAMLFromBytes([]byte("proxies:\n  - name: valid\n    type: http\n    server: example.com\n    port: 443\n"), "valid.yaml"); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestProxyCatalogDoesNotRequireProvisionedDefaults(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CODE_SWITCH_REFERENCE_PROXY_DIR", t.TempDir())
	catalog, err := NewProxyCatalog()
	if err != nil {
		t.Fatalf("NewProxyCatalog: %v", err)
	}
	configs := catalog.List()
	if len(configs) != 0 {
		t.Fatalf("unprovisioned defaults should not be materialized: %#v", configs)
	}
}

func TestProxyCatalogLegacyConfigHasNoMutableDisplayNameOwner(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := filepath.Join(home, appSettingsDir, proxyConfigsDirName)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "legacy.yaml"), []byte("proxies:\n  - name: legacy-node\n    type: http\n    server: example.com\n    port: 443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	index, err := json.Marshal(proxyIndex{Version: proxyManagerVersion, Configs: []proxyConfigMetadata{{
		Name: "legacy", FileName: "legacy.yaml", Uploader: "alice",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, proxyIndexFileName), index, 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, err := NewProxyCatalog()
	if err != nil {
		t.Fatal(err)
	}
	configs := catalog.ListForUser("user-alice")
	if len(configs) != 1 || configs[0].IsOwner {
		t.Fatalf("legacy config must not grant ownership by mutable display name: %#v", configs)
	}
	service := &ProxyService{catalog: catalog, manager: NewProxyManager(catalog)}
	if err := service.DeleteProxyConfigForUser("user-alice", configs[0].ID, nil); err == nil || !strings.Contains(err.Error(), "只有上传者") {
		t.Fatalf("legacy config deletion by display-name user error = %v", err)
	}
}

func TestProxyServiceRejectsEnabledPoolProxyWithoutNodes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CODE_SWITCH_REFERENCE_PROXY_DIR", t.TempDir())
	service, err := NewProxyService()
	if err != nil {
		t.Fatalf("NewProxyService: %v", err)
	}

	for _, config := range []*AccountPoolProxyConfig{
		{Enabled: true, Selection: AccountPoolProxySelectionAuto},
		{Enabled: true, Selection: AccountPoolProxySelectionNode, ProxyNodeID: "missing"},
	} {
		if err := service.NormalizePoolProxyConfig(config); err == nil || !strings.Contains(err.Error(), "至少一个有效的代理配置") {
			t.Fatalf("enabled proxy config without nodes error = %v", err)
		}
	}
	if err := service.NormalizePoolProxyConfig(&AccountPoolProxyConfig{Enabled: false, Selection: AccountPoolProxySelectionNone}); err != nil {
		t.Fatalf("disabled proxy config should remain valid: %v", err)
	}
}

func TestRuntimeNodesRewriteIntraConfigProxyReferences(t *testing.T) {
	configs := []proxyConfigMetadata{{Name: "chain", Uploader: "alice"}}
	sources := map[string]proxySource{
		"chain": {Nodes: []map[string]any{
			{"name": "hop", "type": "http", "server": "hop.example", "port": 443},
			{"name": "exit", "type": "http", "server": "exit.example", "port": 443, "dialer-proxy": "hop"},
		}},
	}
	runtime := runtimeNodes(configs, sources)
	if len(runtime) != 2 {
		t.Fatalf("runtime nodes = %#v", runtime)
	}
	hopName, _ := runtime[0]["name"].(string)
	dialer, _ := runtime[1]["dialer-proxy"].(string)
	if hopName == "" || dialer != hopName {
		t.Fatalf("dialer-proxy = %q, want renamed node %q", dialer, hopName)
	}
	if original, _ := sources["chain"].Nodes[1]["dialer-proxy"].(string); original != "hop" {
		t.Fatalf("source configuration was mutated: %q", original)
	}
}

func TestRuntimeNodesWithDialerProxyPassMihomoValidationWhenAvailable(t *testing.T) {
	binary := filepath.Join(referenceProxyDir(), ".runtime", "mihomo-"+mihomoVersion)
	if _, err := os.Stat(binary); err != nil {
		t.Skip("local Mihomo binary is not provisioned")
	}
	configs := []proxyConfigMetadata{{Name: "chain", Uploader: "alice"}}
	sources := map[string]proxySource{
		"chain": {Nodes: []map[string]any{
			{"name": "hop", "type": "http", "server": "hop.example", "port": 443},
			{"name": "exit", "type": "http", "server": "exit.example", "port": 443, "dialer-proxy": "hop"},
		}},
	}
	catalog := &ProxyCatalog{index: proxyIndex{Version: proxyManagerVersion, Configs: configs}, sources: sources}
	manager := NewProxyManager(catalog)
	manager.binary = binary
	manager.workDir = t.TempDir()
	manager.secret = "test-secret"
	control, err := availablePort()
	if err != nil {
		t.Fatal(err)
	}
	manager.control = control
	listenerPort, err := availablePort()
	if err != nil {
		t.Fatal(err)
	}
	manager.listeners["test-listener"] = proxyListener{
		port:       listenerPort,
		proxy:      proxyAutoGroupName,
		listener:   "test-listener",
		generation: 1,
	}
	configPath := filepath.Join(manager.workDir, "config.yaml")
	if err := manager.writeRuntimeConfigLocked(configPath); err != nil {
		t.Fatal(err)
	}
	if err := manager.validateRuntimeConfigLocked(configPath, context.Background()); err != nil {
		t.Fatalf("rewritten chain config failed Mihomo validation: %v", err)
	}
}

func TestRefreshProxyConfigsReloadsRunningMihomo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fake Mihomo validation test requires a POSIX shell")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODE_SWITCH_REFERENCE_PROXY_DIR", t.TempDir())
	catalog, err := NewProxyCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if err := catalog.Upload("shared.yaml", "proxies:\n  - name: node-a\n    type: http\n    server: a.example\n    port: 443\n", "alice"); err != nil {
		t.Fatal(err)
	}

	fakeMihomo := filepath.Join(t.TempDir(), "mihomo")
	if err := os.WriteFile(fakeMihomo, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	reloaded := make(chan struct{}, 1)
	controller := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPut && request.URL.Path == "/configs" {
			select {
			case reloaded <- struct{}{}:
			default:
			}
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer controller.Close()
	hostPort := strings.TrimPrefix(controller.URL, "http://")
	_, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatal(err)
	}
	control, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewProxyManager(catalog)
	manager.binary = fakeMihomo
	manager.workDir = t.TempDir()
	manager.control = control
	manager.secret = "test-secret"
	manager.process = &exec.Cmd{}
	if err := os.WriteFile(filepath.Join(manager.workDir, "config.yaml"), []byte("mode: rule\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := &ProxyService{catalog: catalog, manager: manager}
	if err := os.WriteFile(filepath.Join(catalog.root, "shared.yaml"), []byte("proxies:\n  - name: node-b\n    type: http\n    server: b.example\n    port: 443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := service.RefreshProxyConfigs(); err != nil {
		t.Fatalf("RefreshProxyConfigs: %v", err)
	}
	select {
	case <-reloaded:
	case <-time.After(time.Second):
		t.Fatal("running Mihomo did not receive a config reload")
	}
	configs := catalog.List()
	if len(configs) != 1 || len(configs[0].Nodes) != 1 || configs[0].Nodes[0].OriginalName != "node-b" {
		t.Fatalf("catalog did not reflect refreshed YAML: %#v", configs)
	}
}

func TestProxyCatalogRejectsFutureIndexWithoutBreakingStartup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODE_SWITCH_REFERENCE_PROXY_DIR", t.TempDir())
	root := filepath.Join(home, appSettingsDir, proxyConfigsDirName)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	sharedYAML := []byte("proxies:\n  - name: shared\n    type: http\n    server: example.com\n    port: 80\n")
	if err := os.WriteFile(filepath.Join(root, "shared.yaml"), sharedYAML, 0o600); err != nil {
		t.Fatal(err)
	}
	index, _ := json.Marshal(proxyIndex{Version: proxyManagerVersion + 1, Configs: []proxyConfigMetadata{{
		Name: "shared", FileName: "shared.yaml", Uploader: "alice", UploadedAt: "2030-01-02T03:04:05Z",
	}}})
	if err := os.WriteFile(filepath.Join(root, proxyIndexFileName), index, 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, err := NewProxyCatalog()
	if err != nil {
		t.Fatalf("future index should degrade gracefully: %v", err)
	}
	configs := catalog.List()
	if len(configs) != 1 || configs[0].Name != "shared" || configs[0].Uploader != "alice" {
		t.Fatalf("future index metadata was not preserved: %#v", configs)
	}
	if _, err := os.Stat(filepath.Join(root, "xfltd.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("future index unexpectedly wrote defaults: %v", err)
	}
	if err := catalog.Upload("future-blocked.yaml", "proxies:\n  - name: n\n    type: http\n    server: example.com\n    port: 80\n", "alice"); err == nil {
		t.Fatal("future index accepted a write")
	}
	after, err := os.ReadFile(filepath.Join(root, proxyIndexFileName))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(index) {
		t.Fatal("future index changed while operating in read-only mode")
	}
}

func TestProxyServiceUploadRollsBackWhenMihomoValidationFails(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fake Mihomo validation test requires a POSIX shell")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODE_SWITCH_REFERENCE_PROXY_DIR", t.TempDir())
	fakeMihomo := filepath.Join(t.TempDir(), "mihomo")
	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = "-v" ]; then
  echo "Mihomo Meta %s"
  exit 0
fi
if [ "$1" = "-t" ]; then
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "-f" ]; then
      shift
      if grep -q "reject-runtime" "$1"; then
        echo "rejected by fake Mihomo" >&2
        exit 1
      fi
      exit 0
    fi
    shift
  done
fi
exit 1
`, strings.TrimPrefix(mihomoVersion, "v"))
	if err := os.WriteFile(fakeMihomo, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODE_SWITCH_MIHOMO_BINARY", fakeMihomo)

	service, err := NewProxyService()
	if err != nil {
		t.Fatal(err)
	}
	defer service.Stop()
	upload := "proxies:\n  - name: reject-runtime\n    type: http\n    server: example.com\n    port: 8081\n"
	err = service.UploadProxyConfig("rejected.yaml", upload, "alice")
	if err == nil || !strings.Contains(err.Error(), "Mihomo 配置校验失败") {
		t.Fatalf("upload validation error = %v", err)
	}
	for _, config := range service.ListProxyConfigs() {
		if config.Name == "rejected" {
			t.Fatal("failed upload remained visible in the catalog")
		}
	}
	if _, err := os.Stat(filepath.Join(service.catalog.root, "rejected.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed upload file still exists: %v", err)
	}
}

type proxyTestErrorReadCloser struct {
	err    error
	closed int
}

func (r *proxyTestErrorReadCloser) Read([]byte) (int, error) { return 0, r.err }
func (r *proxyTestErrorReadCloser) Close() error {
	r.closed++
	return nil
}

func TestProxyLeaseBodyPreservesUpstreamReadError(t *testing.T) {
	sentinel := errors.New("read failed")
	reader := &proxyTestErrorReadCloser{err: sentinel}
	releases := 0
	body := &proxyLeaseBody{
		ReadCloser: reader,
		release:    func() { releases++ },
	}
	_, err := body.Read(make([]byte, 1))
	var proxyErr *proxyRequestError
	if errors.As(err, &proxyErr) || !errors.Is(err, sentinel) {
		t.Fatalf("upstream read error = %v", err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if releases != 1 || reader.closed != 2 {
		t.Fatalf("release count = %d, close count = %d", releases, reader.closed)
	}
}

func TestRelayBodyReadersPreserveProxyReadErrors(t *testing.T) {
	tests := []struct {
		name string
		read func(*xrequest.Response) error
	}{
		{
			name: "extract upstream error",
			read: func(response *xrequest.Response) error {
				_, err := extractUpstreamError(response)
				return err
			},
		},
		{
			name: "write OpenAI JSON response",
			read: func(response *xrequest.Response) error {
				return writeOpenAIChatJSONResponse(httptest.NewRecorder(), response, nil)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sentinel := errors.New("proxy body failed")
			releases := 0
			response := xrequest.NewResponse(&http.Response{
				StatusCode: http.StatusBadGateway,
				Header:     make(http.Header),
				Body: &proxyLeaseBody{
					ReadCloser: &proxyTestErrorReadCloser{err: sentinel},
					release:    func() { releases++ },
				},
			})
			err := test.read(response)
			var proxyErr *proxyRequestError
			if errors.As(err, &proxyErr) || !errors.Is(err, sentinel) {
				t.Fatalf("relay read error = %v", err)
			}
			if releases != 1 {
				t.Fatalf("listener release count = %d", releases)
			}
		})
	}
}

type proxyTestRoundTripper func(*http.Request) (*http.Response, error)

func (f proxyTestRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestProxyLeaseClassifiesOnlyLocalListenerErrors(t *testing.T) {
	newTransport := func(err error) *proxyLeaseRoundTripper {
		manager := NewProxyManager(nil)
		manager.listeners["lease"] = proxyListener{generation: 1}
		return &proxyLeaseRoundTripper{
			base: proxyTestRoundTripper(func(*http.Request) (*http.Response, error) {
				return nil, err
			}),
			manager:    manager,
			key:        "lease",
			node:       "node-a",
			generation: 1,
		}
	}
	request := httptest.NewRequest(http.MethodGet, "https://provider.example/v1/models", nil)
	local := &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, Err: errors.New("connection refused")}
	_, err := newTransport(local).RoundTrip(request)
	var proxyErr *proxyRequestError
	if !errors.As(err, &proxyErr) || !errors.Is(err, local) {
		t.Fatalf("local listener error = %v", err)
	}
	upstream := &net.OpError{Op: "read", Net: "tcp", Addr: &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 443}, Err: errors.New("connection reset")}
	_, err = newTransport(upstream).RoundTrip(request)
	if errors.As(err, &proxyErr) || !errors.Is(err, upstream) {
		t.Fatalf("upstream error was misclassified: %v", err)
	}
}

func TestProxyLeasePreservesProxiedUpstreamBadGatewayResponse(t *testing.T) {
	manager := NewProxyManager(nil)
	manager.listeners["lease"] = proxyListener{generation: 1}
	transport := &proxyLeaseRoundTripper{
		base: proxyTestRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("Bad Gateway")),
			}, nil
		}),
		manager:    manager,
		key:        "lease",
		node:       "node-a",
		generation: 1,
	}
	response, err := transport.RoundTrip(httptest.NewRequest(http.MethodGet, "https://provider.example/v1/models", nil))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusBadGateway)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProviderRequestPreservesProxiedUpstreamBadGateway(t *testing.T) {
	manager := NewProxyManager(nil)
	manager.listeners["lease"] = proxyListener{generation: 1}
	requests := 0
	relay := &ProviderRelayService{
		proxyManager: manager,
		httpClient: &http.Client{Transport: &proxyLeaseRoundTripper{
			base: proxyTestRoundTripper(func(*http.Request) (*http.Response, error) {
				requests++
				return &http.Response{
					StatusCode: http.StatusBadGateway,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("Bad Gateway")),
				}, nil
			}),
			manager:    manager,
			key:        "lease",
			node:       "node-a",
			generation: 1,
		}},
	}
	response, err := relay.doProviderRequest(context.Background(), "https://provider.example/v1/responses", make(http.Header), nil, nil)
	if err != nil {
		t.Fatalf("proxied upstream 502 error = %v", err)
	}
	if response == nil || response.StatusCode() != http.StatusBadGateway {
		t.Fatalf("proxied upstream 502 response = %#v", response)
	}
	if requests != 2 {
		t.Fatalf("provider 502 should use normal upstream retry handling, requests = %d", requests)
	}
}

func TestProxyManagerEndpointUsesReplacementListenerState(t *testing.T) {
	manager := NewProxyManager(nil)
	manager.listeners["listener"] = proxyListener{port: 31001, proxy: "old-node", generation: 1}
	// This mirrors startLocked retrying after Mihomo has exited and assigning a
	// new listener port/generation before ProxyURLForPool returns its endpoint.
	manager.listeners["listener"] = proxyListener{port: 31002, proxy: "new-node", generation: 2}
	endpoint, err := manager.endpointForListenerLocked("listener")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.URL != "http://127.0.0.1:31002" || endpoint.Node != "new-node" || endpoint.Generation != 2 {
		t.Fatalf("endpoint uses stale listener state: %#v", endpoint)
	}
}

func TestAutoProxyTargetUsesMihomoURLTestGroup(t *testing.T) {
	catalog := &ProxyCatalog{
		index: proxyIndex{Version: proxyManagerVersion, Configs: []proxyConfigMetadata{{Name: "test", Uploader: "alice"}}},
		sources: map[string]proxySource{"test": {Nodes: []map[string]any{
			{"name": "node-a", "type": "http", "server": "a.example", "port": 443},
			{"name": "node-b", "type": "http", "server": "b.example", "port": 443},
		}}},
	}
	manager := NewProxyManager(catalog)
	target, err := manager.autoProxyTarget()
	if err != nil || target != proxyAutoGroupName {
		t.Fatalf("auto target = %q, err = %v", target, err)
	}
	groups := autoProxyGroupConfig(catalog.runtimeNodes())
	if len(groups) != 1 || groups[0]["name"] != proxyAutoGroupName {
		t.Fatalf("auto group = %#v", groups)
	}
	proxies, ok := groups[0]["proxies"].([]string)
	if !ok || len(proxies) != 2 {
		t.Fatalf("auto group nodes = %#v", groups[0]["proxies"])
	}
	if interval, ok := groups[0]["interval"].(int); !ok || interval != int(proxyAutoProbeInterval.Seconds()) {
		t.Fatalf("auto group interval = %#v, want %d", groups[0]["interval"], int(proxyAutoProbeInterval.Seconds()))
	}
}

type autoProbeController struct {
	t *testing.T

	mu                   sync.Mutex
	groupStatus          int
	groupDelays          map[string]int64
	groupCalls           int
	groupPaths           []string
	groupURLs            []string
	groupDelayPathCalls  int
	proxyDelayCalls      int
	reloadCalls          int
	groupEntered         chan struct{}
	groupRelease         <-chan struct{}
	groupResponseDelay   time.Duration
	proxyResponseDelay   time.Duration
	proxyDelayResults    map[string]proxyDelayResult
	activeProxyDelays    int
	maxActiveProxyDelays int
	proxyDelayEntered    chan struct{}
}

type proxyDelayResult struct {
	status int
	delay  *int64
}

func newAutoProbeController(t *testing.T) (*autoProbeController, int) {
	t.Helper()
	fixture := &autoProbeController{
		t:                 t,
		groupDelays:       make(map[string]int64),
		groupEntered:      make(chan struct{}, 1),
		proxyDelayResults: make(map[string]proxyDelayResult),
		proxyDelayEntered: make(chan struct{}, 1),
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-secret" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case request.Method == http.MethodPut && request.URL.Path == "/configs":
			fixture.mu.Lock()
			fixture.reloadCalls++
			fixture.mu.Unlock()
			writer.WriteHeader(http.StatusNoContent)
			return
		case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/group/") && strings.HasSuffix(request.URL.Path, "/delay"):
			fixture.mu.Lock()
			fixture.groupCalls++
			fixture.groupPaths = append(fixture.groupPaths, request.URL.Path)
			fixture.groupURLs = append(fixture.groupURLs, request.URL.Query().Get("url"))
			status := fixture.groupStatus
			delays := make(map[string]int64, len(fixture.groupDelays))
			for name, delay := range fixture.groupDelays {
				delays[name] = delay
			}
			release := fixture.groupRelease
			responseDelay := fixture.groupResponseDelay
			fixture.mu.Unlock()
			select {
			case fixture.groupEntered <- struct{}{}:
			default:
			}
			if release != nil {
				select {
				case <-release:
				case <-request.Context().Done():
					return
				}
			}
			if !waitAutoProbeControllerDelay(request, responseDelay) {
				return
			}
			if status != 0 && status != http.StatusOK {
				writer.WriteHeader(status)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(writer).Encode(delays); err != nil {
				fixture.t.Errorf("encode group delays: %v", err)
			}
			return
		case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/proxies/"+proxyAutoGroupName+"/delay"):
			fixture.mu.Lock()
			fixture.groupDelayPathCalls++
			fixture.mu.Unlock()
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/proxies/") && strings.HasSuffix(request.URL.Path, "/delay"):
			fixture.mu.Lock()
			fixture.proxyDelayCalls++
			responseDelay := fixture.proxyResponseDelay
			nodeName := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/proxies/"), "/delay")
			response, configured := fixture.proxyDelayResults[nodeName]
			fixture.activeProxyDelays++
			if fixture.activeProxyDelays > fixture.maxActiveProxyDelays {
				fixture.maxActiveProxyDelays = fixture.activeProxyDelays
			}
			fixture.mu.Unlock()
			select {
			case fixture.proxyDelayEntered <- struct{}{}:
			default:
			}
			defer func() {
				fixture.mu.Lock()
				fixture.activeProxyDelays--
				fixture.mu.Unlock()
			}()
			if !waitAutoProbeControllerDelay(request, responseDelay) {
				return
			}
			if configured && response.status != 0 && response.status != http.StatusOK {
				writer.WriteHeader(response.status)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			if !configured {
				defaultDelay := int64(7)
				response.delay = &defaultDelay
			}
			payload := map[string]any{}
			if response.delay != nil {
				payload["delay"] = *response.delay
			}
			if err := json.NewEncoder(writer).Encode(payload); err != nil {
				fixture.t.Errorf("encode proxy delay: %v", err)
			}
			return
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil || host == "" {
		t.Fatalf("controller address %q: %v", server.URL, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, port
}

func waitAutoProbeControllerDelay(request *http.Request, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-request.Context().Done():
		return false
	}
}

func (c *autoProbeController) setGroupResult(status int, delays map[string]int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.groupStatus = status
	c.groupDelays = make(map[string]int64, len(delays))
	for name, delay := range delays {
		c.groupDelays[name] = delay
	}
}

func (c *autoProbeController) setResponseDelays(group, proxy time.Duration) {
	c.mu.Lock()
	c.groupResponseDelay = group
	c.proxyResponseDelay = proxy
	c.mu.Unlock()
}

func (c *autoProbeController) setProxyDelayResults(results map[string]proxyDelayResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.proxyDelayResults = make(map[string]proxyDelayResult, len(results))
	for name, result := range results {
		c.proxyDelayResults[name] = result
	}
}

func (c *autoProbeController) counts() (groups, groupDelayPaths, reloads int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.groupCalls, c.groupDelayPathCalls, c.reloadCalls
}

func (c *autoProbeController) groupProbePaths() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.groupPaths...)
}

func (c *autoProbeController) groupProbeURLs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.groupURLs...)
}

func (c *autoProbeController) proxyDelayCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.proxyDelayCalls
}

func (c *autoProbeController) maxProxyDelayConcurrency() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxActiveProxyDelays
}

func newAutoProbeCatalog(nodes []map[string]any) *ProxyCatalog {
	return &ProxyCatalog{
		index: proxyIndex{Version: proxyManagerVersion, Configs: []proxyConfigMetadata{{
			ID: "test-config", Name: "test", FileName: "test.yaml", Uploader: "alice", UploaderID: "alice-id",
		}}},
		sources: map[string]proxySource{"test": {Nodes: nodes}},
	}
}

func newAutoProbeManager(t *testing.T, catalog *ProxyCatalog, control int) *ProxyManager {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("fake Mihomo runtime test requires a POSIX shell")
	}
	binary := filepath.Join(t.TempDir(), "mihomo")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	manager := NewProxyManager(catalog)
	manager.binary = binary
	manager.workDir = t.TempDir()
	manager.control = control
	manager.secret = "test-secret"
	manager.process = &exec.Cmd{}
	manager.runtimeGeneration = 1
	if err := os.WriteFile(filepath.Join(manager.workDir, "config.yaml"), []byte("mode: rule\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return manager
}

func autoProbeRuntimeNames(catalog *ProxyCatalog) []string {
	nodes := catalog.runtimeNodes()
	names := make([]string, 0, len(nodes))
	for _, node := range nodes {
		name, _ := node["name"].(string)
		names = append(names, name)
	}
	return names
}

func newScopedAutoProbeCatalog() *ProxyCatalog {
	return &ProxyCatalog{
		index: proxyIndex{Version: proxyManagerVersion, Configs: []proxyConfigMetadata{
			{ID: "config-a", Name: "yaml-a", FileName: "yaml-a.yaml", Uploader: "alice", UploaderID: "alice-id"},
			{ID: "config-b", Name: "yaml-b", FileName: "yaml-b.yaml", Uploader: "carol", UploaderID: "carol-id"},
		}},
		sources: map[string]proxySource{
			"yaml-a": {Nodes: []map[string]any{{"name": "a-node", "type": "http", "server": "a.example", "port": 443}}},
			"yaml-b": {Nodes: []map[string]any{{"name": "b-node", "type": "http", "server": "b.example", "port": 443}}},
		},
	}
}

func nodeIDForConfig(t *testing.T, catalog *ProxyCatalog, configName string) string {
	t.Helper()
	for _, config := range catalog.List() {
		if config.Name == configName && len(config.Nodes) == 1 {
			return config.Nodes[0].ID
		}
	}
	t.Fatalf("missing node for config %q", configName)
	return ""
}

func runtimeNameForNode(t *testing.T, catalog *ProxyCatalog, nodeID string) string {
	t.Helper()
	name, ok := catalog.FindNode(nodeID)
	if !ok {
		t.Fatalf("missing runtime node %q", nodeID)
	}
	return name
}

func TestBatchRuntimeConfigOmitsAutoGroupAndAutoListeners(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{{"name": "fixed", "type": "http", "server": "fixed.example", "port": 443}})
	manager := NewProxyManager(catalog)
	manager.control = 19090
	manager.secret = "test-secret"
	nodeName := autoProbeRuntimeNames(catalog)[0]
	manager.listeners["fixed"] = proxyListener{proxy: nodeName, listener: "fixed-listener", port: 19091}
	manager.listeners["auto"] = proxyListener{proxy: proxyAutoGroupName, listener: "auto-listener", port: 19092}
	path := filepath.Join(t.TempDir(), "batch.yaml")
	if err := manager.writeRuntimeConfigWithAutoGroupLocked(path, false); err != nil {
		t.Fatalf("write batch runtime config: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		ProxyGroups []map[string]any `yaml:"proxy-groups"`
		Listeners   []map[string]any `yaml:"listeners"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.ProxyGroups) != 0 {
		t.Fatalf("batch config unexpectedly contains auto group: %#v", config.ProxyGroups)
	}
	if len(config.Listeners) != 1 || config.Listeners[0]["name"] != "fixed-listener" || config.Listeners[0]["proxy"] != nodeName {
		t.Fatalf("batch listeners = %#v", config.Listeners)
	}
}

func TestAutoRequestReloadsGroupAfterBatchOnlyRuntime(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{{"name": "first", "type": "http", "server": "first.example", "port": 443}})
	fixture, control := newAutoProbeController(t)
	names := autoProbeRuntimeNames(catalog)
	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 9})
	manager := newAutoProbeManager(t, catalog, control)
	manager.runtimeHasAutoGroup = false
	manager.listeners["old-auto"] = proxyListener{
		poolID: "pool", port: 19100, proxy: proxyAutoGroupName, listener: "old-auto", generation: 1,
	}
	manager.poolListeners["pool"] = "old-auto"

	endpoint, err := manager.ProxyURLForPool(context.Background(), "pool", &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto})
	if err != nil || endpoint.Node != proxyAutoGroupName {
		t.Fatalf("auto endpoint after batch runtime = %#v, err = %v", endpoint, err)
	}
	manager.mu.Lock()
	hasAutoGroup := manager.runtimeHasAutoGroup
	manager.mu.Unlock()
	if !hasAutoGroup {
		t.Fatal("auto request did not restore the url-test group")
	}
	if _, _, reloads := fixture.counts(); reloads != 1 {
		t.Fatalf("auto request reloads = %d, want 1", reloads)
	}
}

func TestFirstAutoRequestInvalidatesConcurrentBatchResult(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{{"name": "first", "type": "http", "server": "first.example", "port": 443}})
	fixture, control := newAutoProbeController(t)
	names := autoProbeRuntimeNames(catalog)
	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 9})
	fixture.setResponseDelays(0, 100*time.Millisecond)
	manager := newAutoProbeManager(t, catalog, control)
	manager.runtimeHasAutoGroup = false
	target := proxyLatencyTarget{nodeID: "first-id", runtimeName: names[0]}
	batchResults := make(chan []ProxyNodeLatencyResult, 1)
	go func() {
		batchResults <- manager.TestNodeLatencies(context.Background(), []proxyLatencyTarget{target})
	}()
	select {
	case <-fixture.proxyDelayEntered:
	case <-time.After(time.Second):
		t.Fatal("batch delay request did not start")
	}
	endpoint, err := manager.ProxyURLForPool(context.Background(), "auto-pool", &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto})
	if err != nil || endpoint.Node != proxyAutoGroupName {
		t.Fatalf("first auto endpoint = %#v, err = %v", endpoint, err)
	}
	select {
	case results := <-batchResults:
		if len(results) != 1 || results[0].Tested || results[0].LatencyMs != nil || results[0].Error != "代理运行配置已刷新，请重新测速" {
			t.Fatalf("batch result after auto reload = %#v", results)
		}
	case <-time.After(time.Second):
		t.Fatal("batch result did not finish after auto reload")
	}
	manager.mu.Lock()
	hasAutoGroup := manager.runtimeHasAutoGroup
	manager.mu.Unlock()
	if !hasAutoGroup {
		t.Fatal("first auto request did not install url-test group")
	}
}

func TestFixedRequestReusesBatchOnlyRuntimeWithoutAutoReload(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{{"name": "fixed", "type": "http", "server": "fixed.example", "port": 443}})
	fixture, control := newAutoProbeController(t)
	manager := newAutoProbeManager(t, catalog, control)
	manager.runtimeHasAutoGroup = false
	configs := catalog.ListForUser("alice-id")
	nodeID := configs[0].Nodes[0].ID
	nodeName := autoProbeRuntimeNames(catalog)[0]
	manager.listeners["fixed-listener"] = proxyListener{
		poolID: "fixed-pool", port: 19101, proxy: nodeName, listener: "fixed-listener", generation: 1,
	}
	manager.poolListeners["fixed-pool"] = "fixed-listener"

	endpoint, err := manager.ProxyURLForPool(context.Background(), "fixed-pool", &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionNode, ProxyNodeID: nodeID})
	if err != nil || endpoint.Node != nodeName {
		t.Fatalf("fixed endpoint = %#v, err = %v", endpoint, err)
	}
	if _, _, reloads := fixture.counts(); reloads != 0 {
		t.Fatalf("fixed request reloaded batch runtime %d times", reloads)
	}
	manager.mu.Lock()
	hasAutoGroup := manager.runtimeHasAutoGroup
	manager.mu.Unlock()
	if hasAutoGroup {
		t.Fatal("fixed request unexpectedly installed auto group")
	}
}

func TestEnsureMihomoBinaryContextCancelsHungVersionProbe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell test requires POSIX")
	}
	binary := filepath.Join(t.TempDir(), "mihomo")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexec sleep 5\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODE_SWITCH_MIHOMO_BINARY", binary)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := ensureMihomoBinaryContext(ctx, t.TempDir())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("context-canceled binary validation error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("context-canceled binary validation took %s", elapsed)
	}
}

func TestProxyServiceTestAllProxyLatenciesUsesVisibleStableNodesWithoutListenerReload(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	catalog := &ProxyCatalog{
		index: proxyIndex{Version: proxyManagerVersion, Configs: []proxyConfigMetadata{
			{ID: "visible-config", Name: "visible", FileName: "visible.yaml", Uploader: "alice", UploaderID: "alice-id"},
			{ID: "hidden-config", Name: "hidden", FileName: "hidden.yaml", Uploader: "bob", UploaderID: "bob-id"},
		}},
		sources: map[string]proxySource{
			"visible": {Nodes: []map[string]any{
				{"name": "same-name", "type": "http", "server": "first.example", "port": 443},
				{"name": "partial-failure", "type": "http", "server": "second.example", "port": 443},
			}},
			"hidden": {Nodes: []map[string]any{
				{"name": "same-name", "type": "http", "server": "hidden.example", "port": 443},
			}},
		},
	}
	fixture, control := newAutoProbeController(t)
	manager := newAutoProbeManager(t, catalog, control)
	service := &ProxyService{catalog: catalog, manager: manager}
	configs := catalog.ListForUser("alice-id")
	if len(configs) != 2 || len(configs[0].Nodes) != 2 || len(configs[1].Nodes) != 1 {
		t.Fatalf("catalog summaries = %#v", configs)
	}
	if err := setProxyConfigHidden("alice-id", configs[1].ID, true); err != nil {
		t.Fatalf("setProxyConfigHidden: %v", err)
	}
	catalog.mu.RLock()
	runtimeNames := catalog.runtimeNodeNamesLocked()
	catalog.mu.RUnlock()
	visibleFirst := runtimeNames[configs[0].Nodes[0].ID]
	visibleSecond := runtimeNames[configs[0].Nodes[1].ID]
	hidden := runtimeNames[configs[1].Nodes[0].ID]
	delay := int64(13)
	hiddenDelay := int64(1)
	fixture.setProxyDelayResults(map[string]proxyDelayResult{
		visibleFirst:  {delay: &delay},
		visibleSecond: {status: http.StatusServiceUnavailable},
		hidden:        {delay: &hiddenDelay},
	})

	results, err := service.TestAllProxyLatenciesForUser(context.Background(), "alice-id")
	if err != nil {
		t.Fatalf("TestAllProxyLatenciesForUser: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("result count = %d, want only two visible nodes: %#v", len(results), results)
	}
	if results[0].NodeID != configs[0].Nodes[0].ID || !results[0].Tested || results[0].LatencyMs == nil || *results[0].LatencyMs != delay || results[0].Error != "" {
		t.Fatalf("first stable-ID result = %#v", results[0])
	}
	if results[1].NodeID != configs[0].Nodes[1].ID || !results[1].Tested || results[1].LatencyMs != nil || !strings.Contains(results[1].Error, "HTTP 503") {
		t.Fatalf("partial-failure result = %#v", results[1])
	}
	if calls := fixture.proxyDelayCount(); calls != 2 {
		t.Fatalf("controller measured %d nodes, want only visible nodes", calls)
	}
	if _, _, reloads := fixture.counts(); reloads != 0 {
		t.Fatalf("batch test reloaded Mihomo %d times", reloads)
	}
	manager.mu.Lock()
	listenerCount := len(manager.listeners)
	listeners := make(map[string]proxyListener, listenerCount)
	for key, listener := range manager.listeners {
		listeners[key] = listener
	}
	manager.mu.Unlock()
	if listenerCount != 0 {
		t.Fatalf("batch test created listeners: %#v", listeners)
	}
}

func TestProxyManagerTestNodeLatenciesReportsTimeoutForEachUnfinishedNode(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{
		{"name": "first", "type": "http", "server": "first.example", "port": 443},
		{"name": "second", "type": "http", "server": "second.example", "port": 443},
	})
	fixture, control := newAutoProbeController(t)
	fixture.setResponseDelays(0, 100*time.Millisecond)
	manager := newAutoProbeManager(t, catalog, control)
	names := autoProbeRuntimeNames(catalog)
	targets := []proxyLatencyTarget{{nodeID: "first-id", runtimeName: names[0]}, {nodeID: "second-id", runtimeName: names[1]}}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	results := manager.TestNodeLatencies(ctx, targets)
	if len(results) != len(targets) {
		t.Fatalf("result count = %d", len(results))
	}
	for index, result := range results {
		if result.NodeID != targets[index].nodeID || !result.Tested || result.LatencyMs != nil || result.Error != "测速超时" {
			t.Fatalf("timeout result %d = %#v", index, result)
		}
	}
}

func TestProxyManagerTestNodeLatenciesLeavesStartupFailureUntested(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{{"name": "first", "type": "http", "server": "first.example", "port": 443}})
	manager := NewProxyManager(catalog)
	manager.closed = true
	results := manager.TestNodeLatencies(context.Background(), []proxyLatencyTarget{{nodeID: "first-id", runtimeName: autoProbeRuntimeNames(catalog)[0]}})
	if len(results) != 1 || results[0].Tested || results[0].LatencyMs != nil || results[0].Error != "代理测速服务不可用" {
		t.Fatalf("startup-failure result = %#v", results)
	}
}

func TestProxyManagerTestNodeLatenciesMarksQueuedNodesAsNotTested(t *testing.T) {
	nodes := make([]map[string]any, 0, 9)
	for index := 0; index < 9; index++ {
		nodes = append(nodes, map[string]any{"name": fmt.Sprintf("node-%d", index), "type": "http", "server": fmt.Sprintf("node-%d.example", index), "port": 443})
	}
	catalog := newAutoProbeCatalog(nodes)
	fixture, control := newAutoProbeController(t)
	fixture.setResponseDelays(0, 100*time.Millisecond)
	manager := newAutoProbeManager(t, catalog, control)
	manager.batchTestTimeout = 25 * time.Millisecond
	names := autoProbeRuntimeNames(catalog)
	targets := make([]proxyLatencyTarget, len(names))
	for index, name := range names {
		targets[index] = proxyLatencyTarget{nodeID: fmt.Sprintf("id-%d", index), runtimeName: name}
	}

	results := manager.TestNodeLatencies(context.Background(), targets)
	timedOut, notTested := 0, 0
	for index, result := range results {
		switch result.Error {
		case "测速超时":
			if !result.Tested {
				t.Fatalf("timed-out started result %d was not marked tested: %#v", index, result)
			}
			timedOut++
		case "未测速（批量测速总时限已到）":
			if result.Tested {
				t.Fatalf("queued result %d was incorrectly marked tested: %#v", index, result)
			}
			notTested++
		default:
			t.Fatalf("queued result %d = %#v", index, result)
		}
	}
	if timedOut != cap(manager.testSem) || notTested != len(targets)-cap(manager.testSem) {
		t.Fatalf("batch statuses timedOut=%d notTested=%d", timedOut, notTested)
	}
	if calls := fixture.proxyDelayCount(); calls != cap(manager.testSem) {
		t.Fatalf("controller calls = %d, want %d started probes", calls, cap(manager.testSem))
	}
}

func TestProxyManagerTestNodeLatenciesRejectsResultAfterRuntimeRefresh(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{{"name": "first", "type": "http", "server": "first.example", "port": 443}})
	fixture, control := newAutoProbeController(t)
	fixture.setResponseDelays(0, 100*time.Millisecond)
	manager := newAutoProbeManager(t, catalog, control)
	target := proxyLatencyTarget{nodeID: "first-id", runtimeName: autoProbeRuntimeNames(catalog)[0]}
	resultCh := make(chan []ProxyNodeLatencyResult, 1)
	go func() {
		resultCh <- manager.TestNodeLatencies(context.Background(), []proxyLatencyTarget{target})
	}()
	select {
	case <-fixture.proxyDelayEntered:
	case <-time.After(time.Second):
		t.Fatal("batch controller request did not start")
	}
	manager.mu.Lock()
	manager.advanceRuntimeGenerationLocked()
	manager.mu.Unlock()
	select {
	case results := <-resultCh:
		if len(results) != 1 || results[0].Tested || results[0].LatencyMs != nil || results[0].Error != "代理运行配置已刷新，请重新测速" {
			t.Fatalf("refreshed batch result = %#v", results)
		}
	case <-time.After(time.Second):
		t.Fatal("batch request did not finish after runtime refresh")
	}
}

func TestProxyManagerTestNodeLatenciesRejectsReuploadedStableIdentity(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{{"name": "same-name", "type": "http", "server": "old.example", "port": 443}})
	visible := catalog.ListForUser("alice-id")
	targets := catalog.latencyTargetsForConfigs(visible)
	if len(targets) != 1 || targets[0].catalogKey == "" {
		t.Fatalf("captured targets = %#v", targets)
	}
	fixture, control := newAutoProbeController(t)
	manager := newAutoProbeManager(t, catalog, control)

	// A delete/re-upload can preserve the human/runtime name while issuing a
	// new immutable config/node ID. The old target must never measure it.
	catalog.mu.Lock()
	catalog.index.Configs[0].ID = "replacement-config"
	catalog.mu.Unlock()
	results := manager.TestNodeLatencies(context.Background(), targets)
	if len(results) != 1 || results[0].Tested || results[0].LatencyMs != nil || results[0].Error != "代理运行配置已刷新，请重新测速" {
		t.Fatalf("replacement result = %#v", results)
	}
	if calls := fixture.proxyDelayCount(); calls != 0 {
		t.Fatalf("replacement issued %d controller probes", calls)
	}
}

func TestProxyManagerTestNodeLatenciesRejectsMissingZeroAndNegativeDelays(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{
		{"name": "missing", "type": "http", "server": "missing.example", "port": 443},
		{"name": "zero", "type": "http", "server": "zero.example", "port": 443},
		{"name": "negative", "type": "http", "server": "negative.example", "port": 443},
	})
	fixture, control := newAutoProbeController(t)
	manager := newAutoProbeManager(t, catalog, control)
	names := autoProbeRuntimeNames(catalog)
	zero := int64(0)
	negative := int64(-1)
	fixture.setProxyDelayResults(map[string]proxyDelayResult{
		names[0]: {},
		names[1]: {delay: &zero},
		names[2]: {delay: &negative},
	})

	results := manager.TestNodeLatencies(context.Background(), []proxyLatencyTarget{
		{nodeID: "missing-id", runtimeName: names[0]},
		{nodeID: "zero-id", runtimeName: names[1]},
		{nodeID: "negative-id", runtimeName: names[2]},
	})
	for index, result := range results {
		if !result.Tested || result.LatencyMs != nil || result.Error != "代理延时无效" {
			t.Fatalf("invalid-delay result %d = %#v", index, result)
		}
	}
}

func TestProxyServiceTestAllProxyLatenciesEmptyCatalogDoesNotStartRuntime(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	catalog := &ProxyCatalog{index: proxyIndex{Version: proxyManagerVersion}, sources: make(map[string]proxySource)}
	manager := NewProxyManager(catalog)
	service := &ProxyService{catalog: catalog, manager: manager}
	results, err := service.TestAllProxyLatenciesForUser(context.Background(), "user-id")
	if err != nil || len(results) != 0 {
		t.Fatalf("empty catalog results = %#v, err = %v", results, err)
	}
	manager.mu.Lock()
	started := manager.process != nil
	manager.mu.Unlock()
	if started {
		t.Fatal("empty catalog started Mihomo")
	}
}

func TestProxyManagerTestNodeLatenciesUsesGlobalConcurrencyLimit(t *testing.T) {
	nodes := make([]map[string]any, 0, 9)
	for index := 0; index < 9; index++ {
		nodes = append(nodes, map[string]any{"name": fmt.Sprintf("node-%d", index), "type": "http", "server": fmt.Sprintf("node-%d.example", index), "port": 443})
	}
	catalog := newAutoProbeCatalog(nodes)
	fixture, control := newAutoProbeController(t)
	fixture.setResponseDelays(0, 20*time.Millisecond)
	manager := newAutoProbeManager(t, catalog, control)
	names := autoProbeRuntimeNames(catalog)
	targets := make([]proxyLatencyTarget, len(names))
	for index, name := range names {
		targets[index] = proxyLatencyTarget{nodeID: fmt.Sprintf("id-%d", index), runtimeName: name}
	}

	results := manager.TestNodeLatencies(context.Background(), targets)
	for index, result := range results {
		if !result.Tested || result.LatencyMs == nil || result.Error != "" {
			t.Fatalf("concurrent result %d = %#v", index, result)
		}
	}
	if max := fixture.maxProxyDelayConcurrency(); max > cap(manager.testSem) || max < 1 {
		t.Fatalf("controller concurrency = %d, want 1..%d", max, cap(manager.testSem))
	}
}

func TestAutoProxyUsesSuccessfulMihomoGroupProbe(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{
		{"name": "first", "type": "http", "server": "first.example", "port": 443},
		{"name": "second", "type": "http", "server": "second.example", "port": 443},
		{"name": "third", "type": "http", "server": "third.example", "port": 443},
	})
	fixture, control := newAutoProbeController(t)
	names := autoProbeRuntimeNames(catalog)
	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 0, names[1]: 17, names[2]: 17, "unknown": 1})
	manager := newAutoProbeManager(t, catalog, control)

	endpoint, err := manager.ProxyURLForPool(context.Background(), "pool", &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Node != proxyAutoGroupName {
		t.Fatalf("auto endpoint target = %q, want native group %q", endpoint.Node, proxyAutoGroupName)
	}
	manager.mu.Lock()
	selection := manager.autoSelection
	_, listener, ok := manager.currentListenerLocked("pool")
	manager.mu.Unlock()
	if !ok || listener.proxy != proxyAutoGroupName {
		t.Fatalf("published listener = %#v, ok = %v", listener, ok)
	}
	if selection.node != names[1] || selection.delay != 17 {
		t.Fatalf("auto selection = %#v, want second successful tie winner", selection)
	}
	groups, groupDelayPaths, _ := fixture.counts()
	if groups != 1 || groupDelayPaths != 0 {
		t.Fatalf("controller calls: group=%d group-proxy-delay=%d", groups, groupDelayPaths)
	}
}

func TestScopedAutoGroupsEnforcePerUserVisibility(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	catalog := newScopedAutoProbeCatalog()
	fixture, control := newAutoProbeController(t)
	manager := newAutoProbeManager(t, catalog, control)
	service := &ProxyService{catalog: catalog, manager: manager}
	aNodeID := nodeIDForConfig(t, catalog, "yaml-a")
	bNodeID := nodeIDForConfig(t, catalog, "yaml-b")
	aRuntime := runtimeNameForNode(t, catalog, aNodeID)
	bRuntime := runtimeNameForNode(t, catalog, bNodeID)
	fixture.setGroupResult(http.StatusOK, map[string]int64{aRuntime: 10, bRuntime: 5})
	auto := &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto}

	if _, err := service.ProxyURLForPool(context.Background(), "alice-id", "alice-pool", auto); err != nil {
		t.Fatalf("alice scoped auto route: %v", err)
	}
	if _, err := service.ProxyURLForPool(context.Background(), "bob-id", "bob-pool", auto); err != nil {
		t.Fatalf("bob scoped auto route before hide: %v", err)
	}
	if err := service.HideProxyConfigForUser("bob-id", "config-a"); err != nil {
		t.Fatalf("bob hide yaml-a: %v", err)
	}

	manager.mu.Lock()
	aliceGroup, aliceOK := manager.scopedAutoGroups[proxyPoolKey("alice-id", "alice-pool")]
	bobGroup, bobOK := manager.scopedAutoGroups[proxyPoolKey("bob-id", "bob-pool")]
	legacyGroupPresent := false
	for name := range manager.runtimeAutoGroups {
		if name == proxyAutoGroupName {
			legacyGroupPresent = true
		}
	}
	manager.mu.Unlock()
	if !aliceOK || !bobOK {
		t.Fatalf("scoped groups missing: alice=%v bob=%v", aliceOK, bobOK)
	}
	if aliceGroup.name == bobGroup.name || strings.Contains(bobGroup.name, "bob") {
		t.Fatalf("scoped group names must be distinct and opaque: alice=%q bob=%q", aliceGroup.name, bobGroup.name)
	}
	if len(aliceGroup.nodes) != 2 || aliceGroup.nodes[0] != aRuntime || aliceGroup.nodes[1] != bRuntime {
		t.Fatalf("alice scoped group members = %#v", aliceGroup.nodes)
	}
	if len(bobGroup.nodes) != 1 || bobGroup.nodes[0] != bRuntime {
		t.Fatalf("bob scoped group members after hide = %#v, want only %q", bobGroup.nodes, bRuntime)
	}
	if legacyGroupPresent {
		t.Fatal("scoped runtime retained the global auto group containing hidden nodes")
	}
	if _, err := service.ProxyURLForPool(context.Background(), "bob-id", "bob-pool", auto); err != nil {
		t.Fatalf("bob scoped auto route after hide: %v", err)
	}
	paths := fixture.groupProbePaths()
	if len(paths) == 0 || paths[len(paths)-1] != "/group/"+bobGroup.name+"/delay" {
		t.Fatalf("last controller probe path = %#v, want bob group %q", paths, bobGroup.name)
	}
	if _, err := service.ProxyURLForPool(context.Background(), "bob-id", "bob-pool", &AccountPoolProxyConfig{
		Enabled: true, Selection: AccountPoolProxySelectionNode, ProxyNodeID: aNodeID,
	}); err == nil || !strings.Contains(err.Error(), "隐藏") {
		t.Fatalf("hidden fixed node route error = %v", err)
	}
	result := service.TestProxyForUser(context.Background(), "bob-id", "bob-pool", aNodeID, "https://8.8.8.8/", "")
	if !strings.Contains(result.ProxyError, "隐藏") {
		t.Fatalf("hidden fixed node speed test = %#v", result)
	}
	testCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = service.TestProxyForUser(testCtx, "bob-id", "bob-pool", "", "https://8.8.8.8/", "")
	paths = fixture.groupProbePaths()
	if len(paths) == 0 || paths[len(paths)-1] != "/group/"+bobGroup.name+"/delay" {
		t.Fatalf("bob auto speed test probe paths = %#v", paths)
	}
}

func TestScopedAutoUsesPoolBaseURLAndSharedSpeedCache(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	catalog := newScopedAutoProbeCatalog()
	fixture, control := newAutoProbeController(t)
	manager := newAutoProbeManager(t, catalog, control)
	store, err := newProxySpeedTestStore(filepath.Join(t.TempDir(), "speed-tests.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager.speedTests = store
	service := &ProxyService{catalog: catalog, manager: manager, speedTests: store}

	baseURL := "https://upstream.example/v1"
	aNodeID := nodeIDForConfig(t, catalog, "yaml-a")
	bNodeID := nodeIDForConfig(t, catalog, "yaml-b")
	slow := int64(40)
	fast := int64(9)
	store.record(normalizeScopedAutoTestURL(baseURL), aNodeID, ProxyNodeLatencyResult{ProxiedBaseURLMs: &slow})
	store.record(normalizeScopedAutoTestURL(baseURL), bNodeID, ProxyNodeLatencyResult{ProxiedBaseURLMs: &fast})

	auto := &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto}
	if _, err := service.ProxyURLForPoolWithBaseURL(context.Background(), "alice-id", "pool", auto, baseURL); err != nil {
		t.Fatalf("scoped auto route: %v", err)
	}
	manager.mu.Lock()
	group := manager.scopedAutoGroups[proxyPoolKey("alice-id", "pool")]
	selection := manager.scopedAutoStates[group.name].selection
	configs := manager.scopedAutoProxyGroupConfigsLocked()
	manager.mu.Unlock()
	if group.testURL != baseURL {
		t.Fatalf("group test URL = %q, want %q", group.testURL, baseURL)
	}
	if selection.node != runtimeNameForNode(t, catalog, bNodeID) || selection.delay != fast {
		t.Fatalf("cached selection = %#v, want fastest shared result", selection)
	}
	if len(configs) != 1 || configs[0]["url"] != baseURL {
		t.Fatalf("Mihomo group config = %#v, want base URL", configs)
	}
	if calls, _, _ := fixture.counts(); calls != 0 {
		t.Fatalf("cached route made %d live group probes", calls)
	}

	fixture.setGroupResult(http.StatusOK, map[string]int64{
		runtimeNameForNode(t, catalog, aNodeID): slow,
		runtimeNameForNode(t, catalog, bNodeID): fast,
	})
	if _, err := manager.scopedAutoSelectionForRuntime(context.Background(), group, true); err != nil {
		t.Fatalf("automatic refresh: %v", err)
	}
	urls := fixture.groupProbeURLs()
	if len(urls) != 1 || urls[0] != baseURL {
		t.Fatalf("automatic probe URLs = %#v, want %q", urls, baseURL)
	}
}

func TestProxyServiceCanceledNodeTestDoesNotPersistSpeedResult(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	catalog := newScopedAutoProbeCatalog()
	_, control := newAutoProbeController(t)
	manager := newAutoProbeManager(t, catalog, control)
	store, err := newProxySpeedTestStore(filepath.Join(t.TempDir(), "speed-tests.json"))
	if err != nil {
		t.Fatal(err)
	}
	service := &ProxyService{catalog: catalog, manager: manager, speedTests: store}
	baseURL := "https://8.8.8.8/"
	nodeID := nodeIDForConfig(t, catalog, "yaml-a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_ = service.TestProxyForUser(ctx, "alice-id", "pool", nodeID, baseURL, "")

	snapshot := store.snapshot(normalizeScopedAutoTestURL(baseURL), map[string]struct{}{nodeID: {}})
	if len(snapshot.Results) != 0 {
		t.Fatalf("canceled speed test persisted results: %#v", snapshot.Results)
	}
}

func TestMeasureResponsesEndpointPostsWithoutCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/responses" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		if got := request.Header.Get("Authorization"); got != "Bearer code-switch-connectivity-probe-invalid" {
			t.Fatalf("probe authorization = %q", got)
		}
		if got := request.Header.Get("Accept"); got != "text/event-stream" {
			t.Fatalf("probe accept = %q", got)
		}
		if got := request.Header.Get("Accept-Encoding"); got != "identity" {
			t.Fatalf("probe accept encoding = %q", got)
		}
		if got := request.Header.Get("User-Agent"); got != "codex-cli/1.0" {
			t.Fatalf("probe user agent = %q", got)
		}
		if got := request.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
			t.Fatalf("probe content type = %q", got)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != `{"model":"gpt-5-codex","input":[{"role":"user","content":[{"type":"input_text","text":"ping"}]}],"stream":true}` {
			t.Fatalf("unexpected probe body: %s", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"error":"missing API key"}`))
	}))
	defer server.Close()

	targetURL, err := url.Parse(server.URL + "/v1/responses")
	if err != nil {
		t.Fatal(err)
	}
	target := resolvedProxyTestTarget{url: targetURL, hostHeader: targetURL.Host, serverName: targetURL.Hostname()}
	latency, status, probeErr, cloudflareBlocked := measureResponsesEndpoint(context.Background(), target, "")
	if latency == nil || *latency < 0 || status != http.StatusUnauthorized || probeErr != "" || cloudflareBlocked {
		t.Fatalf("probe result = latency=%v status=%d error=%q cloudflare=%v", latency, status, probeErr, cloudflareBlocked)
	}
}

// TestMeasureChatEndpointPostsChatProbeBody verifies a chat account pool is
// probed with a Chat Completions payload and a non-codex user agent, so the
// latency test measures the same protocol the pool actually serves.
func TestMeasureChatEndpointPostsChatProbeBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/chat/completions" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		if got := request.Header.Get("Authorization"); got != "Bearer code-switch-connectivity-probe-invalid" {
			t.Fatalf("chat probe authorization = %q", got)
		}
		if got := request.Header.Get("User-Agent"); got != "openai-python/1.0" {
			t.Fatalf("chat probe user agent = %q", got)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"ping"}],"stream":true}` {
			t.Fatalf("unexpected chat probe body: %s", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"error":"missing API key"}`))
	}))
	defer server.Close()

	targetURL, err := url.Parse(server.URL + "/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	target := resolvedProxyTestTarget{url: targetURL, hostHeader: targetURL.Host, serverName: targetURL.Hostname()}
	latency, status, probeErr, cloudflareBlocked := measureResponsesEndpoint(context.Background(), target, "")
	if latency == nil || *latency < 0 || status != http.StatusUnauthorized || probeErr != "" || cloudflareBlocked {
		t.Fatalf("chat probe result = latency=%v status=%d error=%q cloudflare=%v", latency, status, probeErr, cloudflareBlocked)
	}
}

func TestMeasureResponsesEndpointMarksCloudflareForbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Server", "cloudflare")
		writer.Header().Set("Content-Type", "text/html")
		writer.WriteHeader(http.StatusForbidden)
		_, _ = writer.Write([]byte("<html>Cloudflare</html>"))
	}))
	defer server.Close()

	targetURL, err := url.Parse(server.URL + "/v1/responses")
	if err != nil {
		t.Fatal(err)
	}
	target := resolvedProxyTestTarget{url: targetURL, hostHeader: targetURL.Host, serverName: targetURL.Hostname()}
	latency, status, probeErr, cloudflareBlocked := measureResponsesEndpoint(context.Background(), target, "")
	if latency != nil || status != http.StatusForbidden || !cloudflareBlocked || !strings.Contains(probeErr, "Cloudflare") {
		t.Fatalf("probe result = latency=%v status=%d error=%q cloudflare=%v", latency, status, probeErr, cloudflareBlocked)
	}
}

func TestProxySpeedTestStoreClearsPreCodexProbeMeasurements(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprintf("version-%d", version), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "speed-tests.json")
			legacy := []byte(fmt.Sprintf(`{"version":%d,"targets":{"https://upstream.example/v1":{"testedAt":"2026-01-01T00:00:00Z","results":[{"nodeId":"node-a","tested":true,"proxiedBaseUrlMs":12}]}}}`, version))
			if err := os.WriteFile(path, legacy, 0o600); err != nil {
				t.Fatal(err)
			}

			store, err := newProxySpeedTestStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if store.data.Version != proxySpeedTestsVersion || len(store.data.Targets) != 0 {
				t.Fatalf("migrated speed-test store = %#v", store.data)
			}
		})
	}
}

func TestRecordResponsesCloudflareBlockRemovesNodeFromAutoSelection(t *testing.T) {
	catalog := newScopedAutoProbeCatalog()
	store, err := newProxySpeedTestStore(filepath.Join(t.TempDir(), "speed-tests.json"))
	if err != nil {
		t.Fatal(err)
	}
	service := &ProxyService{catalog: catalog, speedTests: store}
	nodeID := nodeIDForConfig(t, catalog, "yaml-a")
	runtimeNode := runtimeNameForNode(t, catalog, nodeID)
	responsesURL := "https://upstream.example/v1/responses"
	baseURL := "https://upstream.example/v1"
	fast := int64(12)
	store.record(normalizeScopedAutoTestURL(baseURL), nodeID, ProxyNodeLatencyResult{ProxiedBaseURLMs: &fast})

	service.RecordResponsesCloudflareBlock(runtimeNode, responsesURL, baseURL)

	visible := map[string]struct{}{nodeID: {}}
	responses := store.snapshot(normalizeScopedAutoTestURL(responsesURL), visible)
	if len(responses.Results) != 1 || !responses.Results[0].ResponsesCloudflareBlocked || responses.Results[0].ResponsesStatus != http.StatusForbidden {
		t.Fatalf("responses block result = %#v", responses.Results)
	}
	selection := store.snapshot(normalizeScopedAutoTestURL(baseURL), visible)
	if len(selection.Results) != 1 || selection.Results[0].ProxiedBaseURLMs != nil || !strings.Contains(selection.Results[0].ProxiedBaseURLError, "Cloudflare") {
		t.Fatalf("auto-selection block result = %#v", selection.Results)
	}
}

func TestCloudflareBlockedHeaders(t *testing.T) {
	header := make(http.Header)
	header.Set("CF-Ray", "test")
	response := &http.Response{StatusCode: http.StatusForbidden, Header: header}
	if !cloudflareBlockedHeaders(response) {
		t.Fatal("Cloudflare headers were not recognized")
	}
}

func TestCloudflareBlockedHTMLPreservesResponseBody(t *testing.T) {
	body := "<html>Cloudflare challenge</html>"
	response := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	if !cloudflareBlockedResponse(response) {
		t.Fatal("Cloudflare HTML was not recognized")
	}
	restored, err := io.ReadAll(response.Body)
	if err != nil || string(restored) != body {
		t.Fatalf("restored body = %q, err = %v", restored, err)
	}
}

func TestCatalogMutationsRebuildActiveScopedAutoGroups(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fake Mihomo runtime test requires a POSIX shell")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODE_SWITCH_REFERENCE_PROXY_DIR", t.TempDir())
	fakeMihomo := filepath.Join(t.TempDir(), "mihomo")
	if err := os.WriteFile(fakeMihomo, []byte("#!/bin/sh\nif [ \"$1\" = \"-v\" ]; then echo 'Mihomo Meta v1.19.28'; fi\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODE_SWITCH_MIHOMO_BINARY", fakeMihomo)
	service, err := NewProxyService()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Stop)
	firstYAML := "proxies:\n  - name: first\n    type: http\n    server: first.example\n    port: 443\n"
	secondYAML := "proxies:\n  - name: second\n    type: http\n    server: second.example\n    port: 443\n"
	if err := service.UploadProxyConfigForUser("first.yaml", firstYAML, "alice-id", "alice"); err != nil {
		t.Fatalf("upload first: %v", err)
	}
	fixture, control := newAutoProbeController(t)
	manager := service.Manager()
	manager.mu.Lock()
	manager.workDir = t.TempDir()
	manager.binary = fakeMihomo
	manager.control = control
	manager.secret = "test-secret"
	manager.process = &exec.Cmd{}
	manager.runtimeGeneration = 1
	if err := os.WriteFile(filepath.Join(manager.workDir, "config.yaml"), []byte("mode: rule\n"), 0o600); err != nil {
		manager.mu.Unlock()
		t.Fatal(err)
	}
	manager.mu.Unlock()
	firstConfig := service.ListProxyConfigs()
	if len(firstConfig) != 1 || len(firstConfig[0].Nodes) != 1 {
		t.Fatalf("first catalog = %#v", firstConfig)
	}
	firstRuntime := runtimeNameForNode(t, service.catalog, firstConfig[0].Nodes[0].ID)
	fixture.setGroupResult(http.StatusOK, map[string]int64{firstRuntime: 7})
	auto := &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto}
	if _, err := service.ProxyURLForPool(context.Background(), "bob-id", "pool", auto); err != nil {
		t.Fatalf("initial scoped route: %v", err)
	}

	if err := service.UploadProxyConfigForUser("second.yaml", secondYAML, "carol-id", "carol"); err != nil {
		t.Fatalf("upload second: %v", err)
	}
	configs := service.ListProxyConfigs()
	if len(configs) != 2 {
		t.Fatalf("catalog after upload = %#v", configs)
	}
	secondConfig := configs[1]
	secondRuntime := runtimeNameForNode(t, service.catalog, secondConfig.Nodes[0].ID)
	manager.mu.Lock()
	group := manager.scopedAutoGroups[proxyPoolKey("bob-id", "pool")]
	manager.mu.Unlock()
	if len(group.nodes) != 2 || group.nodes[0] != firstRuntime || group.nodes[1] != secondRuntime {
		t.Fatalf("active group after upload = %#v", group.nodes)
	}

	if err := service.DeleteProxyConfigForUser("carol-id", secondConfig.ID, nil); err != nil {
		t.Fatalf("delete second: %v", err)
	}
	manager.mu.Lock()
	group = manager.scopedAutoGroups[proxyPoolKey("bob-id", "pool")]
	manager.mu.Unlock()
	if len(group.nodes) != 1 || group.nodes[0] != firstRuntime {
		t.Fatalf("active group after delete = %#v", group.nodes)
	}

	refreshedYAML := "proxies:\n  - name: refreshed\n    type: http\n    server: refreshed.example\n    port: 443\n"
	if err := os.WriteFile(filepath.Join(service.catalog.root, firstConfig[0].FileName), []byte(refreshedYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := service.RefreshProxyConfigs(); err != nil {
		t.Fatalf("refresh catalog: %v", err)
	}
	refreshedConfigs := service.ListProxyConfigs()
	if len(refreshedConfigs) != 1 || len(refreshedConfigs[0].Nodes) != 1 {
		t.Fatalf("catalog after refresh = %#v", refreshedConfigs)
	}
	refreshedRuntime := runtimeNameForNode(t, service.catalog, refreshedConfigs[0].Nodes[0].ID)
	manager.mu.Lock()
	group = manager.scopedAutoGroups[proxyPoolKey("bob-id", "pool")]
	manager.mu.Unlock()
	if len(group.nodes) != 1 || group.nodes[0] != refreshedRuntime || group.nodes[0] == firstRuntime {
		t.Fatalf("active group after refresh = %#v, first=%q refreshed=%q", group.nodes, firstRuntime, refreshedRuntime)
	}
}

func TestAutoGroupProbeUsesDedicatedTotalTimeout(t *testing.T) {
	if proxyAutoProbeTimeout != proxyTestTimeout+5*time.Second {
		t.Fatalf("auto group timeout = %s, want %s", proxyAutoProbeTimeout, proxyTestTimeout+5*time.Second)
	}
	catalog := newAutoProbeCatalog([]map[string]any{{"name": "first", "type": "http", "server": "first.example", "port": 443}})
	fixture, control := newAutoProbeController(t)
	names := autoProbeRuntimeNames(catalog)
	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 12})

	// Scale the production 10s/15s relationship down so this regression does
	// not sleep for ten seconds: the response misses a fixed-node budget but
	// remains within the dedicated full-group budget.
	const fixedBudget = 20 * time.Millisecond
	const groupBudget = 80 * time.Millisecond
	fixture.setResponseDelays(35*time.Millisecond, 35*time.Millisecond)
	manager := newAutoProbeManager(t, catalog, control)
	manager.autoProbeTimeout = groupBudget

	endpoint, err := manager.ProxyURLForPool(context.Background(), "pool", &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto})
	if err != nil || endpoint.Node != proxyAutoGroupName {
		t.Fatalf("delayed group selection endpoint=%#v err=%v", endpoint, err)
	}
	groups, _, _ := fixture.counts()
	if groups != 1 {
		t.Fatalf("group probe calls = %d, want 1", groups)
	}

	// Fixed-node/ordinary controller requests retain their own caller and HTTP
	// budgets; they do not inherit the auto group's larger total timeout.
	ctx, cancel := context.WithTimeout(context.Background(), fixedBudget)
	defer cancel()
	if _, err := manager.measureDelayAt(ctx, control, "test-secret", "fixed"); err == nil {
		t.Fatal("fixed-node delay unexpectedly used the auto group timeout")
	}
	if calls := fixture.proxyDelayCount(); calls != 1 {
		t.Fatalf("fixed-node delay calls = %d, want 1", calls)
	}
}

func TestAutoProxyDoesNotPublishWithoutSuccessfulGroupProbe(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{{"name": "first", "type": "http", "server": "first.example", "port": 443}})
	fixture, control := newAutoProbeController(t)
	fixture.setGroupResult(http.StatusServiceUnavailable, nil)
	manager := newAutoProbeManager(t, catalog, control)

	endpoint, err := manager.ProxyURLForPool(context.Background(), "pool", &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto})
	if err == nil || err.Error() != "自动选择没有可用代理节点" {
		t.Fatalf("auto error = %v", err)
	}
	if endpoint != (proxyEndpoint{}) {
		t.Fatalf("failed auto probe published endpoint %#v", endpoint)
	}
	manager.mu.Lock()
	_, _, exists := manager.currentListenerLocked("pool")
	manager.mu.Unlock()
	if exists {
		t.Fatal("failed auto probe left a current listener")
	}
}

func TestAutoProxyFailureCooldownAvoidsRepeatedGroupProbe(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{{"name": "first", "type": "http", "server": "first.example", "port": 443}})
	fixture, control := newAutoProbeController(t)
	fixture.setGroupResult(http.StatusServiceUnavailable, nil)
	manager := newAutoProbeManager(t, catalog, control)
	config := &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto}

	for attempt := 0; attempt < 2; attempt++ {
		if _, err := manager.ProxyURLForPool(context.Background(), "pool", config); err == nil || err.Error() != "自动选择没有可用代理节点" {
			t.Fatalf("attempt %d auto error = %v", attempt, err)
		}
	}
	groups, _, _ := fixture.counts()
	if groups != 1 {
		t.Fatalf("group probes during cooldown = %d, want 1", groups)
	}
}

func TestAutoProxyFailureCooldownCanRecover(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{{"name": "first", "type": "http", "server": "first.example", "port": 443}})
	fixture, control := newAutoProbeController(t)
	fixture.setGroupResult(http.StatusServiceUnavailable, nil)
	manager := newAutoProbeManager(t, catalog, control)
	config := &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto}
	if _, err := manager.ProxyURLForPool(context.Background(), "pool", config); err == nil {
		t.Fatal("all-failed probe unexpectedly succeeded")
	}
	names := autoProbeRuntimeNames(catalog)
	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 9})
	manager.mu.Lock()
	manager.autoFailureUntil = time.Now().Add(-time.Millisecond)
	manager.mu.Unlock()
	if _, err := manager.ProxyURLForPool(context.Background(), "pool", config); err != nil {
		t.Fatalf("recovered auto probe: %v", err)
	}
	groups, _, _ := fixture.counts()
	if groups != 2 {
		t.Fatalf("recovery group probes = %d, want 2", groups)
	}
}

func TestAutoProxySelectionInvalidatesAfterReload(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{
		{"name": "first", "type": "http", "server": "first.example", "port": 443},
		{"name": "second", "type": "http", "server": "second.example", "port": 443},
	})
	fixture, control := newAutoProbeController(t)
	names := autoProbeRuntimeNames(catalog)
	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 11, names[1]: 27})
	manager := newAutoProbeManager(t, catalog, control)
	config := &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto}
	if _, err := manager.ProxyURLForPool(context.Background(), "pool", config); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	firstGeneration := manager.runtimeGeneration
	firstSelection := manager.autoSelection
	manager.mu.Unlock()
	if firstSelection.node != names[0] {
		t.Fatalf("initial selection = %#v", firstSelection)
	}

	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 31, names[1]: 5})
	if err := manager.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if _, err := manager.ProxyURLForPool(context.Background(), "pool", config); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	secondGeneration := manager.runtimeGeneration
	secondSelection := manager.autoSelection
	manager.mu.Unlock()
	if secondGeneration <= firstGeneration || secondSelection.node != names[1] || secondSelection.delay != 5 {
		t.Fatalf("reload selection = %#v (generation %d -> %d)", secondSelection, firstGeneration, secondGeneration)
	}
	groups, _, _ := fixture.counts()
	if groups != 2 {
		t.Fatalf("group probes after reload = %d, want 2", groups)
	}
}

func TestAutoProxySelectionCancellationDoesNotPublish(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{{"name": "first", "type": "http", "server": "first.example", "port": 443}})
	fixture, control := newAutoProbeController(t)
	release := make(chan struct{})
	fixture.mu.Lock()
	fixture.groupRelease = release
	fixture.mu.Unlock()
	manager := newAutoProbeManager(t, catalog, control)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		endpoint proxyEndpoint
		err      error
	}
	resultCh := make(chan result, 1)
	go func() {
		endpoint, err := manager.ProxyURLForPool(ctx, "pool", &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto})
		resultCh <- result{endpoint: endpoint, err: err}
	}()
	select {
	case <-fixture.groupEntered:
	case <-time.After(time.Second):
		t.Fatal("auto group probe did not start")
	}
	cancel()
	select {
	case result := <-resultCh:
		if !errors.Is(result.err, context.Canceled) || result.endpoint != (proxyEndpoint{}) {
			t.Fatalf("canceled auto result = %#v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled auto request did not return")
	}
	close(release)
	manager.mu.Lock()
	_, _, exists := manager.currentListenerLocked("pool")
	selection := manager.autoSelection
	manager.mu.Unlock()
	if exists || selection.node != "" {
		t.Fatalf("canceled probe published listener=%v selection=%#v", exists, selection)
	}
}

func TestAutoProxySelectionCoalescesConcurrentCallers(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{
		{"name": "first", "type": "http", "server": "first.example", "port": 443},
		{"name": "second", "type": "http", "server": "second.example", "port": 443},
	})
	fixture, control := newAutoProbeController(t)
	names := autoProbeRuntimeNames(catalog)
	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 21, names[1]: 7})
	release := make(chan struct{})
	fixture.mu.Lock()
	fixture.groupRelease = release
	fixture.mu.Unlock()
	manager := newAutoProbeManager(t, catalog, control)
	config := &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto}
	const callers = 12
	results := make(chan error, callers)
	for index := 0; index < callers; index++ {
		go func() {
			_, err := manager.ProxyURLForPool(context.Background(), "pool", config)
			results <- err
		}()
	}
	select {
	case <-fixture.groupEntered:
	case <-time.After(time.Second):
		t.Fatal("auto group probe did not start")
	}
	close(release)
	for index := 0; index < callers; index++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("caller %d: %v", index, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("caller %d did not return", index)
		}
	}
	groups, _, _ := fixture.counts()
	if groups != 1 {
		t.Fatalf("concurrent callers issued %d group probes, want 1", groups)
	}
}

func TestAutoSpeedTestUsesGroupProbeAndSkipsUnreadyListener(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		catalog := newAutoProbeCatalog([]map[string]any{
			{"name": "first", "type": "http", "server": "first.example", "port": 443},
			{"name": "second", "type": "http", "server": "second.example", "port": 443},
		})
		fixture, control := newAutoProbeController(t)
		names := autoProbeRuntimeNames(catalog)
		fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 19, names[1]: 8})
		manager := newAutoProbeManager(t, catalog, control)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result := manager.Test(ctx, "", "", "https://8.8.8.8/")
		if result.ProxyLatencyMs == nil || *result.ProxyLatencyMs != 8 || result.ProxyError != "" {
			t.Fatalf("auto speed result = %#v", result)
		}
		groups, groupDelayPaths, _ := fixture.counts()
		if groups != 1 || groupDelayPaths != 0 {
			t.Fatalf("speed controller calls: group=%d group-proxy-delay=%d", groups, groupDelayPaths)
		}
	})

	t.Run("all failed", func(t *testing.T) {
		catalog := newAutoProbeCatalog([]map[string]any{{"name": "first", "type": "http", "server": "first.example", "port": 443}})
		fixture, control := newAutoProbeController(t)
		fixture.setGroupResult(http.StatusServiceUnavailable, nil)
		manager := newAutoProbeManager(t, catalog, control)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result := manager.Test(ctx, "", "", "https://8.8.8.8/")
		if result.ProxyError != "自动选择没有可用代理节点" || result.ResponsesLatencyMs != nil || result.ResponsesError != "" {
			t.Fatalf("failed auto speed result = %#v", result)
		}
		groups, groupDelayPaths, _ := fixture.counts()
		if groups != 1 || groupDelayPaths != 0 {
			t.Fatalf("failed speed controller calls: group=%d group-proxy-delay=%d", groups, groupDelayPaths)
		}
	})
}

func TestAutoProbeIncludesEveryRuntimeNode(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{
		{"name": "local", "type": "http", "server": "127.0.0.1", "port": 8080},
		{"name": "hop", "type": "http", "server": "hop.example", "port": 443},
		{"name": "chain", "type": "http", "server": "chain.example", "port": 443, "dialer-proxy": "hop"},
		{"name": "subscription-info", "type": "http", "server": "subscription.example", "port": 443},
	})
	fixture, control := newAutoProbeController(t)
	names := autoProbeRuntimeNames(catalog)
	delays := make(map[string]int64, len(names))
	for index, name := range names {
		delays[name] = int64(20 + index)
	}
	delays[names[2]] = 1
	fixture.setGroupResult(http.StatusOK, delays)
	manager := newAutoProbeManager(t, catalog, control)

	selection, err := manager.autoSelectionForRuntime(context.Background())
	if err != nil || selection.node != names[2] {
		t.Fatalf("selection = %#v, err = %v", selection, err)
	}
	groups, _, _ := fixture.counts()
	if groups != 1 {
		t.Fatalf("group calls = %d", groups)
	}
}

func TestAutoProbeDoesNotPublishStaleGeneration(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{
		{"name": "first", "type": "http", "server": "first.example", "port": 443},
		{"name": "second", "type": "http", "server": "second.example", "port": 443},
	})
	fixture, control := newAutoProbeController(t)
	names := autoProbeRuntimeNames(catalog)
	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 3, names[1]: 30})
	release := make(chan struct{})
	fixture.mu.Lock()
	fixture.groupRelease = release
	fixture.mu.Unlock()
	manager := newAutoProbeManager(t, catalog, control)
	type result struct {
		selection proxyAutoSelection
		err       error
	}
	resultCh := make(chan result, 1)
	go func() {
		selection, err := manager.autoSelectionForRuntime(context.Background())
		resultCh <- result{selection: selection, err: err}
	}()
	select {
	case <-fixture.groupEntered:
	case <-time.After(time.Second):
		t.Fatal("initial group probe did not start")
	}
	manager.mu.Lock()
	manager.advanceRuntimeGenerationLocked()
	newGeneration := manager.runtimeGeneration
	manager.mu.Unlock()
	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 40, names[1]: 4})
	close(release)
	select {
	case result := <-resultCh:
		if result.err != nil || result.selection.generation != newGeneration || result.selection.node != names[1] {
			t.Fatalf("stale-generation result = %#v, want second node at generation %d", result, newGeneration)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("selection did not recover after generation change")
	}
	manager.mu.Lock()
	cached := manager.autoSelection
	manager.mu.Unlock()
	if cached.generation != newGeneration || cached.node != names[1] {
		t.Fatalf("stale probe cached %#v", cached)
	}
	groups, _, _ := fixture.counts()
	if groups < 2 {
		t.Fatalf("generation replacement did not issue a new group probe: %d", groups)
	}
}

func TestPeriodicAutoProbeRefreshesLowestLatencyWithoutNewRequest(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{
		{"name": "first", "type": "http", "server": "first.example", "port": 443},
		{"name": "second", "type": "http", "server": "second.example", "port": 443},
	})
	fixture, control := newAutoProbeController(t)
	names := autoProbeRuntimeNames(catalog)
	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 8, names[1]: 25})
	manager := newAutoProbeManager(t, catalog, control)
	config := &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto}
	if _, err := manager.ProxyURLForPool(context.Background(), "pool", config); err != nil {
		t.Fatal(err)
	}

	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 40, names[1]: 4})
	active, err := manager.refreshActiveAutoSelection(context.Background())
	if err != nil || !active {
		t.Fatalf("periodic refresh active=%v err=%v", active, err)
	}
	manager.mu.Lock()
	selection := manager.autoSelection
	_, listener, listenerOK := manager.currentListenerLocked("pool")
	manager.mu.Unlock()
	if selection.node != names[1] || selection.delay != 4 {
		t.Fatalf("periodic selection = %#v", selection)
	}
	if !listenerOK || listener.proxy != proxyAutoGroupName {
		t.Fatalf("periodic refresh changed listener %#v", listener)
	}
	groups, _, _ := fixture.counts()
	if groups != 2 {
		t.Fatalf("periodic group probes = %d, want 2", groups)
	}
}

func TestPeriodicAutoProbeFailureInvalidatesAndCanRecover(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{
		{"name": "first", "type": "http", "server": "first.example", "port": 443},
		{"name": "second", "type": "http", "server": "second.example", "port": 443},
	})
	fixture, control := newAutoProbeController(t)
	names := autoProbeRuntimeNames(catalog)
	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 9, names[1]: 18})
	manager := newAutoProbeManager(t, catalog, control)
	config := &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto}
	if _, err := manager.ProxyURLForPool(context.Background(), "pool", config); err != nil {
		t.Fatal(err)
	}

	fixture.setGroupResult(http.StatusServiceUnavailable, nil)
	active, err := manager.refreshActiveAutoSelection(context.Background())
	if !active || err == nil || err.Error() != "自动选择没有可用代理节点" {
		t.Fatalf("periodic failure active=%v err=%v", active, err)
	}
	manager.mu.Lock()
	selection := manager.autoSelection
	_, watched := manager.autoWatchPools["pool"]
	manager.mu.Unlock()
	if selection.node != "" {
		t.Fatalf("failed periodic probe retained selection %#v", selection)
	}
	if !watched {
		t.Fatal("failed periodic probe removed the recovery watch")
	}
	if _, err := manager.ProxyURLForPool(context.Background(), "pool", config); err == nil || err.Error() != "自动选择没有可用代理节点" {
		t.Fatalf("request after periodic failure = %v", err)
	}

	// The watch survives removal of the unpublished listener, so a later
	// periodic round can recover without another business request or manual
	// listener creation.
	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 30, names[1]: 6})
	manager.mu.Lock()
	manager.lastAutoProbe = time.Now().Add(-proxyAutoProbeInterval)
	manager.mu.Unlock()
	active, err = manager.refreshDueAutoSelection(context.Background())
	if !active || err != nil {
		t.Fatalf("periodic recovery active=%v err=%v", active, err)
	}
	if endpoint, err := manager.ProxyURLForPool(context.Background(), "pool", config); err != nil || endpoint.Node != proxyAutoGroupName {
		t.Fatalf("request after periodic recovery endpoint=%#v err=%v", endpoint, err)
	}
}

func TestDueAutoProbeUsesFiveMinuteInterval(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{{"name": "first", "type": "http", "server": "first.example", "port": 443}})
	fixture, control := newAutoProbeController(t)
	names := autoProbeRuntimeNames(catalog)
	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 8})
	manager := newAutoProbeManager(t, catalog, control)
	if _, err := manager.ProxyURLForPool(context.Background(), "pool", &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto}); err != nil {
		t.Fatal(err)
	}
	if active, err := manager.refreshDueAutoSelection(context.Background()); err != nil || active {
		t.Fatalf("early periodic refresh active=%v err=%v", active, err)
	}
	manager.mu.Lock()
	manager.lastAutoProbe = time.Now().Add(-proxyAutoProbeInterval)
	manager.mu.Unlock()
	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 6})
	if active, err := manager.refreshDueAutoSelection(context.Background()); err != nil || !active {
		t.Fatalf("due periodic refresh active=%v err=%v", active, err)
	}
	groups, _, _ := fixture.counts()
	if groups != 2 {
		t.Fatalf("due periodic group probes = %d, want 2", groups)
	}
}

func TestSyncPoolProxyClearsAutoWatchWhenSavedAsFixedOrDisabled(t *testing.T) {
	for _, test := range []struct {
		name         string
		config       *AccountPoolProxyConfig
		wantListener bool
	}{
		{name: "fixed", config: &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionNode, ProxyNodeID: "node"}, wantListener: true},
		{name: "disabled", config: &AccountPoolProxyConfig{Enabled: false, Selection: AccountPoolProxySelectionNone}},
		{name: "deleted", config: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog := newAutoProbeCatalog([]map[string]any{{"name": "first", "type": "http", "server": "first.example", "port": 443}})
			fixture, control := newAutoProbeController(t)
			names := autoProbeRuntimeNames(catalog)
			fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 7})
			manager := newAutoProbeManager(t, catalog, control)
			poolKey := "user\x00pool"
			if _, err := manager.ProxyURLForPool(context.Background(), poolKey, &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto}); err != nil {
				t.Fatal(err)
			}
			service := &ProxyService{manager: manager}
			if err := service.SyncPoolProxy("user", "pool", test.config); err != nil {
				t.Fatalf("SyncPoolProxy: %v", err)
			}
			manager.mu.Lock()
			_, watched := manager.autoWatchPools[poolKey]
			_, _, listenerExists := manager.currentListenerLocked(poolKey)
			manager.mu.Unlock()
			if watched || listenerExists != test.wantListener {
				t.Fatalf("saved %s watcher=%v listener=%v, want listener=%v", test.name, watched, listenerExists, test.wantListener)
			}
			if test.name == "fixed" {
				if active, err := manager.refreshActiveAutoSelection(context.Background()); err != nil || active {
					t.Fatalf("fixed pool remained auto-monitored: active=%v err=%v", active, err)
				}
			}
		})
	}
}

func TestPeriodicAutoProbeOnlyRunsForActiveAutoListenersAndCoalesces(t *testing.T) {
	catalog := newAutoProbeCatalog([]map[string]any{
		{"name": "first", "type": "http", "server": "first.example", "port": 443},
		{"name": "second", "type": "http", "server": "second.example", "port": 443},
	})
	fixture, control := newAutoProbeController(t)
	names := autoProbeRuntimeNames(catalog)
	fixture.setGroupResult(http.StatusOK, map[string]int64{names[0]: 10, names[1]: 12})
	manager := newAutoProbeManager(t, catalog, control)
	if active, err := manager.refreshActiveAutoSelection(context.Background()); err != nil || active {
		t.Fatalf("inactive periodic refresh active=%v err=%v", active, err)
	}
	if groups, _, _ := fixture.counts(); groups != 0 {
		t.Fatalf("inactive manager probed group %d times", groups)
	}
	if _, err := manager.ProxyURLForPool(context.Background(), "pool", &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-fixture.groupEntered:
	default:
	}
	release := make(chan struct{})
	fixture.mu.Lock()
	fixture.groupRelease = release
	fixture.mu.Unlock()
	const callers = 6
	results := make(chan error, callers)
	for index := 0; index < callers; index++ {
		go func() {
			_, err := manager.refreshActiveAutoSelection(context.Background())
			results <- err
		}()
	}
	select {
	case <-fixture.groupEntered:
	case <-time.After(time.Second):
		t.Fatal("periodic group probe did not start")
	}
	deadline := time.Now().Add(time.Second)
	for {
		manager.mu.Lock()
		waiters := 0
		if probe := manager.autoProbe; probe != nil {
			waiters = probe.waiters
		}
		manager.mu.Unlock()
		if waiters >= callers {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("periodic callers did not join one probe: waiters=%d", waiters)
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	for index := 0; index < callers; index++ {
		if err := <-results; err != nil {
			t.Fatalf("periodic caller %d: %v", index, err)
		}
	}
	groups, _, _ := fixture.counts()
	if groups != 2 { // initial request plus the coalesced periodic refresh
		t.Fatalf("periodic coalescing group probes = %d, want 2", groups)
	}
}

func TestProxyManagerReallocationRetiresOldListenerGeneration(t *testing.T) {
	manager := NewProxyManager(nil)
	manager.nextGeneration = 20
	manager.listeners["keep"] = proxyListener{port: 31001, generation: 10, active: 2}
	manager.listeners["remove"] = proxyListener{port: 31002, generation: 11, active: 1, removeRequested: true}
	if err := manager.reallocateListenerPortsLocked(); err != nil {
		t.Fatal(err)
	}
	listener, ok := manager.listeners["keep"]
	if !ok || listener.generation <= 20 || listener.active != 0 {
		t.Fatalf("reallocated listener = %#v", listener)
	}
	if _, ok := manager.listeners["remove"]; ok {
		t.Fatal("remove-requested listener survived process replacement")
	}
	if manager.markListenerActive("keep", 10, -1) {
		t.Fatal("old generation mutated the replacement listener")
	}
	if !manager.markListenerActive("keep", listener.generation, 1) {
		t.Fatal("replacement generation was not accepted")
	}
}

func TestProxyManagerRetiresOldPhysicalListenerAfterSwitch(t *testing.T) {
	manager := NewProxyManager(nil)
	manager.nextGeneration = 10
	oldKey := "user\x00pool\x00listener\x0010"
	manager.listeners[oldKey] = proxyListener{
		poolID:     "user\x00pool",
		proxy:      "old-node",
		generation: 10,
		active:     1,
	}
	manager.poolListeners["user\x00pool"] = oldKey

	old := manager.listeners[oldKey]
	old.removeRequested = true
	manager.listeners[oldKey] = old
	newKey, current, err := manager.addCurrentListenerLocked("user\x00pool", "new-node")
	if err != nil {
		t.Fatal(err)
	}
	if newKey == oldKey || manager.poolListeners["user\x00pool"] != newKey || current.proxy != "new-node" {
		t.Fatalf("current listener was not replaced: key=%q current=%#v", newKey, current)
	}
	if old := manager.listeners[oldKey]; !old.removeRequested || old.active != 1 {
		t.Fatalf("old listener was not retained for its lease: %#v", old)
	}
	if !manager.markListenerActive(oldKey, 10, -1) {
		t.Fatal("old lease could not drain")
	}
	if _, exists := manager.listeners[oldKey]; exists {
		t.Fatal("drained retired listener remained configured")
	}
	if _, exists := manager.listeners[newKey]; !exists {
		t.Fatal("draining old listener removed the new current listener")
	}
}

func TestProxyManagerProcessExitInvalidatesOldLeases(t *testing.T) {
	manager := NewProxyManager(nil)
	manager.nextGeneration = 5
	key := "user\x00pool\x00listener\x005"
	manager.listeners[key] = proxyListener{poolID: "user\x00pool", generation: 5, active: 2}
	manager.poolListeners["user\x00pool"] = key
	manager.retireProcessLeasesLocked()
	listener := manager.listeners[key]
	if listener.generation <= 5 || listener.active != 0 {
		t.Fatalf("process replacement retained old lease state: %#v", listener)
	}
	if manager.markListenerActive(key, 5, -1) {
		t.Fatal("old process generation changed replacement listener")
	}
}

func TestResolveProxyTestTargetRejectsNonPublicAddresses(t *testing.T) {
	for _, rawURL := range []string{
		"http://100.100.100.200",
		"http://192.0.2.10",
		"http://198.18.0.1",
		"http://[2001:db8::1]",
		"http://[::ffff:127.0.0.1]",
		"http://[64:ff9b::a9fe:a9fe]",
	} {
		t.Run(rawURL, func(t *testing.T) {
			if _, err := resolveProxyTestTarget(context.Background(), rawURL); err == nil {
				t.Fatalf("unsafe target was accepted: %s", rawURL)
			}
		})
	}
	target, err := resolveProxyTestTarget(context.Background(), "https://8.8.8.8/v1/models")
	if err != nil {
		t.Fatalf("public target rejected: %v", err)
	}
	if target.hostHeader != "8.8.8.8" || target.serverName != "8.8.8.8" {
		t.Fatalf("resolved public target = %#v", target)
	}
}

var _ io.ReadCloser = (*proxyTestErrorReadCloser)(nil)
