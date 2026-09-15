package services

import (
	"bytes"
	"compress/gzip"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	proxyConfigsDirName        = "proxy-configs"
	proxyRuntimeDirName        = "proxy-runtime"
	proxyIndexFileName         = "index.json"
	proxySpeedTestsFileName    = "speed-tests.json"
	proxySpeedTestsVersion     = 3
	proxyHiddenConfigsFileName = "hidden-proxy-configs.json"
	proxyManagerVersion        = 1
	proxyHiddenConfigsVersion  = 1
	proxyListenerIdleTTL       = 10 * time.Minute
	proxyTestTimeout           = 10 * time.Second
	proxyAutoProbeTimeout      = proxyTestTimeout + 5*time.Second
	proxyBatchTestTimeout      = 15 * time.Second
	proxyBatchLatencyWorkers   = 4
	proxyHealthURL             = "https://www.gstatic.com/generate_204"
	proxyMaxConfigSize         = 4 << 20
	proxyMaxConfigNodes        = 500
	proxyMaxCatalogFiles       = 100
	proxyMaxCatalogBytes       = 64 << 20
	proxyMaxCatalogNodes       = 5000
	proxyMaxUserConfigs        = 20
	proxyMaxUserBytes          = 16 << 20
	proxyAutoGroupName         = "__code_switch_auto__"
	proxyAutoProbeRetryDelay   = 2 * time.Second
	proxyAutoProbeInterval     = 5 * time.Minute
	proxyMaxSpeedTestWorkers   = 4
	mihomoVersion              = "v1.19.28"
	mihomoAssetName            = "mihomo-linux-amd64-compatible-v1.19.28.gz"
	mihomoDownloadURL          = "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.28/mihomo-linux-amd64-compatible-v1.19.28.gz"
	mihomoAssetSHA256          = "70d01cfb8cb7bf7a92fd1af16cb4b9553d90bb4eecde3b5c4849103e27c80ddb"
)

var errNoVisibleProxyNodes = errors.New("没有可用代理节点")

type AccountPoolProxySelection string

const (
	AccountPoolProxySelectionNone AccountPoolProxySelection = "none"
	AccountPoolProxySelectionAuto AccountPoolProxySelection = "auto"
	AccountPoolProxySelectionNode AccountPoolProxySelection = "node"
)

type AccountPoolProxyConfig struct {
	Enabled                    bool                      `json:"enabled"`
	Selection                  AccountPoolProxySelection `json:"selection"`
	ProxyNodeID                string                    `json:"proxyNodeId,omitempty"`
	AutoDisableWhenNoAvailable bool                      `json:"autoDisableWhenNoAvailable,omitempty"`
}

type ProxyNode struct {
	ID           string `json:"id"`
	ConfigName   string `json:"configName"`
	OriginalName string `json:"originalName"`
	Name         string `json:"name"`
	Uploader     string `json:"uploader"`
}

type ProxyConfigSummary struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	FileName   string      `json:"fileName"`
	Uploader   string      `json:"uploader"`
	UploadedAt string      `json:"uploadedAt"`
	Nodes      []ProxyNode `json:"nodes"`
	IsOwner    bool        `json:"isOwner"`
}

type proxyConfigMetadata struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name"`
	FileName   string `json:"fileName"`
	Uploader   string `json:"uploader"`
	UploaderID string `json:"uploaderId,omitempty"`
	UploadedAt string `json:"uploadedAt"`
}

type proxyIndex struct {
	Version int                   `json:"version"`
	Configs []proxyConfigMetadata `json:"configs"`
}

type proxySource struct {
	Meta  proxyConfigMetadata
	Nodes []map[string]any
}

type proxyUploadCandidate struct {
	name     string
	fileName string
	content  []byte
	source   proxySource
}

type proxyDeletedConfig struct {
	state   proxyCatalogState
	meta    proxyConfigMetadata
	content []byte
}

type proxyHiddenConfigsStore struct {
	Version   int      `json:"version"`
	ConfigIDs []string `json:"configIds"`
}

type ProxySpeedTestResult struct {
	ProxyLatencyMs             *int64 `json:"proxyLatencyMs,omitempty"`
	ResponsesLatencyMs         *int64 `json:"responsesLatencyMs,omitempty"`
	ResponsesStatus            int    `json:"responsesStatus,omitempty"`
	ResponsesError             string `json:"responsesError,omitempty"`
	ResponsesCloudflareBlocked bool   `json:"responsesCloudflareBlocked,omitempty"`
	ProxyError                 string `json:"proxyError,omitempty"`
	CleanupError               string `json:"cleanupError,omitempty"`
}

// ProxySpeedTestSnapshot is the shared latest result for one Responses URL.
// It is deliberately keyed by URL so different upstreams never influence
// each other.
type ProxySpeedTestSnapshot struct {
	TestedAt string                   `json:"testedAt,omitempty"`
	Results  []ProxyNodeLatencyResult `json:"results"`
}

// ProxyNodeLatencyResult is one controller health-check result. Tested is
// false when the batch did not issue a controller delay request for this node.
// Results are keyed by the stable catalog node ID so callers never need to
// infer an identity from a mutable display name or a Mihomo runtime name.
type ProxyNodeLatencyResult struct {
	NodeID                     string `json:"nodeId"`
	Tested                     bool   `json:"tested"`
	LatencyMs                  *int64 `json:"latencyMs,omitempty"`
	Error                      string `json:"error,omitempty"`
	ProxyLatencyMs             *int64 `json:"proxyLatencyMs,omitempty"`
	ProxyError                 string `json:"proxyError,omitempty"`
	ResponsesLatencyMs         *int64 `json:"responsesLatencyMs,omitempty"`
	ResponsesStatus            int    `json:"responsesStatus,omitempty"`
	ResponsesError             string `json:"responsesError,omitempty"`
	ResponsesCloudflareBlocked bool   `json:"responsesCloudflareBlocked,omitempty"`
	// These fields are retained for Mihomo's internal GET url-test cache.
	ProxiedBaseURLMs    *int64 `json:"proxiedBaseUrlMs,omitempty"`
	ProxiedBaseURLError string `json:"proxiedBaseUrlError,omitempty"`
}

type proxySpeedTestStoreData struct {
	Version int                               `json:"version"`
	Targets map[string]ProxySpeedTestSnapshot `json:"targets"`
}

type proxySpeedTestStore struct {
	mu   sync.Mutex
	path string
	data proxySpeedTestStoreData
}

func newProxySpeedTestStore(path string) (*proxySpeedTestStore, error) {
	store := &proxySpeedTestStore{
		path: path,
		data: proxySpeedTestStoreData{Version: proxySpeedTestsVersion, Targets: make(map[string]ProxySpeedTestSnapshot)},
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return store, nil
	}
	if err := json.Unmarshal(data, &store.data); err != nil {
		return nil, fmt.Errorf("读取代理测速缓存失败: %w", err)
	}
	if store.data.Version == 1 || store.data.Version == 2 {
		// Version 1 contains Base URL GET measurements and version 2 contains
		// empty-request probes. Neither is comparable to the Codex-shaped
		// unauthenticated Responses probe used by the current version.
		store.data = proxySpeedTestStoreData{Version: proxySpeedTestsVersion, Targets: make(map[string]ProxySpeedTestSnapshot)}
		if err := writeJSONPrivate(store.path, store.data); err != nil {
			log.Printf("重置旧版代理测速缓存失败: %v", err)
		}
		return store, nil
	}
	if store.data.Version != proxySpeedTestsVersion {
		return nil, errors.New("代理测速缓存版本不兼容")
	}
	if store.data.Targets == nil {
		store.data.Targets = make(map[string]ProxySpeedTestSnapshot)
	}
	return store, nil
}

func (s *proxySpeedTestStore) record(target, nodeID string, result ProxyNodeLatencyResult) {
	if s == nil || strings.TrimSpace(target) == "" || strings.TrimSpace(nodeID) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := s.data.Targets[target]
	results := make(map[string]ProxyNodeLatencyResult, len(snapshot.Results)+1)
	for _, current := range snapshot.Results {
		results[current.NodeID] = current
	}
	result.NodeID = nodeID
	result.Tested = true
	results[nodeID] = result
	snapshot.Results = proxySpeedTestResults(results)
	snapshot.TestedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.data.Targets[target] = snapshot
	if err := writeJSONPrivate(s.path, s.data); err != nil {
		log.Printf("保存代理测速缓存失败: %v", err)
	}
}

func (s *proxySpeedTestStore) recordAutoGroup(target string, runtimeNodeIDs map[string]string, delays map[string]int64) {
	if s == nil || strings.TrimSpace(target) == "" || len(runtimeNodeIDs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := s.data.Targets[target]
	results := make(map[string]ProxyNodeLatencyResult, len(snapshot.Results)+len(runtimeNodeIDs))
	for _, current := range snapshot.Results {
		results[current.NodeID] = current
	}
	for runtimeName, nodeID := range runtimeNodeIDs {
		current := results[nodeID]
		current.NodeID = nodeID
		current.Tested = true
		if delay, ok := delays[runtimeName]; ok && delay > 0 {
			current.ProxiedBaseURLMs = &delay
			current.ProxiedBaseURLError = ""
		} else {
			current.ProxiedBaseURLMs = nil
			current.ProxiedBaseURLError = "代理不可用"
		}
		results[nodeID] = current
	}
	snapshot.Results = proxySpeedTestResults(results)
	snapshot.TestedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.data.Targets[target] = snapshot
	if err := writeJSONPrivate(s.path, s.data); err != nil {
		log.Printf("保存代理自动测速缓存失败: %v", err)
	}
}

func (s *proxySpeedTestStore) snapshot(target string, visibleNodeIDs map[string]struct{}) ProxySpeedTestSnapshot {
	if s == nil || strings.TrimSpace(target) == "" {
		return ProxySpeedTestSnapshot{Results: []ProxyNodeLatencyResult{}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := s.data.Targets[target]
	results := make([]ProxyNodeLatencyResult, 0, len(stored.Results))
	for _, result := range stored.Results {
		if _, visible := visibleNodeIDs[result.NodeID]; visible {
			results = append(results, result)
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].NodeID < results[j].NodeID })
	return ProxySpeedTestSnapshot{TestedAt: stored.TestedAt, Results: results}
}

func (s *proxySpeedTestStore) bestAutoSelection(target string, runtimeNodeIDs map[string]string) (proxyAutoSelection, bool) {
	if s == nil || strings.TrimSpace(target) == "" {
		return proxyAutoSelection{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	byNodeID := make(map[string]ProxyNodeLatencyResult, len(s.data.Targets[target].Results))
	for _, result := range s.data.Targets[target].Results {
		byNodeID[result.NodeID] = result
	}
	best := proxyAutoSelection{}
	for runtimeName, nodeID := range runtimeNodeIDs {
		result, ok := byNodeID[nodeID]
		if !ok || result.ProxiedBaseURLMs == nil || *result.ProxiedBaseURLMs <= 0 {
			continue
		}
		if best.node == "" || *result.ProxiedBaseURLMs < best.delay {
			best.node = runtimeName
			best.delay = *result.ProxiedBaseURLMs
		}
	}
	return best, best.node != ""
}

func proxySpeedTestResults(results map[string]ProxyNodeLatencyResult) []ProxyNodeLatencyResult {
	ordered := make([]ProxyNodeLatencyResult, 0, len(results))
	for _, result := range results {
		ordered = append(ordered, result)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].NodeID < ordered[j].NodeID })
	return ordered
}

type proxyLatencyTarget struct {
	nodeID      string
	runtimeName string
	catalogKey  string
}

// proxyRouteSpec is created only by ProxyService after applying a user's
// visibility preferences. ProxyManager intentionally receives runtime names,
// never a client-provided set of auto candidates.
type proxyRouteSpec struct {
	poolKey   string
	fixedNode string
	autoGroup *proxyScopedAutoGroup
}

// proxyScopedAutoGroup describes one account-pool's native Mihomo url-test
// group. The public group name is an opaque digest so an external controller
// response cannot disclose a user or pool identifier.
type proxyScopedAutoGroup struct {
	poolKey      string
	userID       string
	poolID       string
	name         string
	candidateKey string
	testURL      string
	nodes        []string
}

type ProxyCatalog struct {
	mu          sync.RWMutex
	root        string
	index       proxyIndex
	sources     map[string]proxySource
	futureIndex bool
}

type proxyCatalogState struct {
	index       proxyIndex
	sources     map[string]proxySource
	futureIndex bool
}

type ProxyService struct {
	catalog    *ProxyCatalog
	manager    *ProxyManager
	speedTests *proxySpeedTestStore
	opMu       sync.Mutex
}

var proxyHiddenConfigLocks sync.Map

func NewProxyService() (*ProxyService, error) {
	catalog, err := NewProxyCatalog()
	if err != nil {
		return nil, err
	}
	speedTests, err := newProxySpeedTestStore(filepath.Join(catalog.root, proxySpeedTestsFileName))
	if err != nil {
		return nil, err
	}
	manager := NewProxyManager(catalog)
	manager.speedTests = speedTests
	return &ProxyService{catalog: catalog, manager: manager, speedTests: speedTests}, nil
}

func (s *ProxyService) ListProxyConfigs() []ProxyConfigSummary {
	if s == nil || s.catalog == nil || s.manager == nil {
		return []ProxyConfigSummary{}
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.catalog.List()
}

// ListProxyConfigsForUser returns the shared catalog as it is visible to one
// user. Hiding a config only changes this projection; it never removes nodes
// from the shared Mihomo runtime catalog.
func (s *ProxyService) ListProxyConfigsForUser(userID string) ([]ProxyConfigSummary, error) {
	if s == nil || s.catalog == nil || s.manager == nil {
		return nil, errors.New("代理服务未初始化")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	configs := s.catalog.ListForUser(userID)
	hidden, err := loadAndPruneHiddenProxyConfigs(userID, proxyConfigIDs(configs))
	if err != nil {
		return nil, err
	}
	return filterHiddenProxyConfigs(configs, hidden, false), nil
}

// ListHiddenProxyConfigsForUser returns hidden configs so a user can restore
// them. Stale entries are pruned as part of this read.
func (s *ProxyService) ListHiddenProxyConfigsForUser(userID string) ([]ProxyConfigSummary, error) {
	if s == nil || s.catalog == nil || s.manager == nil {
		return nil, errors.New("代理服务未初始化")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	configs := s.catalog.ListForUser(userID)
	hidden, err := loadAndPruneHiddenProxyConfigs(userID, proxyConfigIDs(configs))
	if err != nil {
		return nil, err
	}
	return filterHiddenProxyConfigs(configs, hidden, true), nil
}

func (s *ProxyService) UploadProxyConfig(fileName, content, uploader string) error {
	return s.uploadProxyConfig(fileName, content, "", uploader)
}

// UploadProxyConfigForUser associates an uploaded shared YAML with the
// immutable authenticated user ID used for later ownership checks.
func (s *ProxyService) UploadProxyConfigForUser(fileName, content, uploaderID, uploader string) error {
	uploaderID = strings.TrimSpace(uploaderID)
	if uploaderID == "" {
		return errors.New("上传代理配置需要已认证用户")
	}
	if _, err := UserDataDir(uploaderID); err != nil {
		return err
	}
	return s.uploadProxyConfig(fileName, content, uploaderID, uploader)
}

func (s *ProxyService) uploadProxyConfig(fileName, content, uploaderID, uploader string) error {
	if s == nil || s.catalog == nil || s.manager == nil {
		return errors.New("代理服务未初始化")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.manager.mu.Lock()
	if s.manager.closed {
		s.manager.mu.Unlock()
		return errors.New("代理服务已停止")
	}
	candidate, err := s.catalog.prepareUploadForOwner(fileName, content, uploaderID, uploader)
	if err != nil {
		s.manager.mu.Unlock()
		return err
	}
	if err := s.manager.validateCatalogCandidateLocked(candidate); err != nil {
		s.manager.mu.Unlock()
		return err
	}
	if err := s.catalog.commitUpload(candidate); err != nil {
		s.manager.mu.Unlock()
		return err
	}
	s.manager.invalidateAutoCatalogLocked()
	s.manager.mu.Unlock()
	if refreshErr := s.refreshAllScopedAutoGroupsLocked(true); refreshErr != nil {
		if rollbackErr := s.catalog.rollbackUpload(candidate.name); rollbackErr != nil {
			return fmt.Errorf("刷新代理配置失败: %v；回滚失败: %w", refreshErr, rollbackErr)
		}
		return refreshErr
	}
	return nil
}

// HideProxyConfigForUser hides a shared YAML only for a non-owner user.
func (s *ProxyService) HideProxyConfigForUser(userID, configID string) error {
	if s == nil || s.catalog == nil || s.manager == nil {
		return errors.New("代理服务未初始化")
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return errors.New("隐藏代理配置需要已认证用户")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	meta, ok := s.catalog.ConfigByID(configID)
	if !ok {
		return errors.New("代理配置不存在或已删除")
	}
	if proxyConfigOwnedBy(meta, userID) {
		return errors.New("上传者不能隐藏自己的代理配置")
	}
	configID = proxyConfigID(meta)
	configs := s.catalog.ListForUser(userID)
	hidden, err := loadAndPruneHiddenProxyConfigs(userID, proxyConfigIDs(configs))
	if err != nil {
		return err
	}
	_, wasHidden := hidden[configID]
	if err := setProxyConfigHidden(userID, configID, true); err != nil {
		return err
	}
	if err := s.refreshScopedAutoGroupsForUserLocked(userID); err != nil {
		if rollbackErr := setProxyConfigHidden(userID, configID, wasHidden); rollbackErr != nil {
			return fmt.Errorf("刷新用户代理范围失败: %v；恢复隐藏偏好失败: %w", err, rollbackErr)
		}
		_ = s.refreshScopedAutoGroupsForUserLocked(userID)
		return err
	}
	return nil
}

// UnhideProxyConfigForUser is deliberately idempotent. It also lets a user
// clear an obsolete local preference after a config was deleted.
func (s *ProxyService) UnhideProxyConfigForUser(userID, configID string) error {
	if s == nil || s.catalog == nil || s.manager == nil {
		return errors.New("代理服务未初始化")
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return errors.New("恢复代理配置需要已认证用户")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	configID = strings.TrimSpace(configID)
	configs := s.catalog.ListForUser(userID)
	hidden, err := loadAndPruneHiddenProxyConfigs(userID, proxyConfigIDs(configs))
	if err != nil {
		return err
	}
	_, wasHidden := hidden[configID]
	if err := setProxyConfigHidden(userID, configID, false); err != nil {
		return err
	}
	if !wasHidden {
		return nil
	}
	if err := s.refreshScopedAutoGroupsForUserLocked(userID); err != nil {
		if rollbackErr := setProxyConfigHidden(userID, configID, true); rollbackErr != nil {
			return fmt.Errorf("刷新用户代理范围失败: %v；恢复隐藏偏好失败: %w", err, rollbackErr)
		}
		_ = s.refreshScopedAutoGroupsForUserLocked(userID)
		return err
	}
	return nil
}

// DeleteProxyConfigForUser removes an uploader-owned YAML. The optional
// precondition runs under the catalog operation lock so callers can reject a
// deletion that would leave dependent account pools invalid.
func (s *ProxyService) DeleteProxyConfigForUser(userID, configID string, precondition func(nodeIDs []string, remainingNodeCount int) error) error {
	if s == nil || s.catalog == nil || s.manager == nil {
		return errors.New("代理服务未初始化")
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return errors.New("删除代理配置需要已认证用户")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.manager.mu.Lock()
	if s.manager.closed {
		s.manager.mu.Unlock()
		return errors.New("代理服务已停止")
	}
	meta, nodeIDs, remainingNodeCount, ok := s.catalog.DeletionInfo(configID)
	if !ok {
		s.manager.mu.Unlock()
		return errors.New("代理配置不存在或已删除")
	}
	if !proxyConfigOwnedBy(meta, userID) {
		s.manager.mu.Unlock()
		return errors.New("只有上传者可以删除该代理配置")
	}
	if precondition != nil {
		if err := precondition(nodeIDs, remainingNodeCount); err != nil {
			s.manager.mu.Unlock()
			return err
		}
	}
	listenerState := s.manager.snapshotListenersLocked()
	deleted, err := s.catalog.deleteConfig(configID)
	if err != nil {
		s.manager.mu.Unlock()
		return err
	}
	s.manager.invalidateAutoCatalogLocked()
	s.manager.removeListenersForMissingNodesLocked()
	s.manager.mu.Unlock()
	if err := s.refreshAllScopedAutoGroupsLocked(true); err != nil {
		s.manager.mu.Lock()
		s.manager.restoreListenersLocked(listenerState, false)
		s.manager.mu.Unlock()
		if rollbackErr := s.catalog.rollbackDelete(deleted); rollbackErr != nil {
			return fmt.Errorf("刷新代理配置失败: %v；回滚删除失败: %w", err, rollbackErr)
		}
		return err
	}
	return nil
}

func (s *ProxyService) RefreshProxyConfigs() error {
	if s == nil || s.catalog == nil || s.manager == nil {
		return errors.New("代理服务未初始化")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	previous := s.catalog.snapshot()
	if err := s.catalog.refresh(); err != nil {
		return err
	}
	s.manager.mu.Lock()
	listenerState := s.manager.snapshotListenersLocked()
	s.manager.invalidateAutoCatalogLocked()
	s.manager.removeListenersForMissingNodesLocked()
	s.manager.mu.Unlock()
	if err := s.refreshAllScopedAutoGroupsLocked(true); err != nil {
		s.manager.mu.Lock()
		s.manager.restoreListenersLocked(listenerState, false)
		s.manager.mu.Unlock()
		if restoreErr := s.catalog.restore(previous); restoreErr != nil {
			return fmt.Errorf("刷新代理运行配置失败: %v；恢复代理目录索引失败: %w", err, restoreErr)
		}
		// The manager keeps the previous runtime configuration on a failed
		// reload. Restore the in-memory catalog as well so later listener
		// changes cannot accidentally publish the failed refresh.
		return err
	}
	return nil
}

func (s *ProxyService) TestProxy(ctx context.Context, poolID, nodeID, responsesURL string) ProxySpeedTestResult {
	if s == nil || s.manager == nil {
		return ProxySpeedTestResult{ProxyError: "代理服务未初始化"}
	}
	return s.manager.Test(ctx, poolID, nodeID, responsesURL)
}

// ProxyURLForPool resolves an account-pool proxy through the authenticated
// user's current visibility projection. It is the route used by the relay;
// the legacy ProxyManager method remains available for unscoped callers and
// older unit tests only.
func (s *ProxyService) ProxyURLForPool(ctx context.Context, userID, poolID string, config *AccountPoolProxyConfig) (proxyEndpoint, error) {
	return s.ProxyURLForPoolWithBaseURL(ctx, userID, poolID, config, "")
}

// ProxyURLForPoolWithBaseURL resolves a pool's proxy using its own upstream
// Base URL as the url-test target for automatic selection. The older wrapper
// remains for callers that do not have a pool configuration yet.
func (s *ProxyService) ProxyURLForPoolWithBaseURL(ctx context.Context, userID, poolID string, config *AccountPoolProxyConfig, baseURL string) (proxyEndpoint, error) {
	if s == nil || s.catalog == nil || s.manager == nil {
		return proxyEndpoint{}, errors.New("代理服务未初始化")
	}
	userID = strings.TrimSpace(userID)
	poolID = strings.TrimSpace(poolID)
	if userID == "" || poolID == "" {
		return proxyEndpoint{}, errors.New("代理号池缺少用户或 ID")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	spec, err := s.proxyRouteSpecForUserLocked(userID, poolID, config, baseURL)
	if err != nil {
		return proxyEndpoint{}, err
	}
	return s.manager.ProxyURLForPoolWithSpec(ctx, config, spec)
}

// TestProxyForUser applies the same visibility policy as real account-pool
// routing. An empty nodeID means auto selection; a non-empty nodeID must be a
// node visible to this user. The preview path gets a server-generated pool
// identity, so clients never choose a scoped candidate set or group name.
func (s *ProxyService) TestProxyForUser(ctx context.Context, userID, poolID, nodeID, responsesURL, autoSelectionURL string) ProxySpeedTestResult {
	if s == nil || s.catalog == nil || s.manager == nil {
		return ProxySpeedTestResult{ProxyError: "代理服务未初始化"}
	}
	userID = strings.TrimSpace(userID)
	poolID = strings.TrimSpace(poolID)
	if userID == "" {
		return ProxySpeedTestResult{ProxyError: "测试代理需要已认证用户"}
	}
	if poolID == "" {
		poolID = "preview"
	}
	config := &AccountPoolProxyConfig{Enabled: true, Selection: AccountPoolProxySelectionAuto}
	if nodeID = strings.TrimSpace(nodeID); nodeID != "" {
		config.Selection = AccountPoolProxySelectionNode
		config.ProxyNodeID = nodeID
	}
	s.opMu.Lock()
	// The preview must not replace a saved pool's live auto group merely
	// because an unsaved form value is being measured. Per-node preview tests
	// still measure the Responses endpoint directly below.
	spec, err := s.proxyRouteSpecForUserLocked(userID, poolID, config, "")
	s.opMu.Unlock()
	if err != nil {
		return ProxySpeedTestResult{ProxyError: err.Error()}
	}
	result := s.manager.TestWithRouteSpec(ctx, spec, strings.TrimSpace(responsesURL))
	if ctx.Err() == nil && config.Selection == AccountPoolProxySelectionNode {
		if stableID, ok := s.catalog.NormalizeNodeID(config.ProxyNodeID); ok {
			responsesTarget := normalizeScopedAutoTestURL(responsesURL)
			s.speedTests.record(responsesTarget, stableID, ProxyNodeLatencyResult{
				ProxyLatencyMs:             result.ProxyLatencyMs,
				ProxyError:                 result.ProxyError,
				ResponsesLatencyMs:         result.ResponsesLatencyMs,
				ResponsesStatus:            result.ResponsesStatus,
				ResponsesError:             result.ResponsesError,
				ResponsesCloudflareBlocked: result.ResponsesCloudflareBlocked,
			})
			// The runtime auto group remains isolated by the pool Base URL, but
			// this value is a Responses POST measurement rather than a Base URL
			// request. This lets a just-finished bulk test influence auto routing.
			if strings.TrimSpace(autoSelectionURL) != "" {
				if selectionTarget := normalizeScopedAutoTestURL(autoSelectionURL); selectionTarget != responsesTarget {
					s.speedTests.record(selectionTarget, stableID, ProxyNodeLatencyResult{
						ProxiedBaseURLMs:    result.ResponsesLatencyMs,
						ProxiedBaseURLError: result.ResponsesError,
					})
				}
			}
		}
	}
	return result
}

// SharedProxySpeedTestsForUser returns the shared latest measurements for the
// nodes currently visible to this user. The cache itself is global; visibility
// filtering prevents hidden nodes from leaking into a user's modal.
func (s *ProxyService) SharedProxySpeedTestsForUser(userID, responsesURL string) (ProxySpeedTestSnapshot, error) {
	if s == nil || s.catalog == nil || s.speedTests == nil {
		return ProxySpeedTestSnapshot{Results: []ProxyNodeLatencyResult{}}, errors.New("代理服务未初始化")
	}
	targets, err := s.visibleProxyLatencyTargetsForUser(strings.TrimSpace(userID))
	if err != nil {
		return ProxySpeedTestSnapshot{Results: []ProxyNodeLatencyResult{}}, err
	}
	visible := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		visible[target.nodeID] = struct{}{}
	}
	return s.speedTests.snapshot(normalizeScopedAutoTestURL(responsesURL), visible), nil
}

// RecordResponsesCloudflareBlock updates a node from a real proxied request.
// runtimeNode is issued by ProxyManager after resolving the account pool's
// visible catalog, so it cannot name an arbitrary hidden node.
func (s *ProxyService) RecordResponsesCloudflareBlock(runtimeNode, responsesURL, autoSelectionURL string) {
	if s == nil || s.catalog == nil || s.speedTests == nil {
		return
	}
	runtimeNode = strings.TrimSpace(runtimeNode)
	stableID, ok := s.catalog.nodeIDsForRuntimeNames([]string{runtimeNode})[runtimeNode]
	if !ok {
		return
	}
	blocked := ProxyNodeLatencyResult{
		ResponsesStatus:            http.StatusForbidden,
		ResponsesError:             "Cloudflare 拦截（HTTP 403）",
		ResponsesCloudflareBlocked: true,
	}
	responsesTarget := normalizeScopedAutoTestURL(responsesURL)
	s.speedTests.record(responsesTarget, stableID, blocked)
	if strings.TrimSpace(autoSelectionURL) == "" {
		return
	}
	if selectionTarget := normalizeScopedAutoTestURL(autoSelectionURL); selectionTarget != responsesTarget {
		s.speedTests.record(selectionTarget, stableID, ProxyNodeLatencyResult{
			ProxiedBaseURLError: blocked.ResponsesError,
		})
	}
}

// TestAllProxyLatenciesForUser measures every node visible to userID. Hidden
// YAMLs are excluded before a controller request is made, rather than merely
// filtering a shared url-test group's response afterwards.
func (s *ProxyService) TestAllProxyLatenciesForUser(ctx context.Context, userID string) ([]ProxyNodeLatencyResult, error) {
	if s == nil || s.catalog == nil || s.manager == nil {
		return nil, errors.New("代理服务未初始化")
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, errors.New("测试代理延时需要已认证用户")
	}
	targets, err := s.visibleProxyLatencyTargetsForUser(userID)
	if err != nil {
		return nil, err
	}
	return s.manager.TestNodeLatencies(ctx, targets), nil
}

// visibleProxyLatencyTargetsForUser takes the catalog and per-user hide
// preference snapshot under the catalog operation lock. The potentially slow
// controller requests deliberately happen after releasing that lock.
func (s *ProxyService) visibleProxyLatencyTargetsForUser(userID string) ([]proxyLatencyTarget, error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.visibleProxyLatencyTargetsForUserLocked(userID)
}

func (s *ProxyService) visibleProxyLatencyTargetsForUserLocked(userID string) ([]proxyLatencyTarget, error) {
	configs := s.catalog.ListForUser(userID)
	hidden, err := loadAndPruneHiddenProxyConfigs(userID, proxyConfigIDs(configs))
	if err != nil {
		return nil, err
	}
	return s.catalog.latencyTargetsForConfigs(filterHiddenProxyConfigs(configs, hidden, false)), nil
}

func (s *ProxyService) SyncPoolProxy(userID, poolID string, config *AccountPoolProxyConfig) error {
	return s.SyncPoolProxyWithBaseURL(userID, poolID, config, "")
}

// SyncPoolProxyWithBaseURL publishes the automatic group for a saved pool.
// Keeping the Base URL here makes the next request use the current target
// even before the first relay call reaches the proxy manager.
func (s *ProxyService) SyncPoolProxyWithBaseURL(userID, poolID string, config *AccountPoolProxyConfig, baseURL string) error {
	if s == nil || s.manager == nil {
		return nil
	}
	userID = strings.TrimSpace(userID)
	poolID = strings.TrimSpace(poolID)
	if userID == "" || poolID == "" {
		return nil
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if config != nil && config.Enabled && (config.Selection == AccountPoolProxySelectionAuto || config.Selection == "") {
		spec, err := s.proxyRouteSpecForUserLocked(userID, poolID, config, baseURL)
		if err != nil {
			return err
		}
		return s.manager.SyncScopedAutoPool(spec)
	}
	if config != nil && config.Enabled && config.Selection == AccountPoolProxySelectionNode {
		// Preserve an existing legacy listener until the next real request
		// replaces it with the fixed node. A scoped group listener is always
		// retired immediately because its group membership is being removed.
		return s.manager.ClearScopedAutoPoolForFixed(proxyPoolKey(userID, poolID))
	}
	// Disabled and deleted pools must not retain a scoped auto group, its
	// periodic watcher, or a listener.
	return s.manager.RemoveScopedAutoPool(proxyPoolKey(userID, poolID))
}

func (s *ProxyService) NormalizePoolProxyConfig(config *AccountPoolProxyConfig) error {
	if s == nil {
		return nil
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.normalizePoolProxyConfigLocked(config)
}

// NormalizePoolProxyConfigForUser validates a saved account-pool proxy against
// the same per-user visibility projection used for relay requests.
func (s *ProxyService) NormalizePoolProxyConfigForUser(userID string, config *AccountPoolProxyConfig) error {
	if s == nil {
		return nil
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.normalizePoolProxyConfigForUserLocked(userID, config)
}

// WithCatalogOperation keeps validation and a dependent pool-store write on the
// same side of an upload publication/rollback transaction.
func (s *ProxyService) WithCatalogOperation(operation func() error) error {
	if s == nil {
		return errors.New("代理服务未初始化")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return operation()
}

// NormalizePoolProxyConfigInOperation is for callers already holding
// WithCatalogOperation.
func (s *ProxyService) NormalizePoolProxyConfigInOperation(config *AccountPoolProxyConfig) error {
	return s.normalizePoolProxyConfigLocked(config)
}

// NormalizePoolProxyConfigForUserInOperation is for a pool save already
// protected by WithCatalogOperation.
func (s *ProxyService) NormalizePoolProxyConfigForUserInOperation(userID string, config *AccountPoolProxyConfig) error {
	return s.normalizePoolProxyConfigForUserLocked(userID, config)
}

func (s *ProxyService) normalizePoolProxyConfigLocked(config *AccountPoolProxyConfig) error {
	if config == nil || !config.Enabled {
		return nil
	}
	if s == nil || s.catalog == nil {
		return errors.New("代理服务未初始化")
	}
	if len(s.catalog.runtimeNodes()) == 0 {
		return errors.New("启用号池代理前请先上传至少一个有效的代理配置")
	}
	if config.Selection != AccountPoolProxySelectionNode {
		return nil
	}
	stableID, ok := s.catalog.NormalizeNodeID(config.ProxyNodeID)
	if !ok {
		return errors.New("选择的代理节点不存在或已失效")
	}
	config.ProxyNodeID = stableID
	return nil
}

func (s *ProxyService) normalizePoolProxyConfigForUserLocked(userID string, config *AccountPoolProxyConfig) error {
	if config == nil || !config.Enabled {
		return nil
	}
	if s == nil || s.catalog == nil {
		return errors.New("代理服务未初始化")
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return errors.New("启用号池代理需要已认证用户")
	}
	if len(s.catalog.runtimeNodes()) == 0 {
		return errors.New("启用号池代理前请先上传至少一个有效的代理配置")
	}
	// A synthetic pool ID is sufficient for save-time validation; the real
	// persisted ID is incorporated when SyncPoolProxy installs its group.
	_, err := s.proxyRouteSpecForUserLocked(userID, "save-validation", config, "")
	if err != nil {
		if errors.Is(err, errNoVisibleProxyNodes) {
			return errors.New("启用号池代理前请先上传至少一个有效的代理配置")
		}
		return err
	}
	if config.Selection == AccountPoolProxySelectionNode {
		stableID, ok := s.catalog.NormalizeNodeID(config.ProxyNodeID)
		if !ok {
			return errors.New("选择的代理节点不存在或已失效")
		}
		config.ProxyNodeID = stableID
	}
	return nil
}

func proxyPoolKey(userID, poolID string) string {
	return strings.TrimSpace(userID) + "\x00" + strings.TrimSpace(poolID)
}

func (s *ProxyService) proxyRouteSpecForUserLocked(userID, poolID string, config *AccountPoolProxyConfig, baseURL string) (proxyRouteSpec, error) {
	if config == nil || !config.Enabled {
		return proxyRouteSpec{poolKey: proxyPoolKey(userID, poolID)}, nil
	}
	if s == nil || s.catalog == nil {
		return proxyRouteSpec{}, errors.New("代理服务未初始化")
	}
	userID = strings.TrimSpace(userID)
	poolID = strings.TrimSpace(poolID)
	if userID == "" || poolID == "" {
		return proxyRouteSpec{}, errors.New("代理号池缺少用户或 ID")
	}
	targets, err := s.visibleProxyLatencyTargetsForUserLocked(userID)
	if err != nil {
		return proxyRouteSpec{}, err
	}
	for _, target := range targets {
		if strings.TrimSpace(target.runtimeName) == "" {
			return proxyRouteSpec{}, errors.New("选择的代理节点不存在或已失效")
		}
	}
	spec := proxyRouteSpec{poolKey: proxyPoolKey(userID, poolID)}
	switch config.Selection {
	case AccountPoolProxySelectionNode:
		stableID, ok := s.catalog.NormalizeNodeID(config.ProxyNodeID)
		if !ok {
			return proxyRouteSpec{}, errors.New("选择的代理节点不存在或已失效")
		}
		for _, target := range targets {
			if target.nodeID == stableID {
				spec.fixedNode = target.runtimeName
				return spec, nil
			}
		}
		return proxyRouteSpec{}, errors.New("选择的代理节点已隐藏或不可用")
	case "", AccountPoolProxySelectionAuto:
		if len(targets) == 0 {
			return proxyRouteSpec{}, errNoVisibleProxyNodes
		}
		nodes := make([]string, 0, len(targets))
		digest := sha256.New()
		testURL := normalizeScopedAutoTestURL(baseURL)
		_, _ = io.WriteString(digest, testURL)
		_, _ = digest.Write([]byte{0})
		for _, target := range targets {
			nodes = append(nodes, target.runtimeName)
			_, _ = io.WriteString(digest, target.nodeID)
			_, _ = digest.Write([]byte{0})
			_, _ = io.WriteString(digest, target.runtimeName)
			_, _ = digest.Write([]byte{0})
		}
		candidateKey := hex.EncodeToString(digest.Sum(nil))
		nameDigest := sha256.Sum256([]byte("code-switch-scoped-auto\x00" + userID + "\x00" + poolID + "\x00" + candidateKey))
		spec.autoGroup = &proxyScopedAutoGroup{
			poolKey:      spec.poolKey,
			userID:       userID,
			poolID:       poolID,
			name:         "__code_switch_auto_" + hex.EncodeToString(nameDigest[:12]),
			candidateKey: candidateKey,
			testURL:      testURL,
			nodes:        nodes,
		}
		return spec, nil
	default:
		return proxyRouteSpec{}, fmt.Errorf("未知代理选择方式: %s", config.Selection)
	}
}

// normalizeScopedAutoTestURL uses a configured upstream URL only when it is
// a complete HTTP(S) URL. Existing callers without a pool configuration keep
// the previous health-check target as a compatible fallback.
func normalizeScopedAutoTestURL(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return proxyHealthURL
	}
	parsed.Fragment = ""
	return parsed.String()
}

// refreshScopedAutoGroupsForUserLocked rebuilds only the active/saved auto
// groups belonging to one user. Callers hold opMu, so an old visibility
// snapshot cannot be re-published after a hide/unhide operation.
func (s *ProxyService) refreshScopedAutoGroupsForUserLocked(userID string) error {
	if s == nil || s.manager == nil {
		return nil
	}
	groups := s.manager.ScopedAutoPoolsForUser(userID)
	replacements := make(map[string]proxyScopedAutoGroup, len(groups))
	for _, group := range groups {
		spec, err := s.proxyRouteSpecForUserLocked(group.userID, group.poolID, &AccountPoolProxyConfig{
			Enabled: true, Selection: AccountPoolProxySelectionAuto,
		}, group.testURL)
		if err != nil {
			if errors.Is(err, errNoVisibleProxyNodes) {
				continue
			}
			return err
		}
		if spec.autoGroup != nil {
			replacements[group.poolKey] = *spec.autoGroup
		}
	}
	return s.manager.ReplaceScopedAutoPoolsForUser(userID, replacements)
}

func (s *ProxyService) refreshAllScopedAutoGroupsLocked(forceRuntimeReload bool) error {
	if s == nil || s.manager == nil {
		return nil
	}
	groups := s.manager.ScopedAutoPools()
	replacements := make(map[string]proxyScopedAutoGroup, len(groups))
	for _, group := range groups {
		spec, err := s.proxyRouteSpecForUserLocked(group.userID, group.poolID, &AccountPoolProxyConfig{
			Enabled: true, Selection: AccountPoolProxySelectionAuto,
		}, group.testURL)
		if err != nil {
			if errors.Is(err, errNoVisibleProxyNodes) {
				continue
			}
			return err
		}
		if spec.autoGroup != nil {
			replacements[group.poolKey] = *spec.autoGroup
		}
	}
	return s.manager.ReplaceAllScopedAutoPools(replacements, forceRuntimeReload)
}

func (s *ProxyService) Stop() {
	if s != nil && s.manager != nil {
		s.manager.Stop()
	}
}

func (s *ProxyService) Manager() *ProxyManager {
	if s == nil {
		return nil
	}
	return s.manager
}

func NewProxyCatalog() (*ProxyCatalog, error) {
	home, err := getUserHomeDir()
	if err != nil {
		return nil, err
	}
	catalog := &ProxyCatalog{
		root:    filepath.Join(home, appSettingsDir, proxyConfigsDirName),
		sources: make(map[string]proxySource),
	}
	if err := catalog.refresh(); err != nil {
		return nil, err
	}
	return catalog, nil
}

func (c *ProxyCatalog) refresh() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refreshLocked()
}

func (c *ProxyCatalog) snapshot() proxyCatalogState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return proxyCatalogState{
		index: proxyIndex{
			Version: c.index.Version,
			Configs: append([]proxyConfigMetadata(nil), c.index.Configs...),
		},
		sources:     cloneProxySources(c.sources),
		futureIndex: c.futureIndex,
	}
}

func (c *ProxyCatalog) restore(state proxyCatalogState) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.index = proxyIndex{
		Version: state.index.Version,
		Configs: append([]proxyConfigMetadata(nil), state.index.Configs...),
	}
	c.sources = cloneProxySources(state.sources)
	c.futureIndex = state.futureIndex
	if c.futureIndex {
		return nil
	}
	return writeJSONPrivate(filepath.Join(c.root, proxyIndexFileName), c.index)
}

func (c *ProxyCatalog) refreshLocked() error {
	if err := os.MkdirAll(c.root, 0o700); err != nil {
		return err
	}
	index := proxyIndex{Version: proxyManagerVersion}
	futureIndex := false
	futureVersion := 0
	if data, err := os.ReadFile(filepath.Join(c.root, proxyIndexFileName)); err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &index); err != nil {
			fmt.Printf("[proxy] 代理配置索引损坏，将从 YAML 重建: %v\n", err)
			index = proxyIndex{Version: proxyManagerVersion}
		} else if index.Version > proxyManagerVersion {
			futureIndex = true
			futureVersion = index.Version
			fmt.Printf("[proxy] 代理配置索引版本 %d 高于当前版本 %d，将以只读降级模式加载\n", index.Version, proxyManagerVersion)
			// Preserve metadata in memory so the UI can still identify known
			// configs while writes remain disabled.
			index = proxyIndex{Version: futureVersion, Configs: append([]proxyConfigMetadata(nil), index.Configs...)}
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if index.Configs == nil {
		index.Configs = []proxyConfigMetadata{}
	}
	c.futureIndex = futureIndex
	known := make(map[string]proxyConfigMetadata, len(index.Configs))
	for _, meta := range index.Configs {
		known[meta.Name] = meta
	}
	entries, err := filepath.Glob(filepath.Join(c.root, "*.yaml"))
	if err != nil {
		return err
	}
	entriesYML, err := filepath.Glob(filepath.Join(c.root, "*.yml"))
	if err != nil {
		return err
	}
	entries = append(entries, entriesYML...)
	sort.Strings(entries)
	if len(entries) > proxyMaxCatalogFiles {
		if !futureIndex {
			return fmt.Errorf("代理配置文件数量不能超过 %d", proxyMaxCatalogFiles)
		}
		fmt.Printf("[proxy] 未来版本索引包含 %d 个配置文件，仅加载前 %d 个\n", len(entries), proxyMaxCatalogFiles)
		entries = entries[:proxyMaxCatalogFiles]
	}
	newSources := make(map[string]proxySource, len(entries))
	newConfigs := make([]proxyConfigMetadata, 0, len(entries))
	for _, path := range entries {
		name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		meta := known[name]
		if meta.Name == "" {
			meta = proxyConfigMetadata{Name: name, FileName: filepath.Base(path), Uploader: "系统", UploadedAt: ""}
		}
		meta.FileName = filepath.Base(path)
		nodes, err := loadProxyYAML(path)
		if err != nil {
			fmt.Printf("[proxy] 跳过无效代理配置 %s: %v\n", filepath.Base(path), err)
			continue
		}
		newSources[name] = proxySource{Meta: meta, Nodes: nodes}
		newConfigs = append(newConfigs, meta)
	}
	version := proxyManagerVersion
	if futureIndex {
		version = futureVersion
		knownNames := make(map[string]struct{}, len(index.Configs))
		for _, meta := range index.Configs {
			knownNames[meta.Name] = struct{}{}
		}
		for _, meta := range newConfigs {
			if _, exists := knownNames[meta.Name]; exists {
				continue
			}
			index.Configs = append(index.Configs, meta)
		}
		newConfigs = index.Configs
	}
	c.index = proxyIndex{Version: version, Configs: newConfigs}
	c.sources = newSources
	if c.futureIndex {
		return nil
	}
	return writeJSONPrivate(filepath.Join(c.root, proxyIndexFileName), c.index)
}

func referenceProxyDir() string {
	if value := strings.TrimSpace(os.Getenv("CODE_SWITCH_REFERENCE_PROXY_DIR")); value != "" {
		return value
	}
	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, "reference", "proxy")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if executable, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(executable), "reference", "proxy")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return filepath.Join("reference", "proxy")
}

func loadProxyYAML(path string) ([]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > proxyMaxConfigSize {
		return nil, fmt.Errorf("代理配置大小无效: %s", filepath.Base(path))
	}
	return loadProxyYAMLFromBytes(data, filepath.Base(path))
}

func (c *ProxyCatalog) List() []ProxyConfigSummary {
	return c.listForUser("")
}

func (c *ProxyCatalog) ListForUser(userID string) []ProxyConfigSummary {
	return c.listForUser(strings.TrimSpace(userID))
}

func (c *ProxyCatalog) listForUser(userID string) []ProxyConfigSummary {
	c.mu.RLock()
	defer c.mu.RUnlock()
	configs := make([]ProxyConfigSummary, 0, len(c.index.Configs))
	for _, meta := range c.index.Configs {
		source, ok := c.sources[meta.Name]
		if !ok {
			continue
		}
		summary := ProxyConfigSummary{
			ID:         proxyConfigID(meta),
			Name:       meta.Name,
			FileName:   meta.FileName,
			Uploader:   meta.Uploader,
			UploadedAt: meta.UploadedAt,
			IsOwner:    proxyConfigOwnedBy(meta, userID),
		}
		for index, node := range source.Nodes {
			original, _ := node["name"].(string)
			summary.Nodes = append(summary.Nodes, c.nodeSummary(meta, original, index))
		}
		configs = append(configs, summary)
	}
	return configs
}

func (c *ProxyCatalog) nodeSummary(meta proxyConfigMetadata, original string, _ int) ProxyNode {
	return ProxyNode{
		ID:           proxyNodeID(proxyConfigID(meta), original),
		ConfigName:   meta.Name,
		OriginalName: original,
		Name:         fmt.Sprintf("%s-%s（来自%s）", meta.Name, original, meta.Uploader),
		Uploader:     meta.Uploader,
	}
}

func (c *ProxyCatalog) runtimeNodeNamesLocked() map[string]string {
	return runtimeNodeNames(c.index.Configs, c.sources)
}

func runtimeNodeNames(configs []proxyConfigMetadata, sources map[string]proxySource) map[string]string {
	type row struct {
		id   string
		base string
	}
	rows := make([]row, 0)
	counts := make(map[string]int)
	for _, meta := range configs {
		for index, node := range sources[meta.Name].Nodes {
			original, _ := node["name"].(string)
			summary := proxyNodeSummary(meta, original, index)
			rows = append(rows, row{id: summary.ID, base: summary.Name})
			counts[summary.Name]++
		}
	}
	names := make(map[string]string, len(rows))
	for _, item := range rows {
		if counts[item.base] == 1 {
			names[item.id] = item.base
		} else {
			names[item.id] = fmt.Sprintf("%s [%s]", item.base, item.id[:8])
		}
	}
	return names
}

func proxyNodeSummary(meta proxyConfigMetadata, original string, _ int) ProxyNode {
	return ProxyNode{
		ID:           proxyNodeID(proxyConfigID(meta), original),
		ConfigName:   meta.Name,
		OriginalName: original,
		Name:         fmt.Sprintf("%s-%s（来自%s）", meta.Name, original, meta.Uploader),
		Uploader:     meta.Uploader,
	}
}

func proxyNodeID(configID string, original string) string {
	hash := sha256.Sum256([]byte(configID + "\x00" + original))
	return hex.EncodeToString(hash[:12])
}

func legacyProxyNodeID(configName string, index int, original string) string {
	hash := sha256.Sum256([]byte(configName + "\x00" + strconv.Itoa(index) + "\x00" + original))
	return hex.EncodeToString(hash[:12])
}

func proxyConfigID(meta proxyConfigMetadata) string {
	if id := strings.TrimSpace(meta.ID); id != "" {
		return id
	}
	// Catalogs created before config IDs were introduced do not have an
	// immutable ID. Keep them addressable without accidentally treating their
	// mutable display metadata as an ownership credential.
	hash := sha256.Sum256([]byte("legacy-proxy-config\x00" + meta.Name + "\x00" + meta.FileName))
	return "legacy-" + hex.EncodeToString(hash[:12])
}

func newProxyConfigID() (string, error) {
	var random [16]byte
	if _, err := cryptorand.Read(random[:]); err != nil {
		return "", fmt.Errorf("生成代理配置 ID 失败: %w", err)
	}
	return hex.EncodeToString(random[:]), nil
}

func proxyConfigOwnedBy(meta proxyConfigMetadata, userID string) bool {
	return strings.TrimSpace(userID) != "" && strings.TrimSpace(meta.UploaderID) != "" && meta.UploaderID == strings.TrimSpace(userID)
}

func (c *ProxyCatalog) ConfigByID(configID string) (proxyConfigMetadata, bool) {
	configID = strings.TrimSpace(configID)
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, meta := range c.index.Configs {
		if _, exists := c.sources[meta.Name]; exists && proxyConfigID(meta) == configID {
			return meta, true
		}
	}
	return proxyConfigMetadata{}, false
}

func (c *ProxyCatalog) DeletionInfo(configID string) (proxyConfigMetadata, []string, int, bool) {
	configID = strings.TrimSpace(configID)
	c.mu.RLock()
	defer c.mu.RUnlock()
	remainingNodeCount := 0
	for _, meta := range c.index.Configs {
		source, ok := c.sources[meta.Name]
		if !ok {
			continue
		}
		if proxyConfigID(meta) == configID {
			return meta, proxyConfigNodeIDs(meta, source), countProxyNodesExcept(c.index.Configs, c.sources, meta.Name), true
		}
		remainingNodeCount += len(source.Nodes)
	}
	return proxyConfigMetadata{}, nil, remainingNodeCount, false
}

func countProxyNodesExcept(configs []proxyConfigMetadata, sources map[string]proxySource, excludedName string) int {
	count := 0
	for _, meta := range configs {
		if meta.Name == excludedName {
			continue
		}
		count += len(sources[meta.Name].Nodes)
	}
	return count
}

func proxyConfigNodeIDs(meta proxyConfigMetadata, source proxySource) []string {
	ids := make([]string, 0, len(source.Nodes)*3)
	for index, node := range source.Nodes {
		original, _ := node["name"].(string)
		ids = append(ids, proxyNodeID(proxyConfigID(meta), original))
		// Only configs written before opaque IDs existed accept their legacy node
		// IDs. A newly uploaded replacement with the same file name must not
		// silently retarget an old fixed-node pool selection.
		if strings.TrimSpace(meta.ID) == "" {
			ids = append(ids,
				proxyNodeID(meta.Name, original),
				legacyProxyNodeID(meta.Name, index, original),
			)
		}
	}
	return ids
}

func (c *ProxyCatalog) deleteConfig(configID string) (proxyDeletedConfig, error) {
	configID = strings.TrimSpace(configID)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.futureIndex {
		return proxyDeletedConfig{}, errors.New("代理配置索引版本过新，当前版本拒绝写入")
	}
	index := -1
	var meta proxyConfigMetadata
	for i, candidate := range c.index.Configs {
		if proxyConfigID(candidate) != configID {
			continue
		}
		index = i
		meta = candidate
		break
	}
	if index < 0 {
		return proxyDeletedConfig{}, errors.New("代理配置不存在或已删除")
	}
	path := filepath.Join(c.root, meta.FileName)
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return proxyDeletedConfig{}, errors.New("代理配置文件不存在或已删除")
		}
		return proxyDeletedConfig{}, err
	}
	state := c.snapshotLocked()
	stagedPath := path + ".deleting-" + proxyConfigID(meta)
	if _, err := os.Lstat(stagedPath); err == nil {
		return proxyDeletedConfig{}, fmt.Errorf("代理配置删除暂存文件已存在: %s", filepath.Base(stagedPath))
	} else if !errors.Is(err, os.ErrNotExist) {
		return proxyDeletedConfig{}, err
	}
	if err := os.Rename(path, stagedPath); err != nil {
		return proxyDeletedConfig{}, err
	}
	nextConfigs := make([]proxyConfigMetadata, 0, len(c.index.Configs)-1)
	nextConfigs = append(nextConfigs, c.index.Configs[:index]...)
	nextConfigs = append(nextConfigs, c.index.Configs[index+1:]...)
	nextIndex := proxyIndex{Version: c.index.Version, Configs: nextConfigs}
	if err := writeJSONPrivate(filepath.Join(c.root, proxyIndexFileName), nextIndex); err != nil {
		_ = os.Rename(stagedPath, path)
		return proxyDeletedConfig{}, err
	}
	if err := os.Remove(stagedPath); err != nil {
		rollbackErr := writeJSONPrivate(filepath.Join(c.root, proxyIndexFileName), state.index)
		restoreErr := os.Rename(stagedPath, path)
		if rollbackErr != nil || restoreErr != nil {
			return proxyDeletedConfig{}, fmt.Errorf("删除代理配置文件失败: %v；恢复目录索引失败: %v；恢复配置文件失败: %v", err, rollbackErr, restoreErr)
		}
		return proxyDeletedConfig{}, err
	}
	c.index = nextIndex
	delete(c.sources, meta.Name)
	return proxyDeletedConfig{
		state:   state,
		meta:    meta,
		content: content,
	}, nil
}

func (c *ProxyCatalog) rollbackDelete(deleted proxyDeletedConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := writePrivateFile(filepath.Join(c.root, deleted.meta.FileName), deleted.content); err != nil {
		return err
	}
	if err := writeJSONPrivate(filepath.Join(c.root, proxyIndexFileName), deleted.state.index); err != nil {
		_ = os.Remove(filepath.Join(c.root, deleted.meta.FileName))
		return err
	}
	c.index = proxyIndex{
		Version: deleted.state.index.Version,
		Configs: append([]proxyConfigMetadata(nil), deleted.state.index.Configs...),
	}
	c.sources = cloneProxySources(deleted.state.sources)
	c.futureIndex = deleted.state.futureIndex
	return nil
}

func (c *ProxyCatalog) snapshotLocked() proxyCatalogState {
	return proxyCatalogState{
		index: proxyIndex{
			Version: c.index.Version,
			Configs: append([]proxyConfigMetadata(nil), c.index.Configs...),
		},
		sources:     cloneProxySources(c.sources),
		futureIndex: c.futureIndex,
	}
}

func proxyConfigIDs(configs []ProxyConfigSummary) map[string]struct{} {
	ids := make(map[string]struct{}, len(configs))
	for _, config := range configs {
		if id := strings.TrimSpace(config.ID); id != "" {
			ids[id] = struct{}{}
		}
	}
	return ids
}

func filterHiddenProxyConfigs(configs []ProxyConfigSummary, hidden map[string]struct{}, wantHidden bool) []ProxyConfigSummary {
	filtered := make([]ProxyConfigSummary, 0, len(configs))
	for _, config := range configs {
		_, isHidden := hidden[config.ID]
		if isHidden == wantHidden {
			filtered = append(filtered, config)
		}
	}
	return filtered
}

func hiddenProxyConfigsPath(userID string) (string, error) {
	dir, err := UserDataDir(userID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, proxyHiddenConfigsFileName), nil
}

func hiddenProxyConfigsMutex(path string) *sync.Mutex {
	if existing, ok := proxyHiddenConfigLocks.Load(path); ok {
		return existing.(*sync.Mutex)
	}
	created := &sync.Mutex{}
	actual, _ := proxyHiddenConfigLocks.LoadOrStore(path, created)
	return actual.(*sync.Mutex)
}

func loadHiddenProxyConfigsLocked(path string) (proxyHiddenConfigsStore, error) {
	store := proxyHiddenConfigsStore{Version: proxyHiddenConfigsVersion, ConfigIDs: []string{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return store, err
	}
	if len(data) == 0 {
		return store, nil
	}
	if err := json.Unmarshal(data, &store); err != nil {
		return store, fmt.Errorf("读取代理隐藏偏好失败: %w", err)
	}
	if store.Version > proxyHiddenConfigsVersion {
		return store, errors.New("代理隐藏偏好版本过新")
	}
	store.Version = proxyHiddenConfigsVersion
	if store.ConfigIDs == nil {
		store.ConfigIDs = []string{}
	}
	return store, nil
}

func normalizeHiddenProxyConfigIDs(ids []string, valid map[string]struct{}) ([]string, map[string]struct{}) {
	unique := make(map[string]struct{}, len(ids))
	normalized := make([]string, 0, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if valid != nil {
			if _, ok := valid[id]; !ok {
				continue
			}
		}
		if _, exists := unique[id]; exists {
			continue
		}
		unique[id] = struct{}{}
		normalized = append(normalized, id)
	}
	sort.Strings(normalized)
	return normalized, unique
}

func loadAndPruneHiddenProxyConfigs(userID string, valid map[string]struct{}) (map[string]struct{}, error) {
	path, err := hiddenProxyConfigsPath(userID)
	if err != nil {
		return nil, err
	}
	mu := hiddenProxyConfigsMutex(path)
	mu.Lock()
	defer mu.Unlock()
	store, err := loadHiddenProxyConfigsLocked(path)
	if err != nil {
		return nil, err
	}
	normalized, hidden := normalizeHiddenProxyConfigIDs(store.ConfigIDs, valid)
	if store.Version != proxyHiddenConfigsVersion || !sameStringSlice(store.ConfigIDs, normalized) {
		store.Version = proxyHiddenConfigsVersion
		store.ConfigIDs = normalized
		if err := writeJSONPrivate(path, store); err != nil {
			return nil, err
		}
	}
	return hidden, nil
}

func setProxyConfigHidden(userID, configID string, hidden bool) error {
	configID = strings.TrimSpace(configID)
	if hidden && configID == "" {
		return errors.New("代理配置 ID 不能为空")
	}
	path, err := hiddenProxyConfigsPath(userID)
	if err != nil {
		return err
	}
	mu := hiddenProxyConfigsMutex(path)
	mu.Lock()
	defer mu.Unlock()
	store, err := loadHiddenProxyConfigsLocked(path)
	if err != nil {
		return err
	}
	ids, current := normalizeHiddenProxyConfigIDs(store.ConfigIDs, nil)
	if hidden {
		current[configID] = struct{}{}
	} else {
		delete(current, configID)
	}
	ids = ids[:0]
	for id := range current {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if store.Version == proxyHiddenConfigsVersion && sameStringSlice(store.ConfigIDs, ids) {
		return nil
	}
	store.Version = proxyHiddenConfigsVersion
	store.ConfigIDs = ids
	return writeJSONPrivate(path, store)
}

func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (c *ProxyCatalog) Upload(fileName, content, uploader string) error {
	candidate, err := c.prepareUpload(fileName, content, uploader)
	if err != nil {
		return err
	}
	return c.commitUpload(candidate)
}

func (c *ProxyCatalog) prepareUpload(fileName, content, uploader string) (proxyUploadCandidate, error) {
	return c.prepareUploadForOwner(fileName, content, "", uploader)
}

func (c *ProxyCatalog) prepareUploadForOwner(fileName, content, uploaderID, uploader string) (proxyUploadCandidate, error) {
	fileName = filepath.Base(strings.TrimSpace(fileName))
	ext := strings.ToLower(filepath.Ext(fileName))
	if ext != ".yaml" && ext != ".yml" {
		return proxyUploadCandidate{}, errors.New("代理配置必须是 .yaml 或 .yml 文件")
	}
	name := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	if name == "" || name == "." || strings.ContainsAny(name, `/\\`) {
		return proxyUploadCandidate{}, errors.New("代理配置文件名无效")
	}
	if len(content) == 0 || len(content) > proxyMaxConfigSize {
		return proxyUploadCandidate{}, errors.New("代理配置大小无效")
	}
	nodes, err := loadProxyYAMLFromBytes([]byte(content), fileName)
	if err != nil {
		return proxyUploadCandidate{}, err
	}
	configID, err := newProxyConfigID()
	if err != nil {
		return proxyUploadCandidate{}, err
	}
	candidate := proxyUploadCandidate{
		name:     name,
		fileName: name + ext,
		content:  []byte(content),
		source: proxySource{Meta: proxyConfigMetadata{
			ID:         configID,
			Name:       name,
			FileName:   name + ext,
			Uploader:   strings.TrimSpace(uploader),
			UploaderID: strings.TrimSpace(uploaderID),
			UploadedAt: time.Now().UTC().Format(time.RFC3339),
		}, Nodes: nodes},
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.validateUploadCandidateLocked(candidate); err != nil {
		return proxyUploadCandidate{}, err
	}
	return candidate, nil
}

func (c *ProxyCatalog) commitUpload(candidate proxyUploadCandidate) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.validateUploadCandidateLocked(candidate); err != nil {
		return err
	}
	previousIndex := c.index
	previousSources := c.sources
	path := filepath.Join(c.root, candidate.fileName)
	if err := writePrivateFile(path, candidate.content); err != nil {
		return err
	}
	c.index.Configs = append(c.index.Configs, candidate.source.Meta)
	if err := writeJSONPrivate(filepath.Join(c.root, proxyIndexFileName), c.index); err != nil {
		_ = os.Remove(path)
		c.index = previousIndex
		return err
	}
	if err := c.refreshLocked(); err != nil {
		_ = os.Remove(path)
		c.index = previousIndex
		c.sources = previousSources
		_ = writeJSONPrivate(filepath.Join(c.root, proxyIndexFileName), c.index)
		return err
	}
	return nil
}

func (c *ProxyCatalog) validateUploadCandidateLocked(candidate proxyUploadCandidate) error {
	if c.futureIndex {
		return errors.New("代理配置索引版本过新，当前版本拒绝写入")
	}
	if len(c.sources) >= proxyMaxCatalogFiles {
		return fmt.Errorf("代理配置文件数量不能超过 %d", proxyMaxCatalogFiles)
	}
	if _, exists := c.sources[candidate.name]; exists {
		return fmt.Errorf("代理配置已存在: %s", candidate.name)
	}
	if _, err := os.Stat(filepath.Join(c.root, candidate.fileName)); err == nil {
		return fmt.Errorf("代理配置文件已存在: %s", candidate.name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var totalBytes int64 = int64(len(candidate.content))
	totalNodes := len(candidate.source.Nodes)
	userBytes := int64(0)
	userConfigs := 0
	for _, source := range c.sources {
		totalNodes += len(source.Nodes)
		if info, err := os.Stat(filepath.Join(c.root, source.Meta.FileName)); err == nil {
			totalBytes += info.Size()
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if sameProxyUploader(source.Meta, candidate.source.Meta) {
			userConfigs++
			if info, err := os.Stat(filepath.Join(c.root, source.Meta.FileName)); err == nil {
				userBytes += info.Size()
			}
		}
	}
	if totalBytes > proxyMaxCatalogBytes {
		return fmt.Errorf("代理配置总大小不能超过 %d MiB", proxyMaxCatalogBytes>>20)
	}
	if totalNodes > proxyMaxCatalogNodes {
		return fmt.Errorf("代理节点总数不能超过 %d", proxyMaxCatalogNodes)
	}
	if strings.TrimSpace(candidate.source.Meta.Uploader) != "" && candidate.source.Meta.Uploader != "系统" {
		if userConfigs >= proxyMaxUserConfigs {
			return fmt.Errorf("每个用户最多上传 %d 个代理配置", proxyMaxUserConfigs)
		}
		if userBytes+int64(len(candidate.content)) > proxyMaxUserBytes {
			return fmt.Errorf("每个用户上传的代理配置总大小不能超过 %d MiB", proxyMaxUserBytes>>20)
		}
	}
	return nil
}

func sameProxyUploader(left, right proxyConfigMetadata) bool {
	if strings.TrimSpace(right.UploaderID) != "" {
		return left.UploaderID == right.UploaderID
	}
	return left.Uploader == right.Uploader && right.Uploader != "" && right.Uploader != "系统"
}

func proxyConfigName(fileName string) string {
	base := filepath.Base(strings.TrimSpace(fileName))
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func (c *ProxyCatalog) rollbackUpload(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	source, ok := c.sources[name]
	if !ok {
		return nil
	}
	if err := os.Remove(filepath.Join(c.root, source.Meta.FileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return c.refreshLocked()
}

func loadProxyYAMLFromBytes(data []byte, name string) ([]map[string]any, error) {
	var config map[string]any
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析代理配置 %s 失败: %w", name, err)
	}
	raw, ok := config["proxies"].([]any)
	if !ok || len(raw) == 0 {
		return nil, fmt.Errorf("代理配置 %s 不包含有效 proxies 列表", name)
	}
	if len(raw) > proxyMaxConfigNodes {
		return nil, fmt.Errorf("代理配置 %s 节点数量不能超过 %d", name, proxyMaxConfigNodes)
	}
	seen := make(map[string]struct{}, len(raw))
	nodes := make([]map[string]any, 0, len(raw))
	for i, item := range raw {
		node, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("代理配置 %s 的第 %d 个节点不是对象", name, i+1)
		}
		nodeName, _ := node["name"].(string)
		nodeName = strings.TrimSpace(nodeName)
		if nodeName == "" {
			return nil, fmt.Errorf("代理配置 %s 的第 %d 个节点没有名称", name, i+1)
		}
		if _, exists := seen[nodeName]; exists {
			return nil, fmt.Errorf("代理配置 %s 存在重复节点: %s", name, nodeName)
		}
		if err := validateProxyNode(node, name, i); err != nil {
			return nil, err
		}
		seen[nodeName] = struct{}{}
		node["name"] = nodeName
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func validateProxyNode(node map[string]any, configName string, index int) error {
	proxyType, _ := node["type"].(string)
	if strings.TrimSpace(proxyType) == "" {
		return fmt.Errorf("代理配置 %s 的第 %d 个节点没有 type", configName, index+1)
	}
	server, _ := node["server"].(string)
	if strings.TrimSpace(server) == "" {
		return fmt.Errorf("代理配置 %s 的第 %d 个节点没有 server", configName, index+1)
	}
	port, ok := proxyPort(node["port"])
	if !ok || port < 1 || port > 65535 {
		return fmt.Errorf("代理配置 %s 的第 %d 个节点端口无效", configName, index+1)
	}
	return nil
}

func proxyPort(value any) (int64, bool) {
	switch port := value.(type) {
	case int:
		return int64(port), true
	case int32:
		return int64(port), true
	case int64:
		return port, true
	case uint:
		return int64(port), uint64(port) <= 65535
	case uint32:
		return int64(port), uint64(port) <= 65535
	case uint64:
		return int64(port), port <= 65535
	case float64:
		return int64(port), port == float64(int64(port))
	default:
		return 0, false
	}
}

func (c *ProxyCatalog) runtimeNodes() []map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return runtimeNodes(c.index.Configs, c.sources)
}

// latencyTargetsForConfigs retains the caller's config/node order while
// resolving stable IDs to the names currently published to Mihomo. An empty
// runtime name is preserved as an explicit per-node failure by the caller,
// rather than silently dropping a visible node from a batch result.
func (c *ProxyCatalog) latencyTargetsForConfigs(configs []ProxyConfigSummary) []proxyLatencyTarget {
	c.mu.RLock()
	defer c.mu.RUnlock()
	runtimeNames := c.runtimeNodeNamesLocked()
	catalogKey := proxyRuntimeCatalogKey(c.index.Configs, c.sources)
	targets := make([]proxyLatencyTarget, 0)
	for _, config := range configs {
		for _, node := range config.Nodes {
			targets = append(targets, proxyLatencyTarget{
				nodeID:      node.ID,
				runtimeName: runtimeNames[node.ID],
				catalogKey:  catalogKey,
			})
		}
	}
	return targets
}

func (c *ProxyCatalog) nodeIDsForRuntimeNames(names []string) map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	runtimeNames := c.runtimeNodeNamesLocked()
	wanted := make(map[string]struct{}, len(names))
	for _, name := range names {
		wanted[name] = struct{}{}
	}
	matched := make(map[string]string, len(wanted))
	for nodeID, runtimeName := range runtimeNames {
		if _, ok := wanted[runtimeName]; ok {
			matched[runtimeName] = nodeID
		}
	}
	return matched
}

// runtimeNodesAndCatalogKey returns an atomic catalog view for controller
// operations. The key includes immutable config/node identities, not only
// display/runtime names, so a delete/re-upload with the same YAML name cannot
// silently retarget a previously captured stable node ID.
func (c *ProxyCatalog) runtimeNodesAndCatalogKey() ([]map[string]any, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return runtimeNodes(c.index.Configs, c.sources), proxyRuntimeCatalogKey(c.index.Configs, c.sources)
}

func proxyRuntimeCatalogKey(configs []proxyConfigMetadata, sources map[string]proxySource) string {
	runtimeNames := runtimeNodeNames(configs, sources)
	digest := sha256.New()
	for _, meta := range configs {
		source, ok := sources[meta.Name]
		if !ok {
			continue
		}
		for index, node := range source.Nodes {
			original, _ := node["name"].(string)
			summary := proxyNodeSummary(meta, original, index)
			_, _ = io.WriteString(digest, summary.ID)
			_, _ = digest.Write([]byte{0})
			_, _ = io.WriteString(digest, runtimeNames[summary.ID])
			_, _ = digest.Write([]byte{0})
		}
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func (c *ProxyCatalog) runtimeNodesWithCandidate(candidate proxyUploadCandidate) []map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	configs := append([]proxyConfigMetadata(nil), c.index.Configs...)
	configs = append(configs, candidate.source.Meta)
	sources := make(map[string]proxySource, len(c.sources)+1)
	for name, source := range c.sources {
		sources[name] = source
	}
	sources[candidate.name] = candidate.source
	return runtimeNodes(configs, sources)
}

func runtimeNodes(configs []proxyConfigMetadata, sources map[string]proxySource) []map[string]any {
	runtimeNames := runtimeNodeNames(configs, sources)
	var nodes []map[string]any
	for _, meta := range configs {
		source := sources[meta.Name]
		sourceNames := make(map[string]string, len(source.Nodes))
		for index, node := range source.Nodes {
			original, _ := node["name"].(string)
			sourceNames[original] = runtimeNames[proxyNodeSummary(meta, original, index).ID]
		}
		for _, node := range source.Nodes {
			copyNode := cloneProxyMap(node)
			original, _ := copyNode["name"].(string)
			rewriteProxyNodeReferences(copyNode, sourceNames)
			copyNode["name"] = sourceNames[original]
			nodes = append(nodes, copyNode)
		}
	}
	return nodes
}

// Mihomo proxy definitions can depend on another proxy from the same YAML,
// most notably through dialer-proxy. Runtime names are globally namespaced, so
// every supported proxy-name field must be rewritten alongside name itself.
var proxyNodeReferenceFields = map[string]struct{}{
	"dialer-proxy": {},
	"detour":       {},
	"outbound":     {},
	"proxy":        {},
}

func rewriteProxyNodeReferences(node map[string]any, names map[string]string) {
	for field, value := range node {
		if _, isReference := proxyNodeReferenceFields[field]; !isReference {
			continue
		}
		node[field] = rewriteProxyNodeReference(value, names)
	}
}

func rewriteProxyNodeReference(value any, names map[string]string) any {
	switch current := value.(type) {
	case string:
		if replacement, ok := names[current]; ok {
			return replacement
		}
		return current
	case []any:
		copyValues := make([]any, len(current))
		for index, item := range current {
			copyValues[index] = rewriteProxyNodeReference(item, names)
		}
		return copyValues
	case []string:
		copyValues := make([]string, len(current))
		for index, item := range current {
			if replacement, ok := names[item]; ok {
				copyValues[index] = replacement
			} else {
				copyValues[index] = item
			}
		}
		return copyValues
	default:
		return value
	}
}

func (c *ProxyCatalog) FindNode(nodeID string) (string, bool) {
	stableID, ok := c.NormalizeNodeID(nodeID)
	if !ok {
		return "", false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	runtimeNames := c.runtimeNodeNamesLocked()
	for _, meta := range c.index.Configs {
		source := c.sources[meta.Name]
		for index, node := range source.Nodes {
			original, _ := node["name"].(string)
			summary := c.nodeSummary(meta, original, index)
			if summary.ID == stableID {
				return runtimeNames[summary.ID], true
			}
		}
	}
	return "", false
}

func (c *ProxyCatalog) NormalizeNodeID(nodeID string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, meta := range c.index.Configs {
		source := c.sources[meta.Name]
		for index, node := range source.Nodes {
			original, _ := node["name"].(string)
			summary := c.nodeSummary(meta, original, index)
			if summary.ID == nodeID {
				return summary.ID, true
			}
			if strings.TrimSpace(meta.ID) == "" && (proxyNodeID(meta.Name, original) == nodeID || legacyProxyNodeID(meta.Name, index, original) == nodeID) {
				return summary.ID, true
			}
		}
	}
	return "", false
}

type proxyListener struct {
	poolID          string
	port            int
	proxy           string
	listener        string
	generation      uint64
	lastUsed        time.Time
	active          int
	removeRequested bool
}

type proxyEndpoint struct {
	URL          string
	Node         string
	SelectedNode string
	Key          string
	Generation   uint64
}

type proxyRequestError struct {
	PoolKey string
	Node    string
	Err     error
}

func (e *proxyRequestError) Error() string { return fmt.Sprintf("proxy %s failed: %v", e.Node, e.Err) }
func (e *proxyRequestError) Unwrap() error { return e.Err }

type proxyLeaseRoundTripper struct {
	base       http.RoundTripper
	manager    *ProxyManager
	key        string
	node       string
	generation uint64
}

func (t *proxyLeaseRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if !t.manager.markListenerActive(t.key, t.generation, 1) {
		return nil, &proxyRequestError{PoolKey: t.key, Node: t.node, Err: errors.New("代理 listener 已更新")}
	}
	response, err := t.base.RoundTrip(request)
	if err != nil {
		t.manager.markListenerActive(t.key, t.generation, -1)
		if isLocalProxyListenerError(err) {
			return nil, &proxyRequestError{PoolKey: t.key, Node: t.node, Err: err}
		}
		return nil, err
	}
	if response == nil || response.Body == nil {
		t.manager.markListenerActive(t.key, t.generation, -1)
		return response, nil
	}
	response.Body = &proxyLeaseBody{
		ReadCloser: response.Body,
		release:    func() { t.manager.markListenerActive(t.key, t.generation, -1) },
	}
	return response, nil
}

type proxyLeaseBody struct {
	io.ReadCloser
	releaseOnce sync.Once
	release     func()
}

func (b *proxyLeaseBody) Read(buffer []byte) (int, error) {
	// A response-body failure occurs after Mihomo has established the request.
	// It may be caused by the upstream server, so preserve its original error
	// instead of treating every truncated response as a local proxy failure.
	return b.ReadCloser.Read(buffer)
}

func (b *proxyLeaseBody) Close() error {
	err := b.ReadCloser.Close()
	b.releaseOnce.Do(b.release)
	return err
}

func wrapProxyTransport(base http.RoundTripper, manager *ProxyManager, key, node string, generation uint64) http.RoundTripper {
	if base == nil || manager == nil || strings.TrimSpace(key) == "" {
		return base
	}
	return &proxyLeaseRoundTripper{base: base, manager: manager, key: key, node: node, generation: generation}
}

func isLocalProxyListenerError(err error) bool {
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}
	return isLoopbackNetAddr(opErr.Addr) || isLoopbackNetAddr(opErr.Source)
}

func isLoopbackNetAddr(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	switch value := addr.(type) {
	case *net.TCPAddr:
		return value.IP.IsLoopback()
	case *net.UDPAddr:
		return value.IP.IsLoopback()
	case *net.IPAddr:
		return value.IP.IsLoopback()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

type ProxyManager struct {
	catalog     *ProxyCatalog
	speedTests  *proxySpeedTestStore
	mu          sync.Mutex
	process     *exec.Cmd
	processDone chan struct{}
	stopping    bool
	workDir     string
	binary      string
	secret      string
	control     int
	// listeners is keyed by a physical listener ID. poolListeners maps a
	// logical pool to its current physical listener. Retired listeners remain
	// in listeners until their leases have drained.
	listeners        map[string]proxyListener
	poolListeners    map[string]string
	nextGeneration   uint64
	testSem          chan struct{}
	closed           bool
	recoveryFailures int
	recovering       bool
	nextRecoveryAt   time.Time
	cleanupStop      chan struct{}
	cleanupOnce      sync.Once
	// runtimeGeneration advances whenever the running Mihomo configuration is
	// published again. A url-test result belongs to exactly one such runtime;
	// reusing it after a reload can expose Mihomo's first-member fallback.
	runtimeGeneration uint64
	// runtimeHasAutoGroup records whether the currently running configuration
	// contains proxyAutoGroupName. A batch-only startup deliberately omits it.
	runtimeHasAutoGroup bool
	autoSelection       proxyAutoSelection
	autoProbe           *proxyAutoProbe
	autoFailureKey      string
	autoFailureUntil    time.Time
	lastAutoProbe       time.Time
	// autoProbeTimeout is a test-only override. Production uses the dedicated
	// group-probe total budget above, while fixed-node tests remain at 10s.
	autoProbeTimeout time.Duration
	// batchTestTimeout is a test-only override for the whole batch latency
	// request. Production uses proxyBatchTestTimeout.
	batchTestTimeout time.Duration
	// autoWatchPools retains the logical auto-pool intent even if an initial
	// or periodic probe has no usable nodes and its unpublished listener is
	// removed. It lets the single shared Mihomo process keep probing and recover
	// without waiting for another provider request.
	autoWatchPools map[string]struct{}
	// scopedAutoGroups is the real account-pool routing path. Each group is
	// derived from one user's visible YAML projection and is emitted into the
	// same shared Mihomo configuration as every other active group.
	scopedAutoGroups     map[string]proxyScopedAutoGroup
	scopedAutoStates     map[string]*proxyScopedAutoState
	scopedAutoWatchPools map[string]struct{}
	// runtimeAutoGroups records the native groups actually present in the live
	// config. A batch-only startup intentionally leaves it empty.
	runtimeAutoGroups map[string]struct{}
}

type proxyAutoSelection struct {
	generation uint64
	node       string
	delay      int64
}

type proxyAutoProbe struct {
	generation uint64
	done       chan struct{}
	cancel     context.CancelFunc
	waiters    int
	complete   bool
	selection  proxyAutoSelection
	err        error
}

type proxyScopedAutoState struct {
	selection    proxyAutoSelection
	probe        *proxyAutoProbe
	failureKey   string
	failureUntil time.Time
	lastProbe    time.Time
}

type proxyRuntimeSnapshot struct {
	generation uint64
	control    int
	secret     string
	nodes      []string
	nodeKey    string
	catalogKey string
}

func NewProxyManager(catalog *ProxyCatalog) *ProxyManager {
	return &ProxyManager{
		catalog:              catalog,
		listeners:            make(map[string]proxyListener),
		poolListeners:        make(map[string]string),
		autoWatchPools:       make(map[string]struct{}),
		scopedAutoGroups:     make(map[string]proxyScopedAutoGroup),
		scopedAutoStates:     make(map[string]*proxyScopedAutoState),
		scopedAutoWatchPools: make(map[string]struct{}),
		runtimeAutoGroups:    make(map[string]struct{}),
		cleanupStop:          make(chan struct{}),
		// The UI applies the user-configured YAML worker limit. Keep the
		// process-wide ceiling aligned with the maximum supported temporary
		// Mihomo listener count.
		testSem: make(chan struct{}, proxyMaxSpeedTestWorkers),
	}
}

func (m *ProxyManager) Refresh() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("代理服务已停止")
	}
	// Refresh can replace the catalog while Mihomo is stopped, so any previous
	// url-test result is no longer tied to the current runtime node set.
	m.invalidateAutoCatalogLocked()
	if m.process == nil {
		// Listing/refreshing shared YAML must not force a Mihomo download or
		// startup. The catalog is validated when a config is uploaded or first
		// used; a running process is the only case that needs a runtime reload.
		return nil
	}
	_, err := m.reloadOrRestartLocked()
	return err
}

func (m *ProxyManager) validateCatalogLocked() error {
	return m.validateRuntimeNodesLocked(m.catalog.runtimeNodes())
}

func (m *ProxyManager) validateCatalogCandidateLocked(candidate proxyUploadCandidate) error {
	return m.validateRuntimeNodesLocked(m.catalog.runtimeNodesWithCandidate(candidate))
}

func (m *ProxyManager) validateRuntimeNodesLocked(nodes []map[string]any) error {
	if runtime.GOOS != "linux" {
		// Mihomo is only started on Linux in this build; keep catalog uploads
		// usable on other platforms and validate them when the runtime is used.
		return nil
	}
	if m.workDir == "" {
		home, err := getUserHomeDir()
		if err != nil {
			return err
		}
		m.workDir = filepath.Join(home, appSettingsDir, proxyRuntimeDirName)
	}
	if err := os.MkdirAll(m.workDir, 0o700); err != nil {
		return err
	}
	if m.binary == "" {
		binary, err := ensureMihomoBinary(m.workDir)
		if err != nil {
			return err
		}
		m.binary = binary
	}
	if m.process == nil {
		control, err := availablePortExcluding(m.listeners, 0)
		if err != nil {
			return err
		}
		m.control = control
		m.secret = fmt.Sprintf("%x", sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10))))
	}
	path := filepath.Join(m.workDir, "config.validate.yaml")
	defer os.Remove(path)
	if err := m.writeRuntimeConfigWithNodesLocked(path, nodes); err != nil {
		return err
	}
	return m.validateRuntimeConfigLocked(path, context.Background())
}

// ProxyURLForPoolWithSpec is the user-scoped counterpart to
// ProxyURLForPool. The spec is produced by ProxyService from authenticated
// server state; callers cannot inject an arbitrary node list into Mihomo.
func (m *ProxyManager) ProxyURLForPoolWithSpec(ctx context.Context, config *AccountPoolProxyConfig, spec proxyRouteSpec) (proxyEndpoint, error) {
	if config == nil || !config.Enabled {
		return proxyEndpoint{}, nil
	}
	if strings.TrimSpace(spec.poolKey) == "" {
		return proxyEndpoint{}, errors.New("代理号池 ID 不能为空")
	}
	if config.Selection == AccountPoolProxySelectionNode {
		if strings.TrimSpace(spec.fixedNode) == "" {
			return proxyEndpoint{}, errors.New("选择的代理节点已隐藏或不可用")
		}
		m.mu.Lock()
		delete(m.scopedAutoWatchPools, spec.poolKey)
		delete(m.scopedAutoGroups, spec.poolKey)
		listenerKey, err := m.ensureRunningLocked(ctx, spec.poolKey, spec.fixedNode)
		if err != nil {
			m.mu.Unlock()
			return proxyEndpoint{}, err
		}
		endpoint, endpointErr := m.endpointForListenerLocked(listenerKey)
		m.mu.Unlock()
		return endpoint, endpointErr
	}
	if config.Selection != "" && config.Selection != AccountPoolProxySelectionAuto {
		return proxyEndpoint{}, fmt.Errorf("未知代理选择方式: %s", config.Selection)
	}
	if spec.autoGroup == nil || len(spec.autoGroup.nodes) == 0 {
		return proxyEndpoint{}, errors.New("没有可用代理节点")
	}
	return m.proxyURLForScopedAutoPool(ctx, spec, 0)
}

func (m *ProxyManager) proxyURLForScopedAutoPool(ctx context.Context, spec proxyRouteSpec, retry int) (proxyEndpoint, error) {
	group := spec.autoGroup
	if group == nil {
		return proxyEndpoint{}, errors.New("没有可用代理节点")
	}
	m.mu.Lock()
	m.installScopedAutoGroupLocked(*group)
	if m.scopedAutoWatchPools == nil {
		m.scopedAutoWatchPools = make(map[string]struct{})
	}
	m.scopedAutoWatchPools[spec.poolKey] = struct{}{}
	listenerKey, err := m.ensureScopedAutoRunningLocked(ctx, spec.poolKey, *group)
	if err != nil {
		m.mu.Unlock()
		return proxyEndpoint{}, err
	}
	m.mu.Unlock()

	selection, err := m.scopedAutoSelectionForRuntime(ctx, *group, false)
	if err != nil {
		m.removeUnreadyScopedAutoListener(spec.poolKey, listenerKey, group.name)
		return proxyEndpoint{}, err
	}
	m.mu.Lock()
	if ctx.Err() != nil {
		m.mu.Unlock()
		m.removeUnreadyScopedAutoListener(spec.poolKey, listenerKey, group.name)
		return proxyEndpoint{}, ctx.Err()
	}
	currentKey, listener, ok := m.currentListenerLocked(spec.poolKey)
	currentGroup, groupOK := m.scopedAutoGroups[spec.poolKey]
	if !ok || currentKey != listenerKey || listener.removeRequested || listener.proxy != group.name || !groupOK ||
		currentGroup.name != group.name || currentGroup.candidateKey != group.candidateKey || currentGroup.testURL != group.testURL ||
		selection.generation != m.runtimeGeneration {
		m.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return proxyEndpoint{}, err
		}
		if retry >= 2 {
			return proxyEndpoint{}, errors.New("Mihomo 配置正在刷新，请稍后重试")
		}
		return m.proxyURLForScopedAutoPool(ctx, spec, retry+1)
	}
	endpoint, endpointErr := m.endpointForListenerLocked(listenerKey)
	endpoint.SelectedNode = selection.node
	m.mu.Unlock()
	return endpoint, endpointErr
}

func (m *ProxyManager) installScopedAutoGroupLocked(group proxyScopedAutoGroup) bool {
	if m.scopedAutoGroups == nil {
		m.scopedAutoGroups = make(map[string]proxyScopedAutoGroup)
	}
	previous, exists := m.scopedAutoGroups[group.poolKey]
	if exists && previous.name == group.name && previous.candidateKey == group.candidateKey && previous.testURL == group.testURL && sameStringSlice(previous.nodes, group.nodes) {
		return false
	}
	m.scopedAutoGroups[group.poolKey] = group
	if m.scopedAutoStates == nil {
		m.scopedAutoStates = make(map[string]*proxyScopedAutoState)
	}
	if previous.name != "" && previous.name != group.name {
		delete(m.scopedAutoStates, previous.name)
	}
	if _, ok := m.scopedAutoStates[group.name]; !ok {
		m.scopedAutoStates[group.name] = &proxyScopedAutoState{}
	}
	return true
}

func (m *ProxyManager) ensureScopedAutoRunningLocked(ctx context.Context, poolID string, group proxyScopedAutoGroup) (string, error) {
	if m.closed {
		return "", errors.New("代理服务已停止")
	}
	key, listener, ok := m.currentListenerLocked(poolID)
	if ok && !listener.removeRequested && listener.proxy == group.name {
		if m.process == nil {
			if m.recovering || time.Now().Before(m.nextRecoveryAt) {
				return "", errors.New("Mihomo 正在恢复，请稍后重试")
			}
			if err := m.startLocked(ctx); err != nil {
				return "", err
			}
		} else if _, published := m.runtimeAutoGroups[group.name]; !published {
			if _, err := m.reloadOrRestartLocked(); err != nil {
				return "", err
			}
		}
		return key, nil
	}

	state := m.snapshotListenersLocked()
	if ok {
		listener.removeRequested = true
		m.listeners[key] = listener
		if listener.active == 0 {
			m.removeListenerLocked(key)
		}
	}
	newKey, _, err := m.addCurrentListenerLocked(poolID, group.name)
	if err != nil {
		m.restoreListenersLocked(state, false)
		return "", err
	}
	if m.process == nil {
		if m.recovering || time.Now().Before(m.nextRecoveryAt) {
			m.restoreListenersLocked(state, false)
			return "", errors.New("Mihomo 正在恢复，请稍后重试")
		}
		err = m.startLocked(ctx)
	} else {
		var restarted bool
		restarted, err = m.reloadOrRestartLocked()
		if err != nil {
			m.restoreListenersLocked(state, restarted)
		}
	}
	if err != nil {
		return "", err
	}
	return newKey, nil
}

func (m *ProxyManager) removeUnreadyScopedAutoListener(poolID, listenerKey, groupName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	currentKey, listener, ok := m.currentListenerLocked(poolID)
	if !ok || currentKey != listenerKey || listener.proxy != groupName {
		return
	}
	if state := m.scopedAutoStates[groupName]; state != nil && state.probe != nil && state.probe.generation == m.runtimeGeneration && state.probe.waiters > 0 {
		return
	}
	state := m.snapshotListenersLocked()
	if listener.active > 0 {
		listener.removeRequested = true
		m.listeners[listenerKey] = listener
		delete(m.poolListeners, poolID)
	} else {
		m.removeListenerLocked(listenerKey)
	}
	if m.process == nil || m.closed {
		return
	}
	if restarted, err := m.reloadOrRestartLocked(); err != nil {
		m.restoreListenersLocked(state, restarted)
		fmt.Printf("[proxy] 清理未就绪自动 listener 失败: %v\n", err)
	}
}

func (m *ProxyManager) ProxyURLForPool(ctx context.Context, poolID string, config *AccountPoolProxyConfig) (proxyEndpoint, error) {
	return m.proxyURLForPool(ctx, poolID, config, 0)
}

func (m *ProxyManager) proxyURLForPool(ctx context.Context, poolID string, config *AccountPoolProxyConfig, retry int) (proxyEndpoint, error) {
	if config == nil || !config.Enabled {
		return proxyEndpoint{}, nil
	}
	if strings.TrimSpace(poolID) == "" {
		return proxyEndpoint{}, errors.New("代理号池 ID 不能为空")
	}
	nodeName := ""
	auto := config.Selection == AccountPoolProxySelectionAuto
	if config.Selection == AccountPoolProxySelectionNode {
		m.mu.Lock()
		var ok bool
		nodeName, ok = m.catalog.FindNode(config.ProxyNodeID)
		m.mu.Unlock()
		if !ok {
			return proxyEndpoint{}, errors.New("选择的代理节点不存在或已失效")
		}
	} else if auto {
		if _, err := m.autoProxyTarget(); err != nil {
			return proxyEndpoint{}, err
		}
		nodeName = proxyAutoGroupName
	} else {
		return proxyEndpoint{}, fmt.Errorf("未知代理选择方式: %s", config.Selection)
	}
	m.mu.Lock()
	if auto {
		if m.autoWatchPools == nil {
			m.autoWatchPools = make(map[string]struct{})
		}
		m.autoWatchPools[poolID] = struct{}{}
	} else {
		delete(m.autoWatchPools, poolID)
	}
	listenerKey, err := m.ensureRunningLocked(ctx, poolID, nodeName)
	if err != nil {
		m.mu.Unlock()
		return proxyEndpoint{}, err
	}
	if !auto {
		endpoint, endpointErr := m.endpointForListenerLocked(listenerKey)
		m.mu.Unlock()
		return endpoint, endpointErr
	}
	m.mu.Unlock()

	selection, err := m.autoSelectionForRuntime(ctx)
	if err != nil {
		m.removeUnreadyAutoListener(poolID, listenerKey)
		return proxyEndpoint{}, err
	}
	m.mu.Lock()
	if ctx.Err() != nil {
		m.mu.Unlock()
		m.removeUnreadyAutoListener(poolID, listenerKey)
		return proxyEndpoint{}, ctx.Err()
	}
	currentKey, listener, ok := m.currentListenerLocked(poolID)
	if !ok || currentKey != listenerKey || listener.removeRequested || listener.proxy != proxyAutoGroupName ||
		m.autoSelection.generation != selection.generation || m.runtimeGeneration != selection.generation {
		m.mu.Unlock()
		// A listener/configuration reload raced the probe. Retry against the
		// current runtime instead of publishing an endpoint for stale state.
		if err := ctx.Err(); err != nil {
			return proxyEndpoint{}, err
		}
		if retry >= 2 {
			return proxyEndpoint{}, errors.New("Mihomo 配置正在刷新，请稍后重试")
		}
		return m.proxyURLForPool(ctx, poolID, config, retry+1)
	}
	endpoint, endpointErr := m.endpointForListenerLocked(listenerKey)
	endpoint.SelectedNode = selection.node
	m.mu.Unlock()
	return endpoint, endpointErr
}

// removeUnreadyAutoListener removes a listener created for an auto request
// that never obtained a valid full-group probe. It deliberately leaves an
// active shared probe alone so another concurrent caller can still complete it.
func (m *ProxyManager) removeUnreadyAutoListener(poolID, listenerKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	currentKey, listener, ok := m.currentListenerLocked(poolID)
	if !ok || currentKey != listenerKey || listener.proxy != proxyAutoGroupName {
		return
	}
	if probe := m.autoProbe; probe != nil && probe.generation == m.runtimeGeneration && probe.waiters > 0 {
		return
	}
	state := m.snapshotListenersLocked()
	if listener.active > 0 {
		listener.removeRequested = true
		m.listeners[listenerKey] = listener
		delete(m.poolListeners, poolID)
	} else {
		m.removeListenerLocked(listenerKey)
	}
	if m.process == nil || m.closed {
		return
	}
	if restarted, err := m.reloadOrRestartLocked(); err != nil {
		m.restoreListenersLocked(state, restarted)
		fmt.Printf("[proxy] 清理未就绪自动 listener 失败: %v\n", err)
	}
}

func (m *ProxyManager) endpointForListenerLocked(listenerKey string) (proxyEndpoint, error) {
	listener, ok := m.listeners[listenerKey]
	if !ok || listener.removeRequested {
		return proxyEndpoint{}, errors.New("代理 listener 在启动时已失效")
	}
	listener.lastUsed = time.Now()
	m.listeners[listenerKey] = listener
	return proxyEndpoint{
		URL:          fmt.Sprintf("http://127.0.0.1:%d", listener.port),
		Node:         listener.proxy,
		SelectedNode: listener.proxy,
		Key:          listenerKey,
		Generation:   listener.generation,
	}, nil
}

func (m *ProxyManager) autoProxyTarget() (string, error) {
	if m.catalog == nil || len(m.catalog.runtimeNodes()) == 0 {
		return "", errors.New("没有可用代理节点")
	}
	// This is only the configured listener target. Callers must first wait for
	// autoSelectionForRuntime before publishing an endpoint that uses it.
	return proxyAutoGroupName, nil
}

func (m *ProxyManager) advanceRuntimeGenerationLocked() {
	m.runtimeGeneration++
	if m.runtimeGeneration == 0 {
		m.runtimeGeneration++
	}
	m.autoSelection = proxyAutoSelection{}
	if probe := m.autoProbe; probe != nil && !probe.complete {
		probe.cancel()
	}
	// A stale probe is allowed to finish so waiters can be released, but it can
	// never populate the selection for this new configuration generation.
	m.autoProbe = nil
	for _, state := range m.scopedAutoStates {
		state.selection = proxyAutoSelection{}
		if probe := state.probe; probe != nil && !probe.complete {
			probe.cancel()
		}
		state.probe = nil
	}
}

// invalidateAutoCatalogLocked is reserved for catalog mutations (upload,
// delete, refresh). Listener-only reloads must invalidate a successful
// selection, but retain a short all-failed cooldown for the unchanged node
// catalog so repeated requests cannot trigger a full group probe storm.
func (m *ProxyManager) invalidateAutoCatalogLocked() {
	m.advanceRuntimeGenerationLocked()
	m.autoFailureKey = ""
	m.autoFailureUntil = time.Time{}
	m.lastAutoProbe = time.Time{}
	for _, state := range m.scopedAutoStates {
		state.failureKey = ""
		state.failureUntil = time.Time{}
		state.lastProbe = time.Time{}
	}
}

func (m *ProxyManager) runtimeSnapshotLocked() (proxyRuntimeSnapshot, error) {
	if m.closed {
		return proxyRuntimeSnapshot{}, errors.New("代理服务已停止")
	}
	if m.process == nil || m.control == 0 || strings.TrimSpace(m.secret) == "" {
		return proxyRuntimeSnapshot{}, errors.New("Mihomo 未运行")
	}
	if m.runtimeGeneration == 0 {
		m.advanceRuntimeGenerationLocked()
	}
	nodes, catalogKey := m.catalog.runtimeNodesAndCatalogKey()
	names := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if name, ok := node["name"].(string); ok && strings.TrimSpace(name) != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return proxyRuntimeSnapshot{}, errors.New("没有可用代理节点")
	}
	return proxyRuntimeSnapshot{
		generation: m.runtimeGeneration,
		control:    m.control,
		secret:     m.secret,
		nodes:      names,
		nodeKey:    strings.Join(names, "\x00"),
		catalogKey: catalogKey,
	}, nil
}

func (m *ProxyManager) runtimeMatchesLocked(snapshot proxyRuntimeSnapshot) bool {
	return !m.closed && m.process != nil && m.runtimeGeneration == snapshot.generation &&
		m.control == snapshot.control && m.secret == snapshot.secret
}

func (m *ProxyManager) batchRuntimeMatches(snapshot proxyRuntimeSnapshot) bool {
	m.mu.Lock()
	matches := m.runtimeMatchesLocked(snapshot)
	m.mu.Unlock()
	return matches
}

func (m *ProxyManager) autoSelectionForRuntime(ctx context.Context) (proxyAutoSelection, error) {
	return m.autoSelectionForRuntimeMode(ctx, false)
}

// refreshAutoSelectionForRuntime forces a fresh full-group probe for the
// current runtime. It is used by the periodic scheduler; request callers use
// autoSelectionForRuntime so a known-good result remains immediately usable.
func (m *ProxyManager) refreshAutoSelectionForRuntime(ctx context.Context) (proxyAutoSelection, error) {
	return m.autoSelectionForRuntimeMode(ctx, true)
}

func (m *ProxyManager) autoSelectionForRuntimeMode(ctx context.Context, force bool) (proxyAutoSelection, error) {
	for {
		m.mu.Lock()
		snapshot, err := m.runtimeSnapshotLocked()
		if err != nil {
			m.mu.Unlock()
			return proxyAutoSelection{}, err
		}
		if !force {
			selection := m.autoSelection
			if selection.generation == snapshot.generation && selection.node != "" {
				m.mu.Unlock()
				return selection, nil
			}
		}
		if !force && m.autoFailureKey == snapshot.nodeKey && time.Now().Before(m.autoFailureUntil) {
			m.mu.Unlock()
			return proxyAutoSelection{}, errors.New("自动选择没有可用代理节点")
		}

		probe := m.autoProbe
		if probe == nil || probe.generation != snapshot.generation {
			probeTimeout := m.autoProbeRequestTimeoutLocked()
			probeContext, cancel := context.WithTimeout(context.Background(), probeTimeout)
			probe = &proxyAutoProbe{
				generation: snapshot.generation,
				done:       make(chan struct{}),
				cancel:     cancel,
			}
			m.autoProbe = probe
			m.lastAutoProbe = time.Now()
			go m.runAutoProbe(probeContext, probe, snapshot, probeTimeout)
		}
		probe.waiters++
		done := probe.done
		m.mu.Unlock()

		select {
		case <-ctx.Done():
			m.leaveAutoProbe(probe)
			return proxyAutoSelection{}, ctx.Err()
		case <-done:
		}

		m.mu.Lock()
		probe.waiters--
		selection, probeErr := probe.selection, probe.err
		matches := m.runtimeMatchesLocked(snapshot)
		m.mu.Unlock()
		if !matches {
			if err := ctx.Err(); err != nil {
				return proxyAutoSelection{}, err
			}
			continue
		}
		if probeErr != nil {
			return proxyAutoSelection{}, probeErr
		}
		if selection.generation != snapshot.generation || selection.node == "" {
			continue
		}
		return selection, nil
	}
}

func (m *ProxyManager) autoProbeRequestTimeoutLocked() time.Duration {
	if m.autoProbeTimeout > 0 {
		return m.autoProbeTimeout
	}
	return proxyAutoProbeTimeout
}

// refreshActiveAutoSelection performs one periodic probe only while at least
// one auto pool is currently configured or being watched for recovery. It
// intentionally drops the manager lock before issuing the controller request.
func (m *ProxyManager) refreshActiveAutoSelection(ctx context.Context) (bool, error) {
	m.mu.Lock()
	active := m.process != nil && !m.closed && m.hasActiveAutoListenerLocked()
	m.mu.Unlock()
	if !active {
		return false, nil
	}
	_, err := m.refreshAutoSelectionForRuntime(ctx)
	return true, err
}

// refreshDueAutoSelection is the scheduler entry point. The cleanup loop runs
// every minute for listener maintenance, while full group health checks remain
// on the deliberately conservative auto-probe interval.
func (m *ProxyManager) refreshDueAutoSelection(ctx context.Context) (bool, error) {
	m.mu.Lock()
	active := m.process != nil && !m.closed && m.hasActiveAutoListenerLocked()
	due := m.lastAutoProbe.IsZero() || time.Since(m.lastAutoProbe) >= proxyAutoProbeInterval
	m.mu.Unlock()
	if !active || !due {
		return false, nil
	}
	_, err := m.refreshAutoSelectionForRuntime(ctx)
	return true, err
}

// refreshDueScopedAutoSelections gives each user-visible url-test group its
// own periodic health check. It deliberately never falls back to the legacy
// global group, which could include YAMLs hidden by that user.
func (m *ProxyManager) refreshDueScopedAutoSelections(ctx context.Context) (bool, error) {
	m.mu.Lock()
	if m.process == nil || m.closed || len(m.scopedAutoWatchPools) == 0 {
		m.mu.Unlock()
		return false, nil
	}
	groups := make([]proxyScopedAutoGroup, 0, len(m.scopedAutoWatchPools))
	for poolKey := range m.scopedAutoWatchPools {
		group, ok := m.scopedAutoGroups[poolKey]
		if !ok {
			continue
		}
		state := m.scopedAutoStates[group.name]
		if state == nil || state.lastProbe.IsZero() || time.Since(state.lastProbe) >= proxyAutoProbeInterval {
			groups = append(groups, group)
		}
	}
	m.mu.Unlock()
	if len(groups) == 0 {
		return false, nil
	}
	var firstErr error
	for _, group := range groups {
		if _, err := m.scopedAutoSelectionForRuntime(ctx, group, true); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return true, firstErr
}

func (m *ProxyManager) hasActiveAutoListenerLocked() bool {
	return len(m.autoWatchPools) > 0
}

func (m *ProxyManager) clearAutoWatchPool(poolID string) {
	m.mu.Lock()
	delete(m.autoWatchPools, poolID)
	m.mu.Unlock()
}

func (m *ProxyManager) leaveAutoProbe(probe *proxyAutoProbe) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if probe.waiters > 0 {
		probe.waiters--
	}
	if probe.waiters != 0 {
		return
	}
	if !probe.complete {
		if m.autoProbe == probe {
			m.autoProbe = nil
		}
		probe.cancel()
		return
	}
}

func (m *ProxyManager) runAutoProbe(ctx context.Context, probe *proxyAutoProbe, snapshot proxyRuntimeSnapshot, requestTimeout time.Duration) {
	selection, err := m.probeAutoGroup(ctx, snapshot, requestTimeout)
	m.mu.Lock()
	probe.selection = selection
	probe.err = err
	probe.complete = true
	if err == nil && m.autoProbe == probe && m.runtimeMatchesLocked(snapshot) {
		m.autoSelection = selection
		m.autoFailureKey = ""
		m.autoFailureUntil = time.Time{}
		m.autoProbe = nil
	}
	if err != nil && !errors.Is(ctx.Err(), context.Canceled) && m.autoProbe == probe && m.runtimeMatchesLocked(snapshot) {
		// A periodic probe is authoritative for this runtime. Once it sees no
		// usable candidate, do not keep routing through an old url-test result.
		m.autoSelection = proxyAutoSelection{}
		m.autoFailureKey = snapshot.nodeKey
		m.autoFailureUntil = time.Now().Add(proxyAutoProbeRetryDelay)
		m.autoProbe = nil
	}
	close(probe.done)
	m.mu.Unlock()
	probe.cancel()
}

func (m *ProxyManager) probeAutoGroup(ctx context.Context, snapshot proxyRuntimeSnapshot, requestTimeout time.Duration) (proxyAutoSelection, error) {
	path := "/group/" + url.PathEscape(proxyAutoGroupName) + "/delay?timeout=10000&url=" + url.QueryEscape(proxyHealthURL)
	delays := make(map[string]int64)
	if err := m.controllerRequestAtWithTimeout(ctx, snapshot.control, snapshot.secret, requestTimeout, http.MethodGet, path, nil, &delays); err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return proxyAutoSelection{}, ctx.Err()
		}
		return proxyAutoSelection{}, errors.New("自动选择没有可用代理节点")
	}
	selection := proxyAutoSelection{generation: snapshot.generation}
	for _, name := range snapshot.nodes {
		delay, ok := delays[name]
		if !ok || delay <= 0 {
			continue
		}
		if selection.node == "" || delay < selection.delay {
			selection.node = name
			selection.delay = delay
		}
	}
	if selection.node == "" {
		return proxyAutoSelection{}, errors.New("自动选择没有可用代理节点")
	}
	return selection, nil
}

func (m *ProxyManager) scopedRuntimeSnapshotLocked(group proxyScopedAutoGroup) (proxyRuntimeSnapshot, error) {
	if m.closed {
		return proxyRuntimeSnapshot{}, errors.New("代理服务已停止")
	}
	if m.process == nil || m.control == 0 || strings.TrimSpace(m.secret) == "" {
		return proxyRuntimeSnapshot{}, errors.New("Mihomo 未运行")
	}
	current, ok := m.scopedAutoGroups[group.poolKey]
	if !ok || current.name != group.name || current.candidateKey != group.candidateKey || current.testURL != group.testURL {
		return proxyRuntimeSnapshot{}, errors.New("代理可见范围已刷新，请重试")
	}
	if _, ok := m.runtimeAutoGroups[group.name]; !ok {
		return proxyRuntimeSnapshot{}, errors.New("Mihomo 自动选择组未就绪")
	}
	if m.runtimeGeneration == 0 {
		m.advanceRuntimeGenerationLocked()
	}
	if len(group.nodes) == 0 {
		return proxyRuntimeSnapshot{}, errors.New("没有可用代理节点")
	}
	return proxyRuntimeSnapshot{
		generation: m.runtimeGeneration,
		control:    m.control,
		secret:     m.secret,
		nodes:      append([]string(nil), group.nodes...),
		nodeKey:    group.candidateKey,
	}, nil
}

func (m *ProxyManager) scopedRuntimeMatchesLocked(snapshot proxyRuntimeSnapshot, group proxyScopedAutoGroup) bool {
	current, ok := m.scopedAutoGroups[group.poolKey]
	if !ok || current.name != group.name || current.candidateKey != group.candidateKey || current.testURL != group.testURL || !m.runtimeMatchesLocked(snapshot) {
		return false
	}
	_, published := m.runtimeAutoGroups[group.name]
	return published
}

// scopedAutoSelectionForRuntime mirrors the legacy auto probe state while
// keeping probes, cache entries, and cooldowns isolated per user-visible
// Mihomo group.
func (m *ProxyManager) scopedAutoSelectionForRuntime(ctx context.Context, group proxyScopedAutoGroup, force bool) (proxyAutoSelection, error) {
	for {
		m.mu.Lock()
		snapshot, err := m.scopedRuntimeSnapshotLocked(group)
		if err != nil {
			m.mu.Unlock()
			return proxyAutoSelection{}, err
		}
		state := m.scopedAutoStates[group.name]
		if state == nil {
			state = &proxyScopedAutoState{}
			m.scopedAutoStates[group.name] = state
		}
		if !force && state.selection.generation == snapshot.generation && state.selection.node != "" {
			// A newer shared measurement may have arrived from another user's
			// bulk test. Re-evaluate it before reusing this runtime cache.
			if m.speedTests == nil {
				selection := state.selection
				m.mu.Unlock()
				return selection, nil
			}
		}
		if !force && m.speedTests != nil && m.catalog != nil {
			if selection, ok := m.speedTests.bestAutoSelection(
				normalizeScopedAutoTestURL(group.testURL),
				m.catalog.nodeIDsForRuntimeNames(snapshot.nodes),
			); ok {
				selection.generation = snapshot.generation
				state.selection = selection
				m.mu.Unlock()
				return selection, nil
			}
		}
		if !force && state.selection.generation == snapshot.generation && state.selection.node != "" {
			selection := state.selection
			m.mu.Unlock()
			return selection, nil
		}
		if !force && state.failureKey == snapshot.nodeKey && time.Now().Before(state.failureUntil) {
			m.mu.Unlock()
			return proxyAutoSelection{}, errors.New("自动选择没有可用代理节点")
		}
		probe := state.probe
		if probe == nil || probe.generation != snapshot.generation {
			probeTimeout := m.autoProbeRequestTimeoutLocked()
			probeContext, cancel := context.WithTimeout(context.Background(), probeTimeout)
			probe = &proxyAutoProbe{generation: snapshot.generation, done: make(chan struct{}), cancel: cancel}
			state.probe = probe
			state.lastProbe = time.Now()
			go m.runScopedAutoProbe(probeContext, probe, snapshot, group, probeTimeout)
		}
		probe.waiters++
		done := probe.done
		m.mu.Unlock()

		select {
		case <-ctx.Done():
			m.leaveScopedAutoProbe(group.name, probe)
			return proxyAutoSelection{}, ctx.Err()
		case <-done:
		}

		m.mu.Lock()
		if probe.waiters > 0 {
			probe.waiters--
		}
		selection, probeErr := probe.selection, probe.err
		matches := m.scopedRuntimeMatchesLocked(snapshot, group)
		m.mu.Unlock()
		if !matches {
			if err := ctx.Err(); err != nil {
				return proxyAutoSelection{}, err
			}
			return proxyAutoSelection{}, errors.New("代理可见范围已刷新，请重试")
		}
		if probeErr != nil {
			return proxyAutoSelection{}, probeErr
		}
		if selection.generation != snapshot.generation || selection.node == "" {
			continue
		}
		return selection, nil
	}
}

func (m *ProxyManager) leaveScopedAutoProbe(groupName string, probe *proxyAutoProbe) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if probe.waiters > 0 {
		probe.waiters--
	}
	if probe.waiters != 0 || probe.complete {
		return
	}
	if state := m.scopedAutoStates[groupName]; state != nil && state.probe == probe {
		state.probe = nil
	}
	probe.cancel()
}

func (m *ProxyManager) runScopedAutoProbe(ctx context.Context, probe *proxyAutoProbe, snapshot proxyRuntimeSnapshot, group proxyScopedAutoGroup, requestTimeout time.Duration) {
	selection, err := m.probeScopedAutoGroup(ctx, snapshot, group, requestTimeout)
	m.mu.Lock()
	probe.selection = selection
	probe.err = err
	probe.complete = true
	state := m.scopedAutoStates[group.name]
	if state != nil && state.probe == probe && m.scopedRuntimeMatchesLocked(snapshot, group) {
		if err == nil {
			state.selection = selection
			state.failureKey = ""
			state.failureUntil = time.Time{}
		} else if !errors.Is(ctx.Err(), context.Canceled) {
			state.selection = proxyAutoSelection{}
			state.failureKey = snapshot.nodeKey
			state.failureUntil = time.Now().Add(proxyAutoProbeRetryDelay)
		}
		state.probe = nil
	}
	close(probe.done)
	m.mu.Unlock()
	probe.cancel()
}

func (m *ProxyManager) probeScopedAutoGroup(ctx context.Context, snapshot proxyRuntimeSnapshot, group proxyScopedAutoGroup, requestTimeout time.Duration) (proxyAutoSelection, error) {
	path := "/group/" + url.PathEscape(group.name) + "/delay?timeout=10000&url=" + url.QueryEscape(normalizeScopedAutoTestURL(group.testURL))
	delays := make(map[string]int64)
	if err := m.controllerRequestAtWithTimeout(ctx, snapshot.control, snapshot.secret, requestTimeout, http.MethodGet, path, nil, &delays); err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return proxyAutoSelection{}, ctx.Err()
		}
		return proxyAutoSelection{}, errors.New("自动选择没有可用代理节点")
	}
	if m.speedTests != nil && m.catalog != nil {
		m.speedTests.recordAutoGroup(normalizeScopedAutoTestURL(group.testURL), m.catalog.nodeIDsForRuntimeNames(snapshot.nodes), delays)
	}
	selection := proxyAutoSelection{generation: snapshot.generation}
	for _, name := range snapshot.nodes {
		delay, ok := delays[name]
		if !ok || delay <= 0 {
			continue
		}
		if selection.node == "" || delay < selection.delay {
			selection.node = name
			selection.delay = delay
		}
	}
	if selection.node == "" {
		return proxyAutoSelection{}, errors.New("自动选择没有可用代理节点")
	}
	return selection, nil
}

func (m *ProxyManager) ensureRunningLocked(ctx context.Context, poolID, nodeName string) (string, error) {
	if m.closed {
		return "", errors.New("代理服务已停止")
	}
	key, listener, ok := m.currentListenerLocked(poolID)
	if ok && !listener.removeRequested && listener.proxy == nodeName &&
		(nodeName != proxyAutoGroupName || m.runtimeHasAutoGroup) {
		if m.process == nil {
			if m.recovering || time.Now().Before(m.nextRecoveryAt) {
				return "", errors.New("Mihomo 正在恢复，请稍后重试")
			}
			if err := m.startLocked(ctx); err != nil {
				return "", err
			}
		}
		return key, nil
	}

	state := m.snapshotListenersLocked()
	if ok {
		listener.removeRequested = true
		m.listeners[key] = listener
		if listener.active == 0 {
			m.removeListenerLocked(key)
		}
	}
	newKey, _, err := m.addCurrentListenerLocked(poolID, nodeName)
	if err != nil {
		m.restoreListenersLocked(state, false)
		return "", err
	}
	if m.process == nil {
		if m.recovering || time.Now().Before(m.nextRecoveryAt) {
			m.restoreListenersLocked(state, false)
			return "", errors.New("Mihomo 正在恢复，请稍后重试")
		}
		err = m.startLocked(ctx)
	} else {
		var restarted bool
		restarted, err = m.reloadOrRestartLocked()
		if err != nil {
			m.restoreListenersLocked(state, restarted)
		}
	}
	if err != nil {
		return "", err
	}
	return newKey, nil
}

func (m *ProxyManager) RemovePoolListener(poolID string) error {
	poolID = strings.TrimSpace(poolID)
	if poolID == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.snapshotListenersLocked()
	changed := false
	delete(m.autoWatchPools, poolID)
	delete(m.poolListeners, poolID)
	for key, listener := range m.listeners {
		if listener.poolID != poolID {
			continue
		}
		changed = true
		if listener.active > 0 {
			listener.removeRequested = true
			m.listeners[key] = listener
			continue
		}
		m.removeListenerLocked(key)
	}
	if !changed || m.process == nil || m.closed {
		return nil
	}
	restarted, err := m.reloadOrRestartLocked()
	if err != nil {
		m.restoreListenersLocked(state, restarted)
		return err
	}
	return nil
}

// ScopedAutoPoolsForUser returns only server-maintained pool identities. It is
// used by ProxyService while its catalog-operation lock is held to rebuild a
// user's groups after hiding or restoring a YAML.
func (m *ProxyManager) ScopedAutoPoolsForUser(userID string) []proxyScopedAutoGroup {
	m.mu.Lock()
	defer m.mu.Unlock()
	groups := make([]proxyScopedAutoGroup, 0)
	for _, group := range m.scopedAutoGroups {
		if group.userID == userID {
			groups = append(groups, group)
		}
	}
	sort.Slice(groups, func(left, right int) bool { return groups[left].poolKey < groups[right].poolKey })
	return groups
}

func (m *ProxyManager) ScopedAutoPools() []proxyScopedAutoGroup {
	m.mu.Lock()
	defer m.mu.Unlock()
	groups := make([]proxyScopedAutoGroup, 0, len(m.scopedAutoGroups))
	for _, group := range m.scopedAutoGroups {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(left, right int) bool { return groups[left].poolKey < groups[right].poolKey })
	return groups
}

// SyncScopedAutoPool records a saved auto strategy without eagerly starting
// Mihomo. If it changes a live configuration, the one shared process reloads
// atomically before the method returns.
func (m *ProxyManager) SyncScopedAutoPool(spec proxyRouteSpec) error {
	if spec.autoGroup == nil || strings.TrimSpace(spec.poolKey) == "" {
		return errors.New("自动选择代理范围无效")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("代理服务已停止")
	}
	snapshot := m.snapshotScopedAutoRuntimeLocked()
	changed := m.installScopedAutoGroupLocked(*spec.autoGroup)
	if m.scopedAutoWatchPools == nil {
		m.scopedAutoWatchPools = make(map[string]struct{})
	}
	m.scopedAutoWatchPools[spec.poolKey] = struct{}{}
	if listenerKey, listener, ok := m.currentListenerLocked(spec.poolKey); ok && listener.proxy != spec.autoGroup.name {
		changed = m.removeScopedAutoListenerLocked(listenerKey, listener) || changed
	}
	if !changed || m.process == nil {
		return nil
	}
	if restarted, err := m.reloadOrRestartLocked(); err != nil {
		m.restoreScopedAutoRuntimeLocked(snapshot, restarted)
		return err
	}
	return nil
}

// RemoveScopedAutoPool removes both the saved group and any listener that
// still targets it. Fixed and disabled pools use this before installing their
// next route.
func (m *ProxyManager) RemoveScopedAutoPool(poolKey string) error {
	poolKey = strings.TrimSpace(poolKey)
	if poolKey == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	snapshot := m.snapshotScopedAutoRuntimeLocked()
	changed := false
	if group, ok := m.scopedAutoGroups[poolKey]; ok {
		delete(m.scopedAutoGroups, poolKey)
		delete(m.scopedAutoStates, group.name)
		changed = true
	}
	delete(m.scopedAutoWatchPools, poolKey)
	if listenerKey, listener, ok := m.currentListenerLocked(poolKey); ok {
		changed = m.removeScopedAutoListenerLocked(listenerKey, listener) || changed
	}
	// Preserve legacy behavior for callers that previously used this cleanup
	// path directly.
	delete(m.autoWatchPools, poolKey)
	if !changed || m.process == nil || m.closed {
		return nil
	}
	if restarted, err := m.reloadOrRestartLocked(); err != nil {
		m.restoreScopedAutoRuntimeLocked(snapshot, restarted)
		return err
	}
	return nil
}

func (m *ProxyManager) ClearScopedAutoPoolForFixed(poolKey string) error {
	poolKey = strings.TrimSpace(poolKey)
	if poolKey == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	snapshot := m.snapshotScopedAutoRuntimeLocked()
	changed := false
	oldGroup, hadScopedGroup := m.scopedAutoGroups[poolKey]
	if hadScopedGroup {
		delete(m.scopedAutoGroups, poolKey)
		delete(m.scopedAutoStates, oldGroup.name)
		changed = true
	}
	delete(m.scopedAutoWatchPools, poolKey)
	delete(m.autoWatchPools, poolKey)
	if listenerKey, listener, ok := m.currentListenerLocked(poolKey); ok && hadScopedGroup && listener.proxy == oldGroup.name {
		changed = m.removeScopedAutoListenerLocked(listenerKey, listener) || changed
	}
	if !changed || m.process == nil || m.closed {
		return nil
	}
	if restarted, err := m.reloadOrRestartLocked(); err != nil {
		m.restoreScopedAutoRuntimeLocked(snapshot, restarted)
		return err
	}
	return nil
}

func (m *ProxyManager) removeScopedAutoListenerLocked(listenerKey string, listener proxyListener) bool {
	if listener.active > 0 {
		listener.removeRequested = true
		m.listeners[listenerKey] = listener
		if m.poolListeners[listener.poolID] == listenerKey {
			delete(m.poolListeners, listener.poolID)
		}
		return true
	}
	if m.poolListeners[listener.poolID] == listenerKey {
		delete(m.poolListeners, listener.poolID)
	}
	m.removeListenerLocked(listenerKey)
	return true
}

func (m *ProxyManager) ReplaceScopedAutoPoolsForUser(userID string, replacements map[string]proxyScopedAutoGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("代理服务已停止")
	}
	snapshot := m.snapshotScopedAutoRuntimeLocked()
	changed := false
	for poolKey, current := range m.scopedAutoGroups {
		if current.userID != userID {
			continue
		}
		replacement, keep := replacements[poolKey]
		if keep && replacement.name == current.name && replacement.candidateKey == current.candidateKey && replacement.testURL == current.testURL && sameStringSlice(replacement.nodes, current.nodes) {
			continue
		}
		delete(m.scopedAutoGroups, poolKey)
		delete(m.scopedAutoStates, current.name)
		if !keep {
			delete(m.scopedAutoWatchPools, poolKey)
		}
		if listenerKey, listener, ok := m.currentListenerLocked(poolKey); ok && listener.proxy == current.name {
			changed = m.removeScopedAutoListenerLocked(listenerKey, listener) || changed
		}
		changed = true
	}
	for poolKey, replacement := range replacements {
		if replacement.userID != userID || strings.TrimSpace(replacement.name) == "" || len(replacement.nodes) == 0 {
			continue
		}
		if m.installScopedAutoGroupLocked(replacement) {
			changed = true
		}
		if m.scopedAutoWatchPools == nil {
			m.scopedAutoWatchPools = make(map[string]struct{})
		}
		m.scopedAutoWatchPools[poolKey] = struct{}{}
	}
	if !changed || m.process == nil {
		return nil
	}
	if restarted, err := m.reloadOrRestartLocked(); err != nil {
		m.restoreScopedAutoRuntimeLocked(snapshot, restarted)
		return err
	}
	return nil
}

// ReplaceAllScopedAutoPools republishes every active scoped group in one
// Mihomo reload. Catalog mutations use forceReload even when memberships did
// not change, because a runtime proxy definition may have changed in place.
func (m *ProxyManager) ReplaceAllScopedAutoPools(replacements map[string]proxyScopedAutoGroup, forceReload bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("代理服务已停止")
	}
	snapshot := m.snapshotScopedAutoRuntimeLocked()
	changed := false
	for poolKey, current := range m.scopedAutoGroups {
		replacement, keep := replacements[poolKey]
		if keep && replacement.name == current.name && replacement.candidateKey == current.candidateKey && replacement.testURL == current.testURL && sameStringSlice(replacement.nodes, current.nodes) {
			continue
		}
		delete(m.scopedAutoGroups, poolKey)
		delete(m.scopedAutoStates, current.name)
		if !keep {
			delete(m.scopedAutoWatchPools, poolKey)
		}
		if listenerKey, listener, ok := m.currentListenerLocked(poolKey); ok && listener.proxy == current.name {
			changed = m.removeScopedAutoListenerLocked(listenerKey, listener) || changed
		}
		changed = true
	}
	for poolKey, replacement := range replacements {
		if strings.TrimSpace(replacement.name) == "" || len(replacement.nodes) == 0 {
			continue
		}
		if m.installScopedAutoGroupLocked(replacement) {
			changed = true
		}
		if m.scopedAutoWatchPools == nil {
			m.scopedAutoWatchPools = make(map[string]struct{})
		}
		m.scopedAutoWatchPools[poolKey] = struct{}{}
	}
	if (!changed && !forceReload) || m.process == nil {
		return nil
	}
	if restarted, err := m.reloadOrRestartLocked(); err != nil {
		m.restoreScopedAutoRuntimeLocked(snapshot, restarted)
		return err
	}
	return nil
}

type proxyScopedAutoRuntimeState struct {
	listeners     proxyListenerState
	groups        map[string]proxyScopedAutoGroup
	states        map[string]*proxyScopedAutoState
	watches       map[string]struct{}
	runtimeGroups map[string]struct{}
}

func (m *ProxyManager) snapshotScopedAutoRuntimeLocked() proxyScopedAutoRuntimeState {
	groups := make(map[string]proxyScopedAutoGroup, len(m.scopedAutoGroups))
	for key, group := range m.scopedAutoGroups {
		group.nodes = append([]string(nil), group.nodes...)
		groups[key] = group
	}
	states := make(map[string]*proxyScopedAutoState, len(m.scopedAutoStates))
	for key, state := range m.scopedAutoStates {
		copyState := *state
		states[key] = &copyState
	}
	watches := make(map[string]struct{}, len(m.scopedAutoWatchPools))
	for key := range m.scopedAutoWatchPools {
		watches[key] = struct{}{}
	}
	return proxyScopedAutoRuntimeState{
		listeners:     m.snapshotListenersLocked(),
		groups:        groups,
		states:        states,
		watches:       watches,
		runtimeGroups: cloneAutoGroupNames(m.runtimeAutoGroups),
	}
}

func (m *ProxyManager) restoreScopedAutoRuntimeLocked(state proxyScopedAutoRuntimeState, restarted bool) {
	m.restoreListenersLocked(state.listeners, restarted)
	m.scopedAutoGroups = state.groups
	m.scopedAutoStates = state.states
	m.scopedAutoWatchPools = state.watches
	m.runtimeAutoGroups = state.runtimeGroups
}

func (m *ProxyManager) addCurrentListenerLocked(poolID, nodeName string) (string, proxyListener, error) {
	listener, err := m.newListenerLocked(poolID, nodeName)
	if err != nil {
		return "", proxyListener{}, err
	}
	key := m.listenerKeyLocked(poolID, listener.generation)
	m.listeners[key] = listener
	m.poolListeners[poolID] = key
	return key, listener, nil
}

func (m *ProxyManager) newListenerLocked(poolID, nodeName string) (proxyListener, error) {
	for attempt := 0; attempt < 20; attempt++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		port := listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()
		if port == m.control || m.listenerPortInUseLocked(port) {
			continue
		}
		return proxyListener{
			poolID:     poolID,
			port:       port,
			proxy:      nodeName,
			listener:   fmt.Sprintf("pool-%d", port),
			generation: m.nextListenerGenerationLocked(),
			lastUsed:   time.Now(),
		}, nil
	}
	return proxyListener{}, errors.New("无法为 Mihomo listener 分配本地端口")
}

func (m *ProxyManager) listenerKeyLocked(poolID string, generation uint64) string {
	return poolID + "\x00listener\x00" + strconv.FormatUint(generation, 10)
}

func (m *ProxyManager) currentListenerLocked(poolID string) (string, proxyListener, bool) {
	key, ok := m.poolListeners[poolID]
	if !ok {
		return "", proxyListener{}, false
	}
	listener, ok := m.listeners[key]
	if !ok || listener.poolID != poolID {
		delete(m.poolListeners, poolID)
		return "", proxyListener{}, false
	}
	return key, listener, true
}

func (m *ProxyManager) nextListenerGenerationLocked() uint64 {
	m.nextGeneration++
	if m.nextGeneration == 0 {
		m.nextGeneration++
	}
	return m.nextGeneration
}

func (m *ProxyManager) listenerPortInUseLocked(port int) bool {
	for _, listener := range m.listeners {
		if listener.port == port {
			return true
		}
	}
	return false
}

func newMihomoCommand(binary, workDir, configPath string) *exec.Cmd {
	command := exec.Command(binary, "-d", workDir, "-f", configPath)
	configureMihomoProcess(command)
	return command
}

func (m *ProxyManager) startLocked(ctx context.Context) error {
	return m.startWithOptionsLocked(ctx, true)
}

// startBatchLatencyLocked starts the one shared process without a url-test
// group. Direct controller delay requests do not need that group, and omitting
// it prevents a first batch test from proactively probing YAMLs hidden from
// the requesting user.
func (m *ProxyManager) startBatchLatencyLocked(ctx context.Context) error {
	return m.startWithOptionsLocked(ctx, false)
}

func (m *ProxyManager) startWithOptionsLocked(ctx context.Context, includeAutoGroup bool) error {
	if m.closed {
		return errors.New("代理服务已停止")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return errors.New("当前版本的号池代理仅支持 Linux")
	}
	home, err := getUserHomeDir()
	if err != nil {
		return err
	}
	m.workDir = filepath.Join(home, appSettingsDir, proxyRuntimeDirName)
	if err := os.MkdirAll(m.workDir, 0o700); err != nil {
		return err
	}
	binary, err := ensureMihomoBinaryContext(ctx, m.workDir)
	if err != nil {
		return err
	}
	control, err := availablePortExcluding(m.listeners, 0)
	if err != nil {
		return err
	}
	m.control = control
	m.binary = binary
	m.secret = fmt.Sprintf("%x", sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10))))
	configPath := filepath.Join(m.workDir, "config.yaml")
	includeLegacyAutoGroup := includeAutoGroup && m.shouldIncludeLegacyAutoGroupLocked()
	if err := m.writeRuntimeConfigWithGroupOptionsLocked(configPath, m.catalog.runtimeNodes(), includeLegacyAutoGroup, includeAutoGroup); err != nil {
		return err
	}
	if err := m.validateRuntimeConfigLocked(configPath, ctx); err != nil {
		return err
	}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			if err := m.reallocateListenerPortsLocked(); err != nil {
				return err
			}
			control, err = availablePortExcluding(m.listeners, 0)
			if err != nil {
				return err
			}
			m.control = control
			if err := m.writeRuntimeConfigWithGroupOptionsLocked(configPath, m.catalog.runtimeNodes(), includeLegacyAutoGroup, includeAutoGroup); err != nil {
				return err
			}
			if err := m.validateRuntimeConfigLocked(configPath, ctx); err != nil {
				return err
			}
		}
		cmd := newMihomoCommand(binary, m.workDir, configPath)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("启动 Mihomo 失败: %w", err)
		}
		m.process = cmd
		done := make(chan struct{})
		m.processDone = done
		go func() {
			_ = cmd.Wait()
			close(done)
			m.processExited(cmd)
		}()
		deadline := time.Now().Add(15 * time.Second)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
	startupWait:
		for time.Now().Before(deadline) {
			probeContext, cancel := context.WithTimeout(ctx, time.Second)
			err := m.controllerRequest(probeContext, http.MethodGet, "/version", nil)
			cancel()
			if err == nil {
				m.advanceRuntimeGenerationLocked()
				m.runtimeHasAutoGroup = includeLegacyAutoGroup
				m.runtimeAutoGroups = m.configuredAutoGroupNamesLocked(includeLegacyAutoGroup, includeAutoGroup)
				m.lastAutoProbe = time.Time{}
				m.startCleanupLoop()
				return nil
			}
			select {
			case <-done:
				m.retireProcessLeasesLocked()
				m.process = nil
				m.processDone = nil
				if attempt < 2 {
					break startupWait
				}
				return errors.New("Mihomo 启动后立即退出")
			default:
			}
			if ctx.Err() != nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if m.process == cmd {
			if err := m.stopProcessWithContextLocked(ctx); err != nil {
				return err
			}
		}
	}
	if err := m.stopProcessWithContextLocked(ctx); err != nil {
		return err
	}
	return errors.New("Mihomo 启动超时")
}

func (m *ProxyManager) reallocateListenerPortsLocked() error {
	// Reallocation follows a dead process. Old leased responses belong to that
	// process incarnation and must not keep a replacement listener alive.
	m.retireProcessLeasesLocked()
	used := make(map[int]struct{}, len(m.listeners))
	for _, listener := range m.listeners {
		used[listener.port] = struct{}{}
	}
	for key, listener := range m.listeners {
		delete(used, listener.port)
		// Port reallocation only happens after the previous Mihomo process has
		// exited. Requests leased from that process can no longer be active in
		// the replacement listener, and their old generation must not mutate it.
		if listener.removeRequested {
			m.removeListenerLocked(key)
			continue
		}
		var port int
		var err error
		for attempt := 0; attempt < 20; attempt++ {
			port, err = availablePort()
			if err == nil && port != m.control {
				if _, exists := used[port]; !exists {
					break
				}
			}
			port = 0
		}
		if port == 0 {
			return fmt.Errorf("无法重新分配 listener 端口: %s", key)
		}
		listener.port = port
		listener.listener = fmt.Sprintf("pool-%d", port)
		listener.generation = m.nextListenerGenerationLocked()
		m.listeners[key] = listener
		used[port] = struct{}{}
	}
	return nil
}

func (m *ProxyManager) processExited(cmd *exec.Cmd) {
	m.mu.Lock()
	if m.process != cmd {
		m.mu.Unlock()
		return
	}
	m.process = nil
	m.processDone = nil
	m.runtimeHasAutoGroup = false
	m.runtimeAutoGroups = make(map[string]struct{})
	m.advanceRuntimeGenerationLocked()
	m.lastAutoProbe = time.Time{}
	m.retireProcessLeasesLocked()
	if m.stopping || (len(m.listeners) == 0 && len(m.autoWatchPools) == 0 && len(m.scopedAutoWatchPools) == 0) {
		m.mu.Unlock()
		return
	}
	failures := m.recoveryFailures
	if failures > 4 {
		failures = 4
	}
	m.recovering = true
	m.nextRecoveryAt = time.Now().Add(time.Second << failures)
	m.mu.Unlock()
	go m.recoverUntilRunning()
}

func (m *ProxyManager) scheduleRecoveryLocked() {
	if m.closed || m.recovering {
		return
	}
	failures := m.recoveryFailures
	if failures > 4 {
		failures = 4
	}
	m.recovering = true
	m.nextRecoveryAt = time.Now().Add(time.Second << failures)
	go m.recoverUntilRunning()
}

func (m *ProxyManager) recoverUntilRunning() {
	for {
		m.mu.Lock()
		if m.closed || m.process != nil || (len(m.listeners) == 0 && len(m.autoWatchPools) == 0 && len(m.scopedAutoWatchPools) == 0) {
			m.recovering = false
			m.mu.Unlock()
			return
		}
		wait := time.Until(m.nextRecoveryAt)
		m.mu.Unlock()
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-m.cleanupStop:
				timer.Stop()
				return
			}
		}

		m.mu.Lock()
		if m.closed || m.process != nil || (len(m.listeners) == 0 && len(m.autoWatchPools) == 0 && len(m.scopedAutoWatchPools) == 0) {
			m.recovering = false
			m.mu.Unlock()
			return
		}
		m.recoveryFailures++
		err := m.startLocked(context.Background())
		if err == nil {
			m.recovering = false
			m.nextRecoveryAt = time.Time{}
			m.recoveryFailures = 0
			m.mu.Unlock()
			return
		}
		failures := m.recoveryFailures
		if failures > 4 {
			failures = 4
		}
		m.nextRecoveryAt = time.Now().Add(time.Second << failures)
		fmt.Printf("[proxy] Mihomo 恢复失败，将重试: %v\n", err)
		m.mu.Unlock()
	}
}

func (m *ProxyManager) writeRuntimeConfigLocked(configPath string) error {
	return m.writeRuntimeConfigWithGroupOptionsLocked(configPath, m.catalog.runtimeNodes(), m.shouldIncludeLegacyAutoGroupLocked(), true)
}

func (m *ProxyManager) writeRuntimeConfigWithAutoGroupLocked(configPath string, includeAutoGroup bool) error {
	return m.writeRuntimeConfigWithGroupOptionsLocked(configPath, m.catalog.runtimeNodes(), includeAutoGroup, includeAutoGroup)
}

func (m *ProxyManager) writeRuntimeConfigWithNodesLocked(configPath string, nodes []map[string]any) error {
	return m.writeRuntimeConfigWithGroupOptionsLocked(configPath, nodes, true, true)
}

func (m *ProxyManager) writeRuntimeConfigWithNodesAndAutoGroupLocked(configPath string, nodes []map[string]any, includeAutoGroup bool) error {
	return m.writeRuntimeConfigWithGroupOptionsLocked(configPath, nodes, includeAutoGroup, includeAutoGroup)
}

func (m *ProxyManager) writeRuntimeConfigWithGroupOptionsLocked(configPath string, nodes []map[string]any, includeLegacyAutoGroup, includeScopedAutoGroups bool) error {
	groups := []map[string]any{}
	if includeLegacyAutoGroup {
		groups = autoProxyGroupConfig(nodes)
	}
	if includeScopedAutoGroups {
		groups = append(groups, m.scopedAutoProxyGroupConfigsLocked()...)
	}
	config := map[string]any{
		"allow-lan": false, "bind-address": "127.0.0.1", "mode": "rule", "log-level": "warning",
		"ipv6": false, "external-controller": fmt.Sprintf("127.0.0.1:%d", m.control), "secret": m.secret,
		"proxies": nodes, "proxy-groups": groups, "listeners": m.listenerConfigWithGroupOptionsLocked(includeLegacyAutoGroup, includeScopedAutoGroups),
	}
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	if err := writePrivateFile(configPath, data); err != nil {
		return err
	}
	return nil
}

func (m *ProxyManager) scopedAutoProxyGroupConfigsLocked() []map[string]any {
	groupsByName := make(map[string]proxyScopedAutoGroup, len(m.scopedAutoGroups))
	for _, group := range m.scopedAutoGroups {
		if strings.TrimSpace(group.name) == "" || len(group.nodes) == 0 {
			continue
		}
		groupsByName[group.name] = group
	}
	names := make([]string, 0, len(groupsByName))
	for name := range groupsByName {
		names = append(names, name)
	}
	sort.Strings(names)
	groups := make([]map[string]any, 0, len(names))
	for _, name := range names {
		group := groupsByName[name]
		groups = append(groups, map[string]any{
			"name": name, "type": "url-test", "proxies": append([]string(nil), group.nodes...),
			"url": normalizeScopedAutoTestURL(group.testURL), "interval": int(proxyAutoProbeInterval.Seconds()), "tolerance": 0,
		})
	}
	return groups
}

func (m *ProxyManager) configuredAutoGroupNamesLocked(includeLegacyAutoGroup, includeScopedAutoGroups bool) map[string]struct{} {
	groups := make(map[string]struct{})
	if includeLegacyAutoGroup && len(m.catalog.runtimeNodes()) > 0 {
		groups[proxyAutoGroupName] = struct{}{}
	}
	if includeScopedAutoGroups {
		for _, group := range m.scopedAutoGroups {
			if strings.TrimSpace(group.name) != "" && len(group.nodes) > 0 {
				groups[group.name] = struct{}{}
			}
		}
	}
	return groups
}

func cloneAutoGroupNames(groups map[string]struct{}) map[string]struct{} {
	clone := make(map[string]struct{}, len(groups))
	for name := range groups {
		clone[name] = struct{}{}
	}
	return clone
}

func autoProxyGroupConfig(nodes []map[string]any) []map[string]any {
	names := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if name, ok := node["name"].(string); ok && strings.TrimSpace(name) != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return []map[string]any{}
	}
	return []map[string]any{{
		"name": proxyAutoGroupName, "type": "url-test", "proxies": names,
		"url": proxyHealthURL, "interval": int(proxyAutoProbeInterval.Seconds()), "tolerance": 0,
	}}
}

func (m *ProxyManager) validateRuntimeConfigLocked(configPath string, parent context.Context) error {
	if strings.TrimSpace(m.binary) == "" {
		return errors.New("Mihomo 二进制未准备好")
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, m.binary, "-t", "-d", m.workDir, "-f", configPath)
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 1000 {
			message = message[len(message)-1000:]
		}
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("Mihomo 配置校验失败: %s", message)
	}
	return nil
}

func (m *ProxyManager) startCleanupLoop() {
	m.cleanupOnce.Do(func() {
		if m.cleanupStop == nil {
			m.cleanupStop = make(chan struct{})
		}
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					m.mu.Lock()
					if m.closed {
						m.mu.Unlock()
						return
					}
					snapshot := m.snapshotListenersLocked()
					if m.pruneListenersLocked() && m.process != nil {
						restarted, err := m.reloadOrRestartLocked()
						if err != nil {
							m.restoreListenersLocked(snapshot, restarted)
							fmt.Printf("[proxy] 清理闲置 listener 失败: %v\n", err)
						}
					}
					m.mu.Unlock()
					// The probe itself performs HTTP I/O; run it after releasing m.mu.
					// It is a no-op while no auto pool is actively watched for use or
					// recovery.
					_, _ = m.refreshDueAutoSelection(context.Background())
					_, _ = m.refreshDueScopedAutoSelections(context.Background())
				case <-m.cleanupStop:
					return
				}
			}
		}()
	})
}

// reloadOrRestartLocked reports whether recovery required a process restart.
// A caller that rolls back listener state must retire old leases in that case.
func (m *ProxyManager) reloadOrRestartLocked() (bool, error) {
	if m.process == nil {
		return false, m.startLocked(context.Background())
	}
	previousAutoGroups := cloneAutoGroupNames(m.runtimeAutoGroups)
	previousHasAutoGroup := m.runtimeHasAutoGroup
	configPath := filepath.Join(m.workDir, "config.yaml")
	previous, err := os.ReadFile(configPath)
	if err != nil {
		return false, fmt.Errorf("读取当前 Mihomo 配置失败: %w", err)
	}
	candidatePath := configPath + ".candidate"
	_ = os.Remove(candidatePath)
	if err := m.writeRuntimeConfigLocked(candidatePath); err != nil {
		return false, err
	}
	defer os.Remove(candidatePath)
	if err := m.validateRuntimeConfigLocked(candidatePath, context.Background()); err != nil {
		return false, err
	}
	if err := os.Rename(candidatePath, configPath); err != nil {
		return false, err
	}
	if err := m.controllerRequestWithBody(context.Background(), http.MethodPut, "/configs?force=true", map[string]any{
		"path": configPath,
	}, nil); err == nil {
		m.advanceRuntimeGenerationLocked()
		m.runtimeHasAutoGroup = m.shouldIncludeLegacyAutoGroupLocked()
		m.runtimeAutoGroups = m.configuredAutoGroupNamesLocked(m.runtimeHasAutoGroup, true)
		return false, nil
	}
	// A controller reload failure must not turn a healthy running process into a
	// process started from a bad candidate. Restore the last-known-good file and
	// ask the live process to reload it once more.
	restoreErr := writePrivateFile(configPath, previous)
	if restoreErr == nil {
		restoreErr = m.controllerRequestWithBody(context.Background(), http.MethodPut, "/configs?force=true", map[string]any{
			"path": configPath,
		}, nil)
	}
	if restoreErr != nil {
		if restartErr := m.restartLocked(); restartErr != nil {
			return true, fmt.Errorf("Mihomo 重载失败，恢复旧配置和受控重启均失败: %v; %w", restoreErr, restartErr)
		}
		return true, errors.New("Mihomo 重载失败，已通过受控重启恢复")
	}
	m.advanceRuntimeGenerationLocked()
	m.runtimeHasAutoGroup = previousHasAutoGroup
	m.runtimeAutoGroups = previousAutoGroups
	return false, errors.New("Mihomo 重载失败，已恢复旧配置")
}

func ensureMihomoBinary(runtimeDir string) (string, error) {
	return ensureMihomoBinaryContext(context.Background(), runtimeDir)
}

func ensureMihomoBinaryContext(ctx context.Context, runtimeDir string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if configured := strings.TrimSpace(os.Getenv("CODE_SWITCH_MIHOMO_BINARY")); configured != "" {
		if err := validateMihomoBinaryContext(ctx, configured); err != nil {
			return "", err
		}
		return configured, nil
	}
	for _, candidate := range []string{
		filepath.Join(referenceProxyDir(), "mihomo-"+mihomoVersion),
		filepath.Join(runtimeDir, "mihomo-"+mihomoVersion),
	} {
		if _, err := os.Stat(candidate); err == nil {
			if err := validateMihomoBinaryContext(ctx, candidate); err == nil {
				_ = os.Chmod(candidate, 0o700)
				return candidate, nil
			} else if ctx.Err() != nil {
				return "", ctx.Err()
			}
		}
	}
	if configured, err := exec.LookPath("mihomo"); err == nil {
		if err := validateMihomoBinaryContext(ctx, configured); err == nil {
			return configured, nil
		} else if ctx.Err() != nil {
			return "", ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if runtime.GOARCH != "amd64" {
		return "", errors.New("当前版本仅支持 Linux amd64 自动下载 Mihomo，请通过 CODE_SWITCH_MIHOMO_BINARY 指定其他架构的二进制")
	}
	archivePath := filepath.Join(runtimeDir, "mihomo-"+mihomoVersion)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, mihomoDownloadURL, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("下载 Mihomo 失败: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载 Mihomo 返回 HTTP %d", response.StatusCode)
	}
	tmp, err := os.CreateTemp(runtimeDir, ".mihomo-download-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	digest := sha256.New()
	reader := io.TeeReader(response.Body, digest)
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("读取 Mihomo 压缩包失败: %w", err)
	}
	if _, err := io.Copy(tmp, gzipReader); err != nil {
		_ = gzipReader.Close()
		_ = tmp.Close()
		return "", err
	}
	if err := gzipReader.Close(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o700); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if hex.EncodeToString(digest.Sum(nil)) != mihomoAssetSHA256 {
		return "", errors.New("Mihomo 下载包 SHA256 校验失败")
	}
	if err := os.Rename(tmpName, archivePath); err != nil {
		return "", err
	}
	if err := validateMihomoBinaryContext(ctx, archivePath); err != nil {
		_ = os.Remove(archivePath)
		return "", err
	}
	return archivePath, nil
}

func validateMihomoBinary(path string) error {
	return validateMihomoBinaryContext(context.Background(), path)
}

func validateMihomoBinaryContext(ctx context.Context, path string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	command := exec.CommandContext(ctx, path, "-v")
	output, err := command.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("Mihomo 二进制不可用: %w", err)
	}
	if !strings.Contains(string(output), strings.TrimPrefix(mihomoVersion, "v")) {
		return fmt.Errorf("Mihomo 版本不匹配: %s", path)
	}
	return nil
}

func (m *ProxyManager) restartLocked() error {
	if err := m.stopProcessLocked(); err != nil {
		return err
	}
	if err := m.startLocked(context.Background()); err != nil {
		m.scheduleRecoveryLocked()
		return err
	}
	return nil
}

func (m *ProxyManager) stopProcessLocked() error {
	return m.stopProcessWithContextLocked(context.Background())
}

func (m *ProxyManager) stopProcessWithContextLocked(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := m.process
	done := m.processDone
	if cmd == nil {
		return nil
	}
	m.stopping = true
	defer func() { m.stopping = false }()
	if cmd.Process != nil {
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			fmt.Printf("[proxy] 停止 Mihomo 失败: %v\n", err)
		}
	}
	if done != nil {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			return errors.New("等待 Mihomo 退出超时，保留进程句柄并拒绝启动第二个实例")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if m.process == cmd {
		m.retireProcessLeasesLocked()
		m.process = nil
		m.processDone = nil
		m.runtimeHasAutoGroup = false
		m.runtimeAutoGroups = make(map[string]struct{})
		m.advanceRuntimeGenerationLocked()
	}
	return nil
}

func (m *ProxyManager) listenerConfigLocked() []map[string]any {
	return m.listenerConfigWithGroupOptionsLocked(m.shouldIncludeLegacyAutoGroupLocked(), true)
}

func (m *ProxyManager) listenerConfigWithAutoGroupLocked(includeAutoGroup bool) []map[string]any {
	return m.listenerConfigWithGroupOptionsLocked(includeAutoGroup, includeAutoGroup)
}

func (m *ProxyManager) listenerConfigWithGroupOptionsLocked(includeLegacyAutoGroup, includeScopedAutoGroups bool) []map[string]any {
	listeners := make([]map[string]any, 0, len(m.listeners))
	validNodes := make(map[string]struct{})
	for _, node := range m.catalog.runtimeNodes() {
		if name, ok := node["name"].(string); ok {
			validNodes[name] = struct{}{}
		}
	}
	if includeLegacyAutoGroup && len(validNodes) > 0 {
		validNodes[proxyAutoGroupName] = struct{}{}
	}
	if includeScopedAutoGroups {
		for _, group := range m.scopedAutoGroups {
			if strings.TrimSpace(group.name) != "" && len(group.nodes) > 0 {
				validNodes[group.name] = struct{}{}
			}
		}
	}
	keys := make([]string, 0, len(m.listeners))
	for key := range m.listeners {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		listener := m.listeners[key]
		if _, ok := validNodes[listener.proxy]; !ok {
			continue
		}
		listeners = append(listeners, map[string]any{"name": listener.listener, "type": "mixed", "listen": "127.0.0.1", "port": listener.port, "proxy": listener.proxy})
	}
	return listeners
}

func (m *ProxyManager) shouldIncludeLegacyAutoGroupLocked() bool {
	if len(m.autoWatchPools) > 0 {
		return true
	}
	for _, listener := range m.listeners {
		if !listener.removeRequested && listener.proxy == proxyAutoGroupName {
			return true
		}
	}
	return false
}

// removeListenersForMissingNodesLocked prevents a deleted fixed-node YAML
// from leaving an in-memory listener pointed at a runtime name that no longer
// exists. Active leases are retired once they drain; they are omitted from the
// next Mihomo configuration immediately.
func (m *ProxyManager) removeListenersForMissingNodesLocked() bool {
	validNodes := make(map[string]struct{})
	for _, node := range m.catalog.runtimeNodes() {
		if name, ok := node["name"].(string); ok {
			validNodes[name] = struct{}{}
		}
	}
	if len(validNodes) > 0 {
		validNodes[proxyAutoGroupName] = struct{}{}
	}
	for _, group := range m.scopedAutoGroups {
		if strings.TrimSpace(group.name) != "" && len(group.nodes) > 0 {
			validNodes[group.name] = struct{}{}
		}
	}
	changed := false
	for key, listener := range m.listeners {
		if _, ok := validNodes[listener.proxy]; ok {
			continue
		}
		changed = true
		if m.poolListeners[listener.poolID] == key {
			delete(m.poolListeners, listener.poolID)
		}
		if listener.active > 0 {
			listener.removeRequested = true
			m.listeners[key] = listener
			continue
		}
		m.removeListenerLocked(key)
	}
	return changed
}

func (m *ProxyManager) pruneListenersLocked() bool {
	now := time.Now()
	changed := false
	for key, listener := range m.listeners {
		if listener.active == 0 && (listener.removeRequested || (!listener.lastUsed.IsZero() && now.Sub(listener.lastUsed) > proxyListenerIdleTTL)) {
			m.removeListenerLocked(key)
			changed = true
		}
	}
	return changed
}

func (m *ProxyManager) markListenerActive(key string, generation uint64, delta int) bool {
	m.mu.Lock()
	listener, ok := m.listeners[key]
	if !ok || listener.generation != generation {
		m.mu.Unlock()
		return false
	}
	listener.active += delta
	if listener.active < 0 {
		listener.active = 0
	}
	listener.lastUsed = time.Now()
	if listener.active == 0 && listener.removeRequested {
		state := m.snapshotListenersLocked()
		m.removeListenerLocked(key)
		if m.process != nil && !m.closed {
			restarted, err := m.reloadOrRestartLocked()
			if err != nil {
				m.restoreListenersLocked(state, restarted)
				fmt.Printf("[proxy] 活跃请求结束后清理 listener 失败: %v\n", err)
			}
		}
	} else {
		m.listeners[key] = listener
	}
	m.mu.Unlock()
	return true
}

func (m *ProxyManager) InvalidateProxy(poolKey, node string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	listener, ok := m.listeners[poolKey]
	if !ok {
		if currentKey, _, current := m.currentListenerLocked(poolKey); current {
			poolKey = currentKey
			listener = m.listeners[currentKey]
			ok = true
		}
	}
	if !ok || (node != "" && listener.proxy != node) {
		return
	}
	state := m.snapshotListenersLocked()
	if m.poolListeners[listener.poolID] == poolKey {
		delete(m.poolListeners, listener.poolID)
	}
	if listener.active > 0 {
		listener.removeRequested = true
		m.listeners[poolKey] = listener
		return
	}
	m.removeListenerLocked(poolKey)
	if m.process != nil {
		restarted, err := m.reloadOrRestartLocked()
		if err != nil {
			m.restoreListenersLocked(state, restarted)
			fmt.Printf("[proxy] 清理失效 listener 失败: %v\n", err)
		}
	}
}

func cloneProxyListeners(input map[string]proxyListener) map[string]proxyListener {
	output := make(map[string]proxyListener, len(input))
	for key, listener := range input {
		output[key] = listener
	}
	return output
}

type proxyListenerState struct {
	listeners     map[string]proxyListener
	poolListeners map[string]string
}

func (m *ProxyManager) snapshotListenersLocked() proxyListenerState {
	current := make(map[string]string, len(m.poolListeners))
	for poolID, key := range m.poolListeners {
		current[poolID] = key
	}
	return proxyListenerState{listeners: cloneProxyListeners(m.listeners), poolListeners: current}
}

func (m *ProxyManager) restoreListenersLocked(state proxyListenerState, processRestarted bool) {
	m.listeners = cloneProxyListeners(state.listeners)
	m.poolListeners = make(map[string]string, len(state.poolListeners))
	for poolID, key := range state.poolListeners {
		m.poolListeners[poolID] = key
	}
	if processRestarted {
		m.retireProcessLeasesLocked()
	}
}

func (m *ProxyManager) removeListenerLocked(key string) {
	listener, ok := m.listeners[key]
	if !ok {
		return
	}
	delete(m.listeners, key)
	if m.poolListeners[listener.poolID] == key {
		delete(m.poolListeners, listener.poolID)
	}
}

// retireProcessLeasesLocked advances generations after a Mihomo process exits.
// Responses held by the dead process cannot safely mutate the replacement.
func (m *ProxyManager) retireProcessLeasesLocked() {
	for key, listener := range m.listeners {
		if listener.removeRequested {
			m.removeListenerLocked(key)
			continue
		}
		listener.active = 0
		listener.generation = m.nextListenerGenerationLocked()
		listener.lastUsed = time.Now()
		m.listeners[key] = listener
	}
}

func (m *ProxyManager) measureDelayLocked(ctx context.Context, nodeName string) (int64, error) {
	if m.process == nil {
		if err := m.startLocked(ctx); err != nil {
			return 0, err
		}
	}
	return m.measureDelayAt(ctx, m.control, m.secret, nodeName)
}

func (m *ProxyManager) measureDelayAt(ctx context.Context, control int, secret, nodeName string) (int64, error) {
	path := "/proxies/" + url.PathEscape(nodeName) + "/delay?timeout=10000&url=" + url.QueryEscape(proxyHealthURL)
	var payload struct {
		Delay int64 `json:"delay"`
	}
	if err := m.controllerRequestAt(ctx, control, secret, http.MethodGet, path, nil, &payload); err != nil {
		return 0, err
	}
	if payload.Delay < 0 {
		return 0, errors.New("代理延时无效")
	}
	return payload.Delay, nil
}

func (m *ProxyManager) controllerRequest(ctx context.Context, method, path string, result any) error {
	return m.controllerRequestWithBody(ctx, method, path, nil, result)
}

func (m *ProxyManager) controllerRequestWithBody(ctx context.Context, method, path string, body any, result any) error {
	return m.controllerRequestAt(ctx, m.control, m.secret, method, path, body, result)
}

func (m *ProxyManager) controllerRequestAt(ctx context.Context, control int, secret, method, path string, body any, result any) error {
	return m.controllerRequestAtWithTimeout(ctx, control, secret, proxyTestTimeout, method, path, body, result)
}

func (m *ProxyManager) controllerRequestAtWithTimeout(ctx context.Context, control int, secret string, timeout time.Duration, method, path string, body any, result any) error {
	if timeout <= 0 {
		timeout = proxyTestTimeout
	}
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = strings.NewReader(string(data))
	}
	request, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("http://127.0.0.1:%d%s", control, path), bodyReader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+secret)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: timeout}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Mihomo controller 返回 HTTP %d", response.StatusCode)
	}
	if result != nil && json.NewDecoder(response.Body).Decode(result) != nil {
		return errors.New("Mihomo controller 返回无效数据")
	}
	return nil
}

// TestNodeLatencies measures a pre-authorized set of nodes through the shared
// Mihomo controller. It neither creates a pool listener nor changes a pool or
// auto-selection. The caller owns visibility filtering; targets are never
// accepted directly from an RPC client.
func (m *ProxyManager) TestNodeLatencies(ctx context.Context, targets []proxyLatencyTarget) []ProxyNodeLatencyResult {
	results := make([]ProxyNodeLatencyResult, len(targets))
	for index, target := range targets {
		results[index].NodeID = target.nodeID
	}
	if len(targets) == 0 {
		return results
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	batchTimeout := m.batchTestTimeout
	m.mu.Unlock()
	if batchTimeout <= 0 {
		batchTimeout = proxyBatchTestTimeout
	}
	batchCtx, cancel := context.WithTimeout(ctx, batchTimeout)
	defer cancel()

	// Starting the one shared runtime is permitted, but this path intentionally
	// has no listener key: a speed-test preview must not publish a route.
	m.mu.Lock()
	var startErr error
	if m.closed {
		startErr = errors.New("代理服务已停止")
	} else if m.process == nil {
		if m.recovering || time.Now().Before(m.nextRecoveryAt) {
			startErr = errors.New("Mihomo 正在恢复，请稍后重试")
		} else {
			startErr = m.startBatchLatencyLocked(batchCtx)
		}
	}
	snapshot := proxyRuntimeSnapshot{}
	if startErr == nil {
		snapshot, startErr = m.runtimeSnapshotLocked()
	}
	m.mu.Unlock()
	if startErr != nil {
		// Startup/validation errors can describe the shared catalog, including
		// YAMLs hidden from this caller. Keep this batch-wide failure generic.
		setProxyLatencyErrors(results, proxyLatencyStartupError(batchCtx, startErr))
		return results
	}

	runtimeNodes := make(map[string]struct{}, len(snapshot.nodes))
	for _, name := range snapshot.nodes {
		runtimeNodes[name] = struct{}{}
	}
	jobs := make(chan int, len(targets))
	for index, target := range targets {
		if target.catalogKey != "" && target.catalogKey != snapshot.catalogKey {
			results[index].Error = "代理运行配置已刷新，请重新测速"
			continue
		}
		if strings.TrimSpace(target.runtimeName) == "" {
			results[index].Error = "代理节点不存在或已失效"
			continue
		}
		if _, exists := runtimeNodes[target.runtimeName]; !exists {
			results[index].Error = "代理运行配置已刷新，请重新测速"
			continue
		}
		jobs <- index
	}
	close(jobs)

	sem := m.testSem
	workerCount := min(cap(sem), proxyBatchLatencyWorkers)
	if workerCount < 1 {
		// NewProxyManager always initializes testSem. Keep a defensive local
		// semaphore for manually constructed test managers instead of blocking
		// forever on a nil channel.
		sem = make(chan struct{}, 1)
		workerCount = 1
	}
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			defer workers.Done()
			for index := range jobs {
				if err := batchCtx.Err(); err != nil {
					results[index].Error = proxyLatencyNotStartedError(batchCtx, err)
					continue
				}
				select {
				case sem <- struct{}{}:
				case <-batchCtx.Done():
					results[index].Error = proxyLatencyNotStartedError(batchCtx, batchCtx.Err())
					continue
				}
				if !m.batchRuntimeMatches(snapshot) {
					<-sem
					results[index].Error = "代理运行配置已刷新，请重新测速"
					continue
				}
				latency, err := m.measureBatchDelayAt(batchCtx, snapshot.control, snapshot.secret, targets[index].runtimeName)
				<-sem
				if !m.batchRuntimeMatches(snapshot) {
					results[index].Error = "代理运行配置已刷新，请重新测速"
					continue
				}
				results[index].Tested = true
				if err != nil {
					results[index].Error = proxyLatencyBatchError(batchCtx, err)
					continue
				}
				results[index].LatencyMs = &latency
			}
		}()
	}
	workers.Wait()
	return results
}

func setProxyLatencyErrors(results []ProxyNodeLatencyResult, message string) {
	for index := range results {
		results[index].Error = message
	}
}

func proxyLatencyStartupError(ctx context.Context, err error) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return "测速超时"
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return "测速已取消"
	}
	return "代理测速服务不可用"
}

func proxyLatencyBatchError(ctx context.Context, err error) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return "测速超时"
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return "测速已取消"
	}
	if err == nil {
		return "未测速"
	}
	return err.Error()
}

func proxyLatencyNotStartedError(ctx context.Context, err error) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return "未测速（批量测速总时限已到）"
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return "未测速（测速已取消）"
	}
	return "未测速"
}

// measureBatchDelayAt is deliberately separate from measureDelayAt so a
// malformed controller response with no delay field becomes a per-node error
// instead of looking like a successful 0 ms measurement.
func (m *ProxyManager) measureBatchDelayAt(ctx context.Context, control int, secret, nodeName string) (int64, error) {
	path := "/proxies/" + url.PathEscape(nodeName) + "/delay?timeout=10000&url=" + url.QueryEscape(proxyHealthURL)
	var payload struct {
		Delay *int64 `json:"delay"`
	}
	if err := m.controllerRequestAt(ctx, control, secret, http.MethodGet, path, nil, &payload); err != nil {
		return 0, err
	}
	if payload.Delay == nil || *payload.Delay <= 0 {
		return 0, errors.New("代理延时无效")
	}
	return *payload.Delay, nil
}

func (m *ProxyManager) Test(ctx context.Context, _ string, nodeID, responsesURL string) (result ProxySpeedTestResult) {
	select {
	case m.testSem <- struct{}{}:
		defer func() { <-m.testSem }()
	case <-ctx.Done():
		result.ProxyError = ctx.Err().Error()
		return result
	}
	target, err := resolveProxyTestTarget(ctx, responsesURL)
	if err != nil {
		result.ResponsesError = err.Error()
		return result
	}
	nodeName := ""
	auto := strings.TrimSpace(nodeID) == ""
	if auto {
		if _, err = m.autoProxyTarget(); err == nil {
			nodeName = proxyAutoGroupName
		}
	} else {
		m.mu.Lock()
		var ok bool
		nodeName, ok = m.catalog.FindNode(nodeID)
		m.mu.Unlock()
		if !ok {
			result.ProxyError = "代理节点不存在或已失效"
			return result
		}
	}
	if err != nil {
		result.ProxyError = err.Error()
		return result
	}
	testID := fmt.Sprintf("__proxy-test-%d", time.Now().UnixNano())
	cleanup := func() error {
		m.mu.Lock()
		defer m.mu.Unlock()
		state := m.snapshotListenersLocked()
		changed := false
		delete(m.poolListeners, testID)
		for key, listener := range m.listeners {
			if listener.poolID != testID {
				continue
			}
			if listener.active > 0 {
				listener.removeRequested = true
				m.listeners[key] = listener
				continue
			}
			m.removeListenerLocked(key)
			changed = true
		}
		if !changed {
			return nil
		}
		if m.process == nil {
			return nil
		}
		restarted, err := m.reloadOrRestartLocked()
		if err != nil {
			m.restoreListenersLocked(state, restarted)
			return err
		}
		return nil
	}
	defer func() {
		if cleanupErr := cleanup(); cleanupErr != nil {
			result.CleanupError = cleanupErr.Error()
		}
	}()
	m.mu.Lock()
	listenerKey, ensureErr := m.ensureRunningLocked(ctx, testID, nodeName)
	if ensureErr != nil {
		m.mu.Unlock()
		result.ResponsesError = ensureErr.Error()
	} else {
		listener := m.listeners[listenerKey]
		proxyURL := fmt.Sprintf("http://127.0.0.1:%d", listener.port)
		control, secret := m.control, m.secret
		m.mu.Unlock()
		if auto {
			selection, selectionErr := m.autoSelectionForRuntime(ctx)
			if selectionErr != nil {
				result.ProxyError = selectionErr.Error()
				// Do not send a Responses request through an unready url-test group:
				// Mihomo would fall back to its first YAML member.
				return result
			} else {
				delay := selection.delay
				result.ProxyLatencyMs = &delay
			}
		} else {
			delay, delayErr := m.measureDelayAt(ctx, control, secret, nodeName)
			if delayErr != nil {
				result.ProxyError = delayErr.Error()
			} else {
				result.ProxyLatencyMs = &delay
			}
		}
		result.ResponsesLatencyMs, result.ResponsesStatus, result.ResponsesError, result.ResponsesCloudflareBlocked = measureResponsesEndpoint(ctx, target, proxyURL)
		return result
	}
	return result
}

// TestWithRouteSpec is the authenticated counterpart to Test. Its auto group
// membership and fixed runtime node have already been resolved by
// ProxyService, so a hidden node cannot be reached by a forged RPC request.
func (m *ProxyManager) TestWithRouteSpec(ctx context.Context, spec proxyRouteSpec, responsesURL string) (result ProxySpeedTestResult) {
	select {
	case m.testSem <- struct{}{}:
		defer func() { <-m.testSem }()
	case <-ctx.Done():
		result.ProxyError = ctx.Err().Error()
		return result
	}
	target, err := resolveProxyTestTarget(ctx, responsesURL)
	if err != nil {
		result.ResponsesError = err.Error()
		return result
	}

	auto := spec.autoGroup != nil
	nodeName := spec.fixedNode
	if auto {
		nodeName = spec.autoGroup.name
	}
	if strings.TrimSpace(nodeName) == "" {
		result.ProxyError = "选择的代理节点已隐藏或不可用"
		return result
	}
	testID := fmt.Sprintf("__proxy-test-%d", time.Now().UnixNano())
	cleanup := func() error {
		m.mu.Lock()
		defer m.mu.Unlock()
		state := m.snapshotListenersLocked()
		changed := false
		delete(m.poolListeners, testID)
		for key, listener := range m.listeners {
			if listener.poolID != testID {
				continue
			}
			if listener.active > 0 {
				listener.removeRequested = true
				m.listeners[key] = listener
				continue
			}
			m.removeListenerLocked(key)
			changed = true
		}
		if !changed || m.process == nil {
			return nil
		}
		restarted, err := m.reloadOrRestartLocked()
		if err != nil {
			m.restoreListenersLocked(state, restarted)
			return err
		}
		return nil
	}
	defer func() {
		if cleanupErr := cleanup(); cleanupErr != nil {
			result.CleanupError = cleanupErr.Error()
		}
	}()

	m.mu.Lock()
	var listenerKey string
	if auto {
		m.installScopedAutoGroupLocked(*spec.autoGroup)
		listenerKey, err = m.ensureScopedAutoRunningLocked(ctx, testID, *spec.autoGroup)
	} else {
		listenerKey, err = m.ensureRunningLocked(ctx, testID, nodeName)
	}
	if err != nil {
		m.mu.Unlock()
		result.ResponsesError = err.Error()
		return result
	}
	listener := m.listeners[listenerKey]
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", listener.port)
	control, secret := m.control, m.secret
	m.mu.Unlock()
	if auto {
		selection, selectionErr := m.scopedAutoSelectionForRuntime(ctx, *spec.autoGroup, false)
		if selectionErr != nil {
			result.ProxyError = selectionErr.Error()
			return result
		}
		delay := selection.delay
		result.ProxyLatencyMs = &delay
	} else {
		delay, delayErr := m.measureDelayAt(ctx, control, secret, nodeName)
		if delayErr != nil {
			result.ProxyError = delayErr.Error()
		} else {
			result.ProxyLatencyMs = &delay
		}
	}
	result.ResponsesLatencyMs, result.ResponsesStatus, result.ResponsesError, result.ResponsesCloudflareBlocked = measureResponsesEndpoint(ctx, target, proxyURL)
	return result
}

type resolvedProxyTestTarget struct {
	url        *url.URL
	hostHeader string
	serverName string
}

func measureResponsesEndpoint(ctx context.Context, target resolvedProxyTestTarget, proxy string) (*int64, int, string, bool) {
	proxyURL, err := url.Parse(proxy)
	if err != nil && proxy != "" {
		return nil, 0, err.Error(), false
	}
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok || baseTransport == nil {
		baseTransport = (&http.Transport{}).Clone()
	}
	transport := baseTransport.Clone()
	defer transport.CloseIdleConnections()
	if proxy != "" {
		transport.Proxy = http.ProxyURL(proxyURL)
	} else {
		transport.Proxy = nil
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{ServerName: target.serverName}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.ServerName = target.serverName
	}
	client := &http.Client{
		Transport:     transport,
		Timeout:       proxyTestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	start := time.Now()
	probeBody, probeUserAgent := proxyConnectivityProbe(target)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.url.String(), bytes.NewReader(probeBody))
	if err != nil {
		return nil, 0, err.Error(), false
	}
	request.Host = target.hostHeader
	request.Header.Set("Authorization", "Bearer code-switch-connectivity-probe-invalid")
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", probeUserAgent)
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err.Error(), false
	}
	ms := time.Since(start).Milliseconds()
	defer response.Body.Close()
	if cloudflareBlockedResponse(response) {
		return nil, response.StatusCode, "Cloudflare 拦截（HTTP 403）", true
	}
	return &ms, response.StatusCode, "", false
}

// proxyConnectivityProbe returns the protocol-shaped probe body and User-Agent
// for an account-pool latency test. The target URL already carries the pool's
// configured protocol endpoint, so the dialect is derived from its path: a Chat
// Completions pool must not be probed with a Responses payload (and a
// codex-cli user agent would route it to the wrong upstream handler).
func proxyConnectivityProbe(target resolvedProxyTestTarget) ([]byte, string) {
	if target.url != nil && strings.Contains(strings.ToLower(target.url.Path), "/chat/completions") {
		return []byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"ping"}],"stream":true}`), "openai-python/1.0"
	}
	return []byte(`{"model":"gpt-5-codex","input":[{"role":"user","content":[{"type":"input_text","text":"ping"}]}],"stream":true}`), "codex-cli/1.0"
}

func cloudflareBlockedResponse(response *http.Response) bool {
	if response == nil || response.StatusCode != http.StatusForbidden {
		return false
	}
	if cloudflareBlockedHeaders(response) {
		return true
	}
	if response.Body == nil || !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/html") {
		return false
	}
	originalBody := response.Body
	body, _ := io.ReadAll(io.LimitReader(originalBody, 8<<10))
	response.Body = &prefixedReadCloser{
		Reader: io.MultiReader(bytes.NewReader(body), originalBody),
		Closer: originalBody,
	}
	return strings.Contains(strings.ToLower(string(body)), "cloudflare")
}

type prefixedReadCloser struct {
	io.Reader
	io.Closer
}

func cloudflareBlockedHeaders(response *http.Response) bool {
	return response != nil && response.StatusCode == http.StatusForbidden &&
		(strings.Contains(strings.ToLower(response.Header.Get("Server")), "cloudflare") || response.Header.Get("CF-Ray") != "")
}

func resolveProxyTestTarget(ctx context.Context, rawURL string) (resolvedProxyTestTarget, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return resolvedProxyTestTarget{}, errors.New("Responses 测速地址必须是无凭据的 HTTP(S) URL")
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return resolvedProxyTestTarget{}, errors.New("Responses 测速地址不允许访问本机或内网域名")
	}
	var ips []net.IP
	if literal := net.ParseIP(host); literal != nil {
		ips = []net.IP{literal}
	} else {
		ips, err = net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return resolvedProxyTestTarget{}, fmt.Errorf("Responses 测速地址 DNS 解析失败: %w", err)
		}
		if len(ips) == 0 {
			return resolvedProxyTestTarget{}, errors.New("Responses 测速地址 DNS 未返回可用地址")
		}
	}
	for _, ip := range ips {
		if unsafeProxyTestIP(ip) {
			return resolvedProxyTestTarget{}, errors.New("Responses 测速地址不允许访问本机、内网或保留地址")
		}
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	pinned := *parsed
	pinned.Host = net.JoinHostPort(ips[0].String(), port)
	return resolvedProxyTestTarget{url: &pinned, hostHeader: parsed.Host, serverName: host}, nil
}

var proxyTestDeniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func unsafeProxyTestIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, prefix := range proxyTestDeniedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (m *ProxyManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if probe := m.autoProbe; probe != nil && !probe.complete {
		probe.cancel()
	}
	m.autoProbe = nil
	m.autoSelection = proxyAutoSelection{}
	m.autoWatchPools = make(map[string]struct{})
	if m.cleanupStop != nil {
		select {
		case <-m.cleanupStop:
		default:
			close(m.cleanupStop)
		}
	}
	if err := m.stopProcessLocked(); err != nil {
		fmt.Printf("[proxy] 停止 Mihomo 未完成: %v\n", err)
	}
}

func availablePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func availablePortExcluding(listeners map[string]proxyListener, excluded int) (int, error) {
	for attempt := 0; attempt < 20; attempt++ {
		port, err := availablePort()
		if err != nil {
			continue
		}
		if port == excluded {
			continue
		}
		used := false
		for _, listener := range listeners {
			if listener.port == port {
				used = true
				break
			}
		}
		if !used {
			return port, nil
		}
	}
	return 0, errors.New("无法分配 Mihomo controller 端口")
}

func cloneProxyMap(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = cloneProxyValue(value)
	}
	return output
}

func cloneProxyValue(value any) any {
	switch current := value.(type) {
	case map[string]any:
		return cloneProxyMap(current)
	case []any:
		copyValues := make([]any, len(current))
		for index, item := range current {
			copyValues[index] = cloneProxyValue(item)
		}
		return copyValues
	case []string:
		return append([]string(nil), current...)
	default:
		return current
	}
}

func cloneProxySources(input map[string]proxySource) map[string]proxySource {
	output := make(map[string]proxySource, len(input))
	for name, source := range input {
		copySource := source
		copySource.Nodes = make([]map[string]any, len(source.Nodes))
		for index, node := range source.Nodes {
			copySource.Nodes[index] = cloneProxyMap(node)
		}
		output[name] = copySource
	}
	return output
}

func writePrivateFile(path string, data []byte) error {
	return atomicWriteFile(path, data, 0o600)
}

func writeJSONPrivate(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFile(path, append(data, '\n'))
}
