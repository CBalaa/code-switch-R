package services

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
)

// Account-pool sessions are deliberately runtime-only. The store keeps hashes
// of client-facing conversation identities, never the identities themselves.
const accountPoolStickyIdleTTL = 24 * time.Hour

type accountPoolStickyScope struct {
	userID     string
	relayKeyID string
	platform   string
	poolID     string
}

// accountPoolLoadScope deliberately omits relayKeyID. Relay keys retain
// independent conversation affinity, while all of a user's keys bound to the
// same account pool compete for the same account-key capacity at selection
// time.
type accountPoolLoadScope struct {
	userID   string
	platform string
	poolID   string
}

func newAccountPoolStickyScope(userID, relayKeyID, platform, poolID string) accountPoolStickyScope {
	return accountPoolStickyScope{
		userID:     strings.TrimSpace(userID),
		relayKeyID: strings.TrimSpace(relayKeyID),
		platform:   strings.TrimSpace(platform),
		poolID:     strings.TrimSpace(poolID),
	}
}

func newAccountPoolLoadScope(userID, platform, poolID string) accountPoolLoadScope {
	return accountPoolLoadScope{
		userID:   strings.TrimSpace(userID),
		platform: strings.TrimSpace(platform),
		poolID:   strings.TrimSpace(poolID),
	}
}

func (scope accountPoolStickyScope) loadScope() accountPoolLoadScope {
	return newAccountPoolLoadScope(scope.userID, scope.platform, scope.poolID)
}

type accountPoolRequestIdentity struct {
	// lookupHashes are ordered by identity precedence: conversation first, then
	// the client-provided previous_response_id. They are used only to find an
	// existing session and never directly become response aliases.
	lookupHashes []string
	// sessionHashes are durable primary identities. At present that is only a
	// conversation ID; response IDs are added only after a successful upstream
	// response in commit.
	sessionHashes   []string
	provisionalHash string
}

// accountPoolRequestIdentityFromBody derives the sticky-session identity from
// the inbound request body. The fields are shared by both account-pool
// protocols: Responses clients send conversation/previous_response_id, while
// Chat Completions clients send prompt_cache_key (and often nothing else).
// Requests that carry no durable identity fall back to least-loaded selection
// with a provisional reservation.
func accountPoolRequestIdentityFromBody(body []byte) accountPoolRequestIdentity {
	conversationID := ""
	conversation := gjson.GetBytes(body, "conversation")
	if conversation.Exists() {
		switch conversation.Type {
		case gjson.String:
			conversationID = strings.TrimSpace(conversation.String())
		default:
			conversationID = strings.TrimSpace(conversation.Get("id").String())
		}
	}
	promptCacheKey := strings.TrimSpace(gjson.GetBytes(body, "prompt_cache_key").String())
	previousResponseID := strings.TrimSpace(gjson.GetBytes(body, "previous_response_id").String())

	identity := accountPoolRequestIdentity{}
	if conversationID != "" {
		conversationHash := accountPoolIdentityHash(conversationID)
		identity.lookupHashes = append(identity.lookupHashes, conversationHash)
		identity.sessionHashes = append(identity.sessionHashes, conversationHash)
	}
	if promptCacheKey != "" {
		// OpenAI Responses clients (e.g. Pi) send their stable session ID as
		// prompt_cache_key instead of previous_response_id, and Chat Completions
		// clients use the same field for prompt-cache affinity. It is safe to use
		// for affinity because only its one-way hash reaches the runtime store.
		promptCacheHash := accountPoolIdentityHash(promptCacheKey)
		if len(identity.lookupHashes) == 0 || identity.lookupHashes[len(identity.lookupHashes)-1] != promptCacheHash {
			identity.lookupHashes = append(identity.lookupHashes, promptCacheHash)
		}
		if len(identity.sessionHashes) == 0 || identity.sessionHashes[len(identity.sessionHashes)-1] != promptCacheHash {
			identity.sessionHashes = append(identity.sessionHashes, promptCacheHash)
		}
	}
	if previousResponseID != "" {
		previousHash := accountPoolIdentityHash(previousResponseID)
		if len(identity.lookupHashes) == 0 || identity.lookupHashes[0] != previousHash {
			identity.lookupHashes = append(identity.lookupHashes, previousHash)
		}
	}
	if len(identity.lookupHashes) == 0 {
		identity.provisionalHash = newAccountPoolProvisionalIdentityHash()
	}
	return identity
}

func accountPoolIdentityHash(value string) string {
	sum := sha256.Sum256([]byte("code-switch/account-pool-session/v1\x00" + strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}

func newAccountPoolProvisionalIdentityHash() string {
	var random [32]byte
	if _, err := cryptorand.Read(random[:]); err == nil {
		sum := sha256.Sum256(random[:])
		return hex.EncodeToString(sum[:])
	}
	// crypto/rand failure is exceptional. This fallback remains a hash and is
	// only retained for the lifetime of the inbound request.
	sum := sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
	return hex.EncodeToString(sum[:])
}

type accountPoolStickySession struct {
	providerID int64
	lastSeen   time.Time
}

type accountPoolStickyScopeState struct {
	aliases            map[string]string
	sessions           map[string]*accountPoolStickySession
	nextSessionOrdinal uint64
}

type accountPoolLoadScopeState struct {
	sessionCounts          map[int64]int
	reservations           map[int64]map[uint64]struct{}
	lastTieProviderID      int64
	nextReservationOrdinal uint64
}

type accountPoolStickyRequest struct {
	scope            accountPoolStickyScope
	loadScope        accountPoolLoadScope
	lookupHashes     []string
	sessionHashes    []string
	provisionalHash  string
	sessionID        string
	providerID       int64
	holdsReservation bool
	reservationID    uint64
}

// accountPoolStickyStore owns all session state for a relay process. It is
// intentionally not persisted: session affinity should expire on restart just
// like other relay runtime state, without storing conversation identifiers.
type accountPoolStickyStore struct {
	mu     sync.Mutex
	ttl    time.Duration
	now    func() time.Time
	scopes map[accountPoolStickyScope]*accountPoolStickyScopeState
	loads  map[accountPoolLoadScope]*accountPoolLoadScopeState
}

func newAccountPoolStickyStore() *accountPoolStickyStore {
	return &accountPoolStickyStore{
		ttl:    accountPoolStickyIdleTTL,
		now:    time.Now,
		scopes: make(map[accountPoolStickyScope]*accountPoolStickyScopeState),
		loads:  make(map[accountPoolLoadScope]*accountPoolLoadScopeState),
	}
}

func (s *accountPoolStickyStore) begin(scope accountPoolStickyScope, identity accountPoolRequestIdentity, active []Provider) *accountPoolStickyRequest {
	request := &accountPoolStickyRequest{
		scope:           scope,
		loadScope:       scope.loadScope(),
		lookupHashes:    append([]string(nil), identity.lookupHashes...),
		sessionHashes:   append([]string(nil), identity.sessionHashes...),
		provisionalHash: identity.provisionalHash,
	}
	if s == nil {
		return request
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.stateLocked(scope)
	loadState := s.loadStateLocked(request.loadScope)
	now := s.nowLocked()
	s.pruneLoadScopeLocked(request.loadScope, active, now)

	for _, identityHash := range request.lookupHashes {
		if sessionID, ok := state.aliases[identityHash]; ok {
			if session := state.sessions[sessionID]; session != nil {
				session.lastSeen = now
				request.sessionID = sessionID
				request.providerID = session.providerID
				return request
			}
			delete(state.aliases, identityHash)
		}
	}

	request.providerID = selectLeastBoundAccountPoolProvider(loadState, active)
	if request.providerID != 0 {
		loadState.lastTieProviderID = request.providerID
		if len(request.sessionHashes) > 0 {
			request.sessionID = s.createSessionLocked(state, loadState, request.providerID, now, request.sessionHashes)
		} else {
			// Requests without a durable conversation identity reserve capacity
			// until an upstream response ID can promote them to a session.
			s.holdReservationLocked(loadState, request)
		}
	}
	return request
}

// order returns only the assigned key for a durable session. A transient
// failure must remain on that key until it is blacklisted or removed; otherwise
// a response produced by a fallback key could be linked back to the old key.
// Anonymous requests retain the configured fallback order until their first
// successful response creates a durable session.
func (s *accountPoolStickyStore) order(request *accountPoolStickyRequest, active []Provider) []Provider {
	if request == nil || s == nil {
		return append([]Provider(nil), active...)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.stateLocked(request.scope)
	loadState := s.loadStateLocked(request.loadScope)
	now := s.nowLocked()
	s.pruneLoadScopeLocked(request.loadScope, active, now)
	activeByID := providersByID(active)

	if request.sessionID != "" {
		if session := state.sessions[request.sessionID]; session != nil {
			if _, available := activeByID[session.providerID]; available {
				session.lastSeen = now
				request.providerID = session.providerID
			} else {
				s.removeSessionLocked(state, loadState, request.sessionID)
				request.sessionID = ""
				request.providerID = 0
			}
		} else {
			request.sessionID = ""
			request.providerID = 0
		}
	}

	if request.providerID != 0 {
		if _, available := activeByID[request.providerID]; !available {
			s.releaseReservationLocked(loadState, request)
			request.providerID = 0
		}
	}
	if request.providerID == 0 {
		request.providerID = selectLeastBoundAccountPoolProvider(loadState, active)
		if request.providerID != 0 {
			loadState.lastTieProviderID = request.providerID
			if len(request.sessionHashes) > 0 {
				request.sessionID = s.createSessionLocked(state, loadState, request.providerID, now, request.sessionHashes)
			} else {
				s.holdReservationLocked(loadState, request)
			}
		}
	}

	if request.providerID == 0 {
		return append([]Provider(nil), active...)
	}
	if request.sessionID != "" {
		for _, provider := range active {
			if provider.ID == request.providerID {
				return []Provider{provider}
			}
		}
	}
	ordered := make([]Provider, 0, len(active))
	for _, provider := range active {
		if provider.ID == request.providerID {
			ordered = append(ordered, provider)
			break
		}
	}
	for _, provider := range active {
		if provider.ID != request.providerID {
			ordered = append(ordered, provider)
		}
	}
	return ordered
}

func (s *accountPoolStickyStore) commit(request *accountPoolStickyRequest, successfulProviderID int64, responseID string) {
	if s == nil || request == nil || successfulProviderID == 0 {
		return
	}
	responseID = strings.TrimSpace(responseID)
	responseHash := ""
	if responseID != "" {
		responseHash = accountPoolIdentityHash(responseID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.stateLocked(request.scope)
	loadState := s.loadStateLocked(request.loadScope)
	now := s.nowLocked()
	s.pruneExpiredLoadScopeLocked(request.loadScope, now)
	s.releaseReservationLocked(loadState, request)

	sessionID := request.sessionID
	session := state.sessions[sessionID]
	createdSession := false
	if session == nil {
		// A request without a durable conversation identity becomes a session
		// only after the upstream has returned a response ID.
		if len(request.sessionHashes) == 0 && responseHash == "" {
			return
		}
		state.nextSessionOrdinal++
		sessionID = strconv.FormatUint(state.nextSessionOrdinal, 10)
		session = &accountPoolStickySession{providerID: successfulProviderID, lastSeen: now}
		state.sessions[sessionID] = session
		loadState.sessionCounts[successfulProviderID]++
		request.sessionID = sessionID
		createdSession = true
	} else {
		// Preserve a valid pre-existing session's key after a transient failure.
		// If it was blacklisted, invalidateProvider removes it before this point,
		// causing a fresh binding to be created above.
		session.lastSeen = now
	}

	aliases := make([]string, 0, len(request.sessionHashes)+1)
	if createdSession {
		// A conversation identity is recorded when it first creates a session.
		// Existing sessions receive only the upstream-issued response ID below.
		aliases = append(aliases, request.sessionHashes...)
	}
	if responseHash != "" {
		aliases = append(aliases, responseHash)
	}
	s.attachAliasesLocked(state, loadState, sessionID, aliases)
}

func (s *accountPoolStickyStore) abort(request *accountPoolStickyRequest) {
	if s == nil || request == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.scopes[request.scope]
	if state == nil {
		return
	}
	s.releaseReservationLocked(s.loads[request.loadScope], request)
}

// invalidateProvider removes sessions only after that pool key has been
// blacklisted. Pool-key deletion is handled lazily by pruneUnavailableLocked
// on the next request, using the latest pool definition.
func (s *accountPoolStickyStore) invalidateProvider(userID, platform, poolID string, providerID int64) {
	if s == nil || providerID == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	loadScope := newAccountPoolLoadScope(userID, platform, poolID)
	loadState := s.loads[loadScope]
	for scope, state := range s.scopes {
		if scope.userID != strings.TrimSpace(userID) || scope.platform != strings.TrimSpace(platform) || scope.poolID != strings.TrimSpace(poolID) {
			continue
		}
		for sessionID, session := range state.sessions {
			if session.providerID == providerID {
				s.removeSessionLocked(state, loadState, sessionID)
			}
		}
	}
	if loadState != nil {
		delete(loadState.reservations, providerID)
	}
}

func (s *accountPoolStickyStore) stateLocked(scope accountPoolStickyScope) *accountPoolStickyScopeState {
	state := s.scopes[scope]
	if state != nil {
		return state
	}
	state = &accountPoolStickyScopeState{
		aliases:  make(map[string]string),
		sessions: make(map[string]*accountPoolStickySession),
	}
	s.scopes[scope] = state
	return state
}

func (s *accountPoolStickyStore) loadStateLocked(scope accountPoolLoadScope) *accountPoolLoadScopeState {
	state := s.loads[scope]
	if state != nil {
		return state
	}
	state = &accountPoolLoadScopeState{
		sessionCounts: make(map[int64]int),
		reservations:  make(map[int64]map[uint64]struct{}),
	}
	s.loads[scope] = state
	return state
}

func (s *accountPoolStickyStore) nowLocked() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

func (s *accountPoolStickyStore) pruneExpiredLoadScopeLocked(loadScope accountPoolLoadScope, now time.Time) {
	loadState := s.loads[loadScope]
	if loadState == nil {
		return
	}
	for scope, state := range s.scopes {
		if scope.loadScope() == loadScope {
			s.pruneExpiredLocked(state, loadState, now)
		}
	}
}

func (s *accountPoolStickyStore) pruneLoadScopeLocked(loadScope accountPoolLoadScope, active []Provider, now time.Time) {
	loadState := s.loads[loadScope]
	if loadState == nil {
		return
	}
	for scope, state := range s.scopes {
		if scope.loadScope() == loadScope {
			s.pruneExpiredLocked(state, loadState, now)
			s.pruneUnavailableLocked(state, loadState, active)
		}
	}
}

func (s *accountPoolStickyStore) pruneExpiredLocked(state *accountPoolStickyScopeState, loadState *accountPoolLoadScopeState, now time.Time) {
	if state == nil {
		return
	}
	ttl := s.ttl
	if ttl <= 0 {
		ttl = accountPoolStickyIdleTTL
	}
	for sessionID, session := range state.sessions {
		if session == nil || now.Sub(session.lastSeen) >= ttl {
			s.removeSessionLocked(state, loadState, sessionID)
		}
	}
}

func (s *accountPoolStickyStore) pruneUnavailableLocked(state *accountPoolStickyScopeState, loadState *accountPoolLoadScopeState, active []Provider) {
	if state == nil {
		return
	}
	available := providersByID(active)
	for sessionID, session := range state.sessions {
		if session == nil {
			s.removeSessionLocked(state, loadState, sessionID)
			continue
		}
		if _, ok := available[session.providerID]; !ok {
			s.removeSessionLocked(state, loadState, sessionID)
		}
	}
}

func (s *accountPoolStickyStore) removeSessionLocked(state *accountPoolStickyScopeState, loadState *accountPoolLoadScopeState, sessionID string) {
	if state == nil || sessionID == "" {
		return
	}
	if session := state.sessions[sessionID]; session != nil && loadState != nil {
		if count := loadState.sessionCounts[session.providerID]; count <= 1 {
			delete(loadState.sessionCounts, session.providerID)
		} else {
			loadState.sessionCounts[session.providerID] = count - 1
		}
	}
	delete(state.sessions, sessionID)
	for identityHash, mappedSessionID := range state.aliases {
		if mappedSessionID == sessionID {
			delete(state.aliases, identityHash)
		}
	}
}

func (s *accountPoolStickyStore) createSessionLocked(state *accountPoolStickyScopeState, loadState *accountPoolLoadScopeState, providerID int64, now time.Time, aliases []string) string {
	if state == nil || providerID == 0 {
		return ""
	}
	state.nextSessionOrdinal++
	sessionID := strconv.FormatUint(state.nextSessionOrdinal, 10)
	state.sessions[sessionID] = &accountPoolStickySession{providerID: providerID, lastSeen: now}
	if loadState != nil {
		loadState.sessionCounts[providerID]++
	}
	s.attachAliasesLocked(state, loadState, sessionID, aliases)
	return sessionID
}

func (s *accountPoolStickyStore) releaseReservationLocked(loadState *accountPoolLoadScopeState, request *accountPoolStickyRequest) {
	if loadState == nil || request == nil || !request.holdsReservation || request.providerID == 0 || request.reservationID == 0 {
		return
	}
	reservations := loadState.reservations[request.providerID]
	delete(reservations, request.reservationID)
	if len(reservations) == 0 {
		delete(loadState.reservations, request.providerID)
	}
	request.holdsReservation = false
	request.reservationID = 0
}

func (s *accountPoolStickyStore) holdReservationLocked(loadState *accountPoolLoadScopeState, request *accountPoolStickyRequest) {
	if loadState == nil || request == nil || request.providerID == 0 || request.holdsReservation {
		return
	}
	loadState.nextReservationOrdinal++
	request.reservationID = loadState.nextReservationOrdinal
	reservations := loadState.reservations[request.providerID]
	if reservations == nil {
		reservations = make(map[uint64]struct{})
		loadState.reservations[request.providerID] = reservations
	}
	reservations[request.reservationID] = struct{}{}
	request.holdsReservation = true
}

func (s *accountPoolStickyStore) attachAliasesLocked(state *accountPoolStickyScopeState, loadState *accountPoolLoadScopeState, targetSessionID string, aliases []string) {
	if state == nil || targetSessionID == "" {
		return
	}
	for _, identityHash := range aliases {
		if identityHash == "" {
			continue
		}
		if previousSessionID := state.aliases[identityHash]; previousSessionID != "" && previousSessionID != targetSessionID {
			// The request's higher-priority identity selects targetSessionID. Merge
			// a linked previous_response_id session into it so aliases count once.
			for alias, mappedSessionID := range state.aliases {
				if mappedSessionID == previousSessionID {
					state.aliases[alias] = targetSessionID
				}
			}
			s.removeSessionLocked(state, loadState, previousSessionID)
		}
		state.aliases[identityHash] = targetSessionID
	}
}

func selectLeastBoundAccountPoolProvider(state *accountPoolLoadScopeState, active []Provider) int64 {
	if state == nil || len(active) == 0 {
		return 0
	}
	loads := make(map[int64]int, len(active))
	for _, provider := range active {
		loads[provider.ID] = state.sessionCounts[provider.ID] + len(state.reservations[provider.ID])
	}

	minimum := -1
	for _, provider := range active {
		load := loads[provider.ID]
		if minimum < 0 || load < minimum {
			minimum = load
		}
	}
	start := 0
	if state.lastTieProviderID != 0 {
		for index, provider := range active {
			if provider.ID == state.lastTieProviderID {
				start = (index + 1) % len(active)
				break
			}
		}
	}
	for offset := 0; offset < len(active); offset++ {
		provider := active[(start+offset)%len(active)]
		if loads[provider.ID] == minimum {
			return provider.ID
		}
	}
	return 0
}

func providersByID(providers []Provider) map[int64]Provider {
	result := make(map[int64]Provider, len(providers))
	for _, provider := range providers {
		if provider.ID != 0 {
			result[provider.ID] = provider
		}
	}
	return result
}
