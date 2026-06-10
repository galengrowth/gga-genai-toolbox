// Copyright 2026 Galen Growth
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"sync"
	"time"
)

const (
	mcpSessionMetaTTL       = 10 * time.Minute
	mcpSessionMetaMaxEntries = 10000
	mcpSessionMetaCleanup   = 2 * time.Minute
)

// mcpSessionMetaManager stores MCP initialize clientInfo keyed by Mcp-Session-Id (streamable HTTP 2025-03-26).
type mcpSessionMetaManager struct {
	mu   sync.Mutex
	byID map[string]*mcpSessionMetaEntry
}

type mcpSessionMetaEntry struct {
	name, version string
	lastActive     time.Time
}

func newMcpSessionMetaManager(ctx context.Context) *mcpSessionMetaManager {
	m := &mcpSessionMetaManager{
		byID: make(map[string]*mcpSessionMetaEntry),
	}
	go m.cleanupRoutine(ctx)
	return m
}

// Register records client name/version for a newly issued session id.
func (m *mcpSessionMetaManager) Register(sessionID, name, version string) {
	if sessionID == "" {
		return
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.byID) >= mcpSessionMetaMaxEntries {
		m.evictOldestLocked()
	}
	m.byID[sessionID] = &mcpSessionMetaEntry{name: name, version: version, lastActive: now}
}

// Get returns stored MCP client metadata and refreshes lastActive.
func (m *mcpSessionMetaManager) Get(sessionID string) (name, version string, ok bool) {
	if sessionID == "" {
		return "", "", false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, found := m.byID[sessionID]
	if !found || e == nil {
		return "", "", false
	}
	e.lastActive = time.Now()
	return e.name, e.version, true
}

func (m *mcpSessionMetaManager) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, e := range m.byID {
		if e == nil {
			delete(m.byID, k)
			continue
		}
		if first || e.lastActive.Before(oldestTime) {
			first = false
			oldestTime = e.lastActive
			oldestKey = k
		}
	}
	if oldestKey != "" {
		delete(m.byID, oldestKey)
	}
}

func (m *mcpSessionMetaManager) cleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(mcpSessionMetaCleanup)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

func (m *mcpSessionMetaManager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for id, e := range m.byID {
		if e == nil || now.Sub(e.lastActive) > mcpSessionMetaTTL {
			delete(m.byID, id)
		}
	}
}
