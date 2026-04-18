package fetcher

import (
	"sync"
	"time"

	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/appconnectorcontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/appconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/appservercontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/bacertificate"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/idpcontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontrollerv2"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/postureprofile"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/scimattributeheader"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/scimgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/segmentgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/servergroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/trustednetwork"
)

type CachedSnapshot struct {
	scimValsMu           sync.Mutex
	ClientTypes          Cache[[]string]
	Segments             Cache[[]applicationsegment.ApplicationSegmentResource]
	SegmentGroups        Cache[[]segmentgroup.SegmentGroup]
	AppConnectors        Cache[[]appconnectorcontroller.AppConnector]
	AppConnectorGroups   Cache[[]appconnectorgroup.AppConnectorGroup]
	AccessPolicies       Cache[[]policysetcontrollerv2.PolicyRuleResource]
	ScimGroups           Cache[[]scimgroup.ScimGroup]
	ServerGroups         Cache[[]servergroup.ServerGroup]
	ApplicationServers   Cache[[]appservercontroller.ApplicationServer]
	TrustedNetworks      Cache[[]trustednetwork.TrustedNetwork]
	PostureProfiles      Cache[[]postureprofile.PostureProfile]
	Platforms            Cache[[]string]
	IdpControllers       Cache[[]idpcontroller.IdpController]
	ScimAttributeHeaders Cache[[]scimattributeheader.ScimAttributeHeader]
	ScimAttributeValues  map[string]*Cache[[]string]
	Certificates         Cache[[]bacertificate.BaCertificate]
}

type Cache[T any] struct {
	mu        sync.RWMutex
	data      T
	fetchedAt time.Time
	ttl       time.Duration
}

// ScimValueCacheFor returns the cache entry for one (idpID, headerID) pair.
// SCIM attribute values vary per header, so the cache must be keyed per
// header, not per IdP.
func (c *CachedSnapshot) ScimValueCacheFor(idpID, headerID string) *Cache[[]string] {
	key := idpID + ":" + headerID
	c.scimValsMu.Lock()
	defer c.scimValsMu.Unlock()
	if c.ScimAttributeValues[key] == nil {
		c.ScimAttributeValues[key] = &Cache[[]string]{ttl: time.Hour}
	}
	return c.ScimAttributeValues[key]
}

// Invalidate forces the next Get to re-fetch by zeroing fetchedAt.
func (c *Cache[T]) Invalidate() {
	c.mu.Lock()
	c.fetchedAt = time.Time{}
	c.mu.Unlock()
}

// Set stores data in the cache and marks it fresh. Used by demo-mode seeding
// so subsequent Get calls return the seeded data without invoking fetch.
func (c *Cache[T]) Set(data T) {
	c.mu.Lock()
	c.data = data
	c.fetchedAt = time.Now()
	c.mu.Unlock()
}

// SeedFromSnapshot writes snap's data into every cache entry, marking each
// fresh. Used by demo mode so BuildIndex and other CachedFetch callers return
// the seeded data without contacting ZPA.
func (c *CachedSnapshot) SeedFromSnapshot(snap *Snapshot) {
	c.ClientTypes.Set(snap.ClientTypes)
	c.Segments.Set(snap.Segments)
	c.SegmentGroups.Set(snap.SegmentGroups)
	c.AppConnectors.Set(snap.AppConnectors)
	c.AppConnectorGroups.Set(snap.AppConnectorGroups)
	c.AccessPolicies.Set(snap.AccessPolicies)
	c.ScimGroups.Set(snap.ScimGroups)
	c.ServerGroups.Set(snap.ServerGroups)
	c.ApplicationServers.Set(snap.ApplicationServers)
	c.TrustedNetworks.Set(snap.TrustedNetworks)
	c.PostureProfiles.Set(snap.PostureProfiles)
	c.Platforms.Set(snap.Platforms)
	c.IdpControllers.Set(snap.IdpControllers)
	c.ScimAttributeHeaders.Set(snap.ScimAttributeHeaders)
	c.Certificates.Set(snap.Certificates)
}

// InvalidateAll marks every cache entry stale so the next Fetch reloads all
// resources from the upstream API. No-op in demo mode so the seeded snapshot
// survives UI refresh actions.
func (c *CachedSnapshot) InvalidateAll() {
	if DemoSeedPath() != "" {
		return
	}
	c.ClientTypes.Invalidate()
	c.Segments.Invalidate()
	c.SegmentGroups.Invalidate()
	c.AppConnectors.Invalidate()
	c.AppConnectorGroups.Invalidate()
	c.AccessPolicies.Invalidate()
	c.ScimGroups.Invalidate()
	c.ServerGroups.Invalidate()
	c.ApplicationServers.Invalidate()
	c.TrustedNetworks.Invalidate()
	c.PostureProfiles.Invalidate()
	c.Platforms.Invalidate()
	c.IdpControllers.Invalidate()
	c.ScimAttributeHeaders.Invalidate()
	c.Certificates.Invalidate()
	c.scimValsMu.Lock()
	for _, v := range c.ScimAttributeValues {
		v.Invalidate()
	}
	c.scimValsMu.Unlock()
}

func (c *Cache[T]) Get(fetch func() (T, error)) (T, error) {
	c.mu.RLock()
	if time.Since(c.fetchedAt) < c.ttl {
		defer c.mu.RUnlock()
		return c.data, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	// Recheck after acquiring the write lock: a concurrent caller may have
	// refreshed while this goroutine was queued. Without this, N concurrent
	// callers after expiry each fire their own fetch in sequence.
	if time.Since(c.fetchedAt) < c.ttl {
		return c.data, nil
	}
	data, err := fetch()
	if err != nil {
		return c.data, err // serve stale on error
	}
	c.data = data
	c.fetchedAt = time.Now()
	return c.data, nil
}
