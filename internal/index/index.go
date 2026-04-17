package index

import (
	"context"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/painscaler/painscaler/internal/fetcher"
	"github.com/painscaler/painscaler/internal/logging"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontrollerv2"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/scimattributeheader"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/scimgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/segmentgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/servergroup"
	"golang.org/x/sync/errgroup"
)

type Index struct {
	Segments      map[string]*applicationsegment.ApplicationSegmentResource
	SegmentGroups map[string]*segmentgroup.SegmentGroup
	Policies      map[string]*policysetcontrollerv2.PolicyRuleResource
	ScimGroups    map[int64]*scimgroup.ScimGroup
	ServerGroups  map[string]*servergroup.ServerGroup
	ScimAttrByID  map[string]*scimattributeheader.ScimAttributeHeader

	SegmentToPolicies  map[string][]string
	GroupToPolicies    map[string][]string
	DomainToSegments   map[string][]string
	ScimAttrNameToID   map[string]string
	OrphanSegments     []string
	DisabledSegments   []string
	OverlappingDomains map[string][]string

	PolicyToScimGroups       map[string][]string // policyID -> []scimGroupID (RHS)
	ConnectorGroupToPolicies map[string][]string // connectorGroupID -> []policyID
	PolicyToConnectorGroups  map[string][]string // policyID -> []connectorGroupID
	ConnectorGroupNames      map[string]string   // connectorGroupID -> name
}

func BuildIndex(ctx context.Context) (*Index, error) {
	start := time.Now()
	outcome := "success"
	defer func() {
		logging.IndexBuildDurationSeconds.Observe(time.Since(start).Seconds())
		logging.IndexBuildsTotal.WithLabelValues(outcome).Inc()
	}()
	cache := fetcher.GetCache()

	// Fan out the six upstream fetches. Each targets a distinct Cache[T], so
	// there is no lock contention between them; each cache still singleflights
	// its own refresh. Cold build goes from 6x serial round-trip to ~1x.
	var (
		segments        []applicationsegment.ApplicationSegmentResource
		segmentGroups   []segmentgroup.SegmentGroup
		accessPolicies  []policysetcontrollerv2.PolicyRuleResource
		serverGroups    []servergroup.ServerGroup
		scimAttrHeaders []scimattributeheader.ScimAttributeHeader
		scimGroups      []scimgroup.ScimGroup
	)
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() (err error) {
		segments, err = fetcher.CachedFetch(gctx, &cache.Segments, fetcher.LoadSegments)
		return
	})
	g.Go(func() (err error) {
		segmentGroups, err = fetcher.CachedFetch(gctx, &cache.SegmentGroups, fetcher.LoadSegmentGroups)
		return
	})
	g.Go(func() (err error) {
		accessPolicies, err = fetcher.CachedFetch(gctx, &cache.AccessPolicies, fetcher.LoadAccessPolicies)
		return
	})
	g.Go(func() (err error) {
		serverGroups, err = fetcher.CachedFetch(gctx, &cache.ServerGroups, fetcher.LoadServerGroups)
		return
	})
	g.Go(func() (err error) {
		scimAttrHeaders, err = fetcher.CachedFetch(gctx, &cache.ScimAttributeHeaders, fetcher.LoadScimAttributeHeaders)
		return
	})
	g.Go(func() (err error) {
		scimGroups, err = fetcher.CachedFetch(gctx, &cache.ScimGroups, fetcher.LoadScimGroups)
		return
	})
	if err := g.Wait(); err != nil {
		outcome = "error"
		return nil, err
	}

	idx := &Index{
		Segments:                 make(map[string]*applicationsegment.ApplicationSegmentResource),
		SegmentGroups:            make(map[string]*segmentgroup.SegmentGroup),
		Policies:                 make(map[string]*policysetcontrollerv2.PolicyRuleResource),
		ScimGroups:               make(map[int64]*scimgroup.ScimGroup),
		ServerGroups:             make(map[string]*servergroup.ServerGroup),
		ScimAttrByID:             make(map[string]*scimattributeheader.ScimAttributeHeader),
		ScimAttrNameToID:         make(map[string]string),
		SegmentToPolicies:        make(map[string][]string),
		GroupToPolicies:          make(map[string][]string),
		DomainToSegments:         make(map[string][]string),
		OverlappingDomains:       make(map[string][]string),
		PolicyToScimGroups:       make(map[string][]string),
		ConnectorGroupToPolicies: make(map[string][]string),
		PolicyToConnectorGroups:  make(map[string][]string),
		ConnectorGroupNames:      make(map[string]string),
	}

	// --- forward lookups ---
	for i := range segments {
		s := &segments[i]
		idx.Segments[s.ID] = s
	}
	for i := range segmentGroups {
		g := &segmentGroups[i]
		idx.SegmentGroups[g.ID] = g
	}
	for i := range accessPolicies {
		p := &accessPolicies[i]
		if reason, ok := validatePolicy(p); !ok {
			slog.Warn("dropped policy",
				slog.String("id", p.ID),
				slog.String("name", p.Name),
				slog.String("ruleOrder", p.RuleOrder),
				slog.String("reason", reason))
			continue
		}
		idx.Policies[p.ID] = p
	}
	for i := range scimGroups {
		g := &scimGroups[i]
		idx.ScimGroups[g.ID] = g
	}
	for i := range serverGroups {
		g := &serverGroups[i]
		idx.ServerGroups[g.ID] = g
	}
	for i := range scimAttrHeaders {
		a := &scimAttrHeaders[i]
		idx.ScimAttrByID[a.ID] = a
		idx.ScimAttrNameToID[a.Name] = a.ID
	}

	// --- domain -> segment inverted index ---
	domainCount := make(map[string][]string)
	for _, seg := range segments {
		for _, domain := range seg.DomainNames {
			d := NormalizeDomain(domain)
			domainCount[d] = AppendUnique(domainCount[d], seg.ID)
		}
	}
	for domain, ids := range domainCount {
		idx.DomainToSegments[domain] = ids
		if len(ids) > 1 {
			idx.OverlappingDomains[domain] = ids
		}
	}

	// --- policy -> segment/group backlinks (inverted) ---
	segmentToGroups := buildSegmentToGroups(segmentGroups)

	for _, pol := range accessPolicies {
		if _, ok := idx.Policies[pol.ID]; !ok {
			continue
		}
		for _, cond := range pol.Conditions {
			for _, op := range cond.Operands {
				switch op.ObjectType {
				case "APP":
					id := op.RHS
					idx.SegmentToPolicies[id] = AppendUnique(idx.SegmentToPolicies[id], pol.ID)

				case "APP_GROUP":
					gid := op.RHS
					idx.GroupToPolicies[gid] = AppendUnique(idx.GroupToPolicies[gid], pol.ID)
					if grp, ok := idx.SegmentGroups[gid]; ok {
						for _, app := range grp.Applications {
							idx.SegmentToPolicies[app.ID] = AppendUnique(idx.SegmentToPolicies[app.ID], pol.ID)
						}
					}
				}
			}
		}
	}

	// --- policy -> scim groups, connector groups ---
	for _, pol := range accessPolicies {
		if _, ok := idx.Policies[pol.ID]; !ok {
			continue
		}
		for _, cond := range pol.Conditions {
			for _, op := range cond.Operands {
				if op.ObjectType == "SCIM_GROUP" && op.RHS != "" {
					idx.PolicyToScimGroups[pol.ID] = AppendUnique(idx.PolicyToScimGroups[pol.ID], op.RHS)
				}
			}
		}
		for _, cg := range pol.AppConnectorGroups {
			if cg.ID != "" {
				idx.PolicyToConnectorGroups[pol.ID] = AppendUnique(idx.PolicyToConnectorGroups[pol.ID], cg.ID)
				idx.ConnectorGroupToPolicies[cg.ID] = AppendUnique(idx.ConnectorGroupToPolicies[cg.ID], pol.ID)
				if cg.Name != "" {
					idx.ConnectorGroupNames[cg.ID] = cg.Name
				}
			}
		}
		for _, sg := range pol.AppServerGroups {
			for _, cg := range sg.AppConnectorGroups {
				if cg.ID != "" {
					idx.PolicyToConnectorGroups[pol.ID] = AppendUnique(idx.PolicyToConnectorGroups[pol.ID], cg.ID)
					idx.ConnectorGroupToPolicies[cg.ID] = AppendUnique(idx.ConnectorGroupToPolicies[cg.ID], pol.ID)
					if cg.Name != "" {
						idx.ConnectorGroupNames[cg.ID] = cg.Name
					}
				}
			}
		}
	}

	// Connector group names from standalone server groups (covers cases not on policies)
	for _, sg := range serverGroups {
		for _, acg := range sg.AppConnectorGroups {
			if acg.ID != "" && acg.Name != "" {
				if _, exists := idx.ConnectorGroupNames[acg.ID]; !exists {
					idx.ConnectorGroupNames[acg.ID] = acg.Name
				}
			}
		}
	}

	for segID, groupIDs := range segmentToGroups {
		for _, gid := range groupIDs {
			for _, polID := range idx.GroupToPolicies[gid] {
				idx.SegmentToPolicies[segID] = AppendUnique(idx.SegmentToPolicies[segID], polID)
			}
		}
	}

	// --- hygiene: orphans and disabled ---
	for _, seg := range segments {
		if !seg.Enabled {
			idx.DisabledSegments = append(idx.DisabledSegments, seg.ID)
		}
		if len(idx.SegmentToPolicies[seg.ID]) == 0 {
			idx.OrphanSegments = append(idx.OrphanSegments, seg.ID)
		}
	}

	return idx, nil
}

// validatePolicy rejects policies that would poison the index: empty IDs
// collide to one map slot, and non-numeric RuleOrder values silently sort
// as 0 in the simulator, quietly reordering real rules.
func validatePolicy(p *policysetcontrollerv2.PolicyRuleResource) (string, bool) {
	if p.ID == "" {
		return "empty ID", false
	}
	if _, err := strconv.Atoi(p.RuleOrder); err != nil {
		return "non-numeric RuleOrder", false
	}
	return "", true
}

func buildSegmentToGroups(segmentGroups []segmentgroup.SegmentGroup) map[string][]string {
	m := make(map[string][]string)
	for _, grp := range segmentGroups {
		for _, app := range grp.Applications {
			m[app.ID] = AppendUnique(m[app.ID], grp.ID)
		}
	}
	return m
}

// NormalizeDomain lowercases and strips a trailing dot from a domain,
// so "MYAPP.corp." and "myapp.corp" match the same key.
func NormalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	return strings.TrimSuffix(d, ".")
}

// AppendUnique appends v to slice only if it isn't already present.
func AppendUnique(slice []string, v string) []string {
	if slices.Contains(slice, v) {
		return slice
	}
	return append(slice, v)
}
