package index

import (
	"strings"

	"github.com/painscaler/painscaler/internal/fetcher"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontrollerv2"
)

// SearchResult is a matched resource with its type and a snippet of
// context showing why it matched.
type SearchResult struct {
	Type    string // "segment" | "segment_group" | "policy" | "server_group"
	ID      string
	Name    string
	Matched string // which field matched and the matching value
}

// Search performs case-insensitive full-text search across all resource
// names, descriptions, and domain names.
func Search(idx *Index, snap *fetcher.Snapshot, term string) []SearchResult {
	term = strings.ToLower(strings.TrimSpace(term))
	if term == "" {
		return nil
	}

	var results []SearchResult

	for _, seg := range snap.Segments {
		if hit, field := matchSegment(seg, term); hit {
			results = append(results, SearchResult{
				Type: "segment", ID: seg.ID, Name: seg.Name, Matched: field,
			})
		}
	}

	for _, grp := range snap.SegmentGroups {
		if contains(grp.Name, term) {
			results = append(results, SearchResult{
				Type: "segment_group", ID: grp.ID, Name: grp.Name, Matched: "name:" + grp.Name,
			})
		}
		if contains(grp.Description, term) {
			results = append(results, SearchResult{
				Type: "segment_group", ID: grp.ID, Name: grp.Name, Matched: "description:" + grp.Description,
			})
		}
	}

	for _, pol := range snap.AccessPolicies {
		if contains(pol.Name, term) {
			results = append(results, SearchResult{
				Type: "policy", ID: pol.ID, Name: pol.Name, Matched: "name:" + pol.Name,
			})
		}
		if contains(pol.Description, term) {
			results = append(results, SearchResult{
				Type: "policy", ID: pol.ID, Name: pol.Name, Matched: "description:" + pol.Description,
			})
		}
	}

	for _, sg := range snap.ServerGroups {
		if contains(sg.Name, term) {
			results = append(results, SearchResult{
				Type: "server_group", ID: sg.ID, Name: sg.Name, Matched: "name:" + sg.Name,
			})
		}
	}

	return results
}

func matchSegment(seg applicationsegment.ApplicationSegmentResource, term string) (bool, string) {
	if contains(seg.Name, term) {
		return true, "name:" + seg.Name
	}
	if contains(seg.Description, term) {
		return true, "description:" + seg.Description
	}
	for _, d := range seg.DomainNames {
		if contains(d, term) {
			return true, "domain:" + d
		}
	}
	return false, ""
}

// PoliciesForSegment returns the access policy rules that cover a given
// app segment ID, along with whether each coverage is direct or via group.
type PolicyCoverage struct {
	Policy *policysetcontrollerv2.PolicyRuleResource
	Via    string // "direct" or "group:<groupName>"
}

func PoliciesForSegment(idx *Index, segmentID string) []PolicyCoverage {
	policyIDs := idx.SegmentToPolicies[segmentID]
	if len(policyIDs) == 0 {
		return nil
	}

	// Build a reverse map: policyID -> which group name caused the match
	// so we can report "via group: Engineering Apps".
	groupCoverage := make(map[string]string)
	for gid, polIDs := range idx.GroupToPolicies {
		grp, ok := idx.SegmentGroups[gid]
		if !ok {
			continue
		}
		var belongs bool
		for _, app := range grp.Applications {
			if app.ID == segmentID {
				belongs = true
				break
			}
		}
		if !belongs {
			continue
		}
		for _, pid := range polIDs {
			groupCoverage[pid] = grp.Name
		}
	}

	var out []PolicyCoverage
	for _, pid := range policyIDs {
		pol, ok := idx.Policies[pid]
		if !ok {
			continue
		}
		via := "direct"
		if gname, ok := groupCoverage[pid]; ok {
			via = "group:" + gname
		}
		out = append(out, PolicyCoverage{Policy: pol, Via: via})
	}
	return out
}

// ReachabilityResult describes which segments cover a host and which
// policy rules allow access to those segments.
type ReachabilityResult struct {
	Domain   string
	Segments []SegmentReachability
}

type SegmentReachability struct {
	Segment  *applicationsegment.ApplicationSegmentResource
	Policies []PolicyCoverage
}

// WhoCanReach returns all app segments that cover the given hostname and
// the policies that grant access to each.
func WhoCanReach(idx *Index, hostname string) ReachabilityResult {
	hostname = NormalizeDomain(hostname)
	result := ReachabilityResult{Domain: hostname}

	// Collect candidates: exact match, then wildcard parents.
	var segIDs []string
	if ids, ok := idx.DomainToSegments[hostname]; ok {
		segIDs = append(segIDs, ids...)
	}
	// Walk wildcard parents: "app.corp.example.com" -> try "*.corp.example.com",
	// "*.example.com", "*.com" in order.
	for _, wc := range WildcardParents(hostname) {
		if ids, ok := idx.DomainToSegments[wc]; ok {
			segIDs = append(segIDs, ids...)
		}
	}
	segIDs = dedup(segIDs)

	for _, sid := range segIDs {
		seg := idx.Segments[sid]
		if seg == nil {
			continue
		}
		policies := PoliciesForSegment(idx, sid)
		result.Segments = append(result.Segments, SegmentReachability{
			Segment:  seg,
			Policies: policies,
		})
	}
	return result
}

// wildcardParents returns the wildcard forms of a hostname from most to
// least specific.  "a.b.example.com" -> ["*.b.example.com", "*.example.com", "*.com"]
func WildcardParents(hostname string) []string {
	parts := strings.Split(hostname, ".")
	var out []string
	for i := 1; i < len(parts); i++ {
		out = append(out, "*."+strings.Join(parts[i:], "."))
	}
	return out
}

// OrphanReport describes segments that have no access policy coverage.
type OrphanReport struct {
	Segment *applicationsegment.ApplicationSegmentResource
	Groups  []string // segment group names this segment belongs to
}

// Orphans returns all app segments that no access policy references.
func Orphans(idx *Index, snap *fetcher.Snapshot) []OrphanReport {
	// Build segment -> group names for context in the report.
	segToGroupNames := make(map[string][]string)
	for _, grp := range snap.SegmentGroups {
		for _, app := range grp.Applications {
			segToGroupNames[app.ID] = append(segToGroupNames[app.ID], grp.Name)
		}
	}

	var out []OrphanReport
	for _, segID := range idx.OrphanSegments {
		seg := idx.Segments[segID]
		if seg == nil {
			continue
		}
		out = append(out, OrphanReport{
			Segment: seg,
			Groups:  segToGroupNames[segID],
		})
	}
	return out
}

// OverlapReport describes a domain covered by more than one app segment.
type OverlapReport struct {
	Domain   string
	Segments []*applicationsegment.ApplicationSegmentResource
}

// Overlaps returns all domains that appear in more than one app segment.
func Overlaps(idx *Index) []OverlapReport {
	var out []OverlapReport
	for domain, ids := range idx.OverlappingDomains {
		rep := OverlapReport{Domain: domain}
		for _, id := range ids {
			if seg := idx.Segments[id]; seg != nil {
				rep.Segments = append(rep.Segments, seg)
			}
		}
		out = append(out, rep)
	}
	return out
}

// --- small helpers ---

func contains(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), sub)
}

func dedup(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := ids[:0]
	for _, id := range ids {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}
