package analysis

import (
	"testing"
)

// TestBlastRadius_ConnectorGroup verifies that passing a connector_group
// target resolves to the affected policies, and from those policies to the
// referenced SCIM groups and segments. Confirms the target name is taken
// from ConnectorGroupNames.
func TestBlastRadius_ConnectorGroup(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "grp1")
	idx.ConnectorGroupNames["cg1"] = "CG One"

	p := withConnectorGroup(policy("pol1", "Pol1", "ALLOW", "1",
		cond("OR", op("APP", "seg1"), op("SCIM_GROUP", "100"))), "cg1", "CG One")
	registerPolicy(idx, p)

	got := BlastRadius(idx, "cg1", "connector_group")
	if got.TargetName != "CG One" {
		t.Errorf("TargetName = %q", got.TargetName)
	}
	if len(got.Policies) != 1 || got.Policies[0].ID != "pol1" {
		t.Errorf("Policies = %+v", got.Policies)
	}
	if len(got.ScimGroups) != 1 || got.ScimGroups[0].ID != "100" {
		t.Errorf("ScimGroups = %+v", got.ScimGroups)
	}
	if len(got.Segments) != 1 || got.Segments[0].ID != "seg1" {
		t.Errorf("Segments = %+v", got.Segments)
	}
}

// TestBlastRadius_ServerGroupResolvesCGs verifies that a server_group
// target expands to its attached connector groups and reports policies
// impacted through any of them. The target name comes from the server
// group record.
func TestBlastRadius_ServerGroupResolvesCGs(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "grp1")
	idx.ServerGroups["srv1"] = serverGroup("srv1", "Srv1", []string{"cg1", "cg2"}, nil)
	idx.ConnectorGroupNames["cg1"] = "CG1"

	p := withConnectorGroup(policy("pol1", "Pol1", "ALLOW", "1",
		cond("AND", op("APP", "seg1"))), "cg1", "CG1")
	registerPolicy(idx, p)

	got := BlastRadius(idx, "srv1", "server_group")
	if got.TargetName != "Srv1" {
		t.Errorf("TargetName = %q", got.TargetName)
	}
	if len(got.Policies) != 1 {
		t.Errorf("want 1 policy via cg1, got %+v", got.Policies)
	}
}

// TestBlastRadius_NoDuplicates verifies that when a policy references the
// same segment via both APP and APP_GROUP and lists a SCIM group operand
// twice, the report contains each segment and SCIM group once. Guards the
// dedup sets (polSet, scimSet, segSet).
func TestBlastRadius_NoDuplicates(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "grp1")
	idx.SegmentGroups["grp1"] = segGroup("grp1", "Grp1", "seg1")

	p := withConnectorGroup(policy("pol1", "Pol1", "ALLOW", "1",
		cond("AND",
			op("APP", "seg1"),
			op("APP_GROUP", "grp1"),
			op("SCIM_GROUP", "100"),
			op("SCIM_GROUP", "100"),
		)), "cg1", "CG1")
	registerPolicy(idx, p)

	got := BlastRadius(idx, "cg1", "connector_group")
	if len(got.Segments) != 1 {
		t.Errorf("dedup failed: segments=%+v", got.Segments)
	}
	if len(got.ScimGroups) != 1 {
		t.Errorf("dedup failed: scim=%+v", got.ScimGroups)
	}
}

// TestPolicyShadows_DetectShadow verifies that two policies sharing the
// same (SCIM group, segment) pair and the same Action yield exactly one
// shadow report with Verdict="shadow". This is the primary shadow signal.
func TestPolicyShadows_DetectShadow(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "grp1")

	a := policy("polA", "A", "ALLOW", "1",
		cond("AND", op("APP", "seg1"), op("SCIM_GROUP", "100")))
	b := policy("polB", "B", "ALLOW", "2",
		cond("AND", op("APP", "seg1"), op("SCIM_GROUP", "100")))
	registerPolicy(idx, a)
	registerPolicy(idx, b)

	reports := PolicyShadows(idx)
	if len(reports) != 1 {
		t.Fatalf("want 1 shadow report, got %d", len(reports))
	}
	if reports[0].Verdict != "shadow" {
		t.Errorf("verdict = %q, want shadow", reports[0].Verdict)
	}
}

// TestPolicyShadows_ConflictVerdict verifies that two overlapping policies
// with differing actions (ALLOW vs DENY) are reported with
// Verdict="conflict" rather than "shadow". Conflicts are a higher-severity
// finding than shadows.
func TestPolicyShadows_ConflictVerdict(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "grp1")

	a := policy("polA", "A", "ALLOW", "1",
		cond("AND", op("APP", "seg1"), op("SCIM_GROUP", "100")))
	b := policy("polB", "B", "DENY", "2",
		cond("AND", op("APP", "seg1"), op("SCIM_GROUP", "100")))
	registerPolicy(idx, a)
	registerPolicy(idx, b)

	reports := PolicyShadows(idx)
	if len(reports) != 1 || reports[0].Verdict != "conflict" {
		t.Errorf("reports = %+v", reports)
	}
}

// TestPolicyShadows_Disjoint verifies that policies whose (SCIM, segment)
// pairs do not intersect produce no shadow reports. Guards against false
// positives when SCIM groups and segments differ across policies.
func TestPolicyShadows_Disjoint(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "")
	idx.Segments["seg2"] = seg("seg2", "Seg2", "")

	a := policy("polA", "A", "ALLOW", "1",
		cond("AND", op("APP", "seg1"), op("SCIM_GROUP", "100")))
	b := policy("polB", "B", "ALLOW", "2",
		cond("AND", op("APP", "seg2"), op("SCIM_GROUP", "200")))
	registerPolicy(idx, a)
	registerPolicy(idx, b)

	if reports := PolicyShadows(idx); len(reports) != 0 {
		t.Errorf("expected no overlap, got %+v", reports)
	}
}

// TestPolicyShadows_SkipPoliciesWithoutScim verifies that policies with no
// SCIM group operands are excluded from shadow analysis. Such policies
// cannot be meaningfully compared on user reach and would produce noise.
func TestPolicyShadows_SkipPoliciesWithoutScim(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "")
	a := policy("polA", "A", "ALLOW", "1", cond("AND", op("APP", "seg1")))
	b := policy("polB", "B", "ALLOW", "2", cond("AND", op("APP", "seg1")))
	registerPolicy(idx, a)
	registerPolicy(idx, b)
	if reports := PolicyShadows(idx); len(reports) != 0 {
		t.Errorf("policies without scim must be skipped, got %+v", reports)
	}
}

// TestOrphanClusters_FullyOrphaned verifies that when every segment in a
// segment group lacks a policy, the resulting cluster is flagged
// FullyOrphaned=true and includes all orphaned segments.
func TestOrphanClusters_FullyOrphaned(t *testing.T) {
	idx := newIndex()
	idx.SegmentGroups["grp1"] = segGroup("grp1", "Grp1", "seg1", "seg2")
	idx.Segments["seg1"] = seg("seg1", "Seg1", "grp1")
	idx.Segments["seg2"] = seg("seg2", "Seg2", "grp1")
	registerOrphans(idx)

	clusters := OrphanClusters(idx)
	if len(clusters) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(clusters))
	}
	if !clusters[0].FullyOrphaned {
		t.Errorf("expected FullyOrphaned=true")
	}
	if len(clusters[0].OrphanSegments) != 2 {
		t.Errorf("segments=%+v", clusters[0].OrphanSegments)
	}
}

// TestOrphanClusters_PartiallyOrphaned verifies that when only some
// segments in a group are orphaned, the cluster is reported with
// FullyOrphaned=false. Ensures the "full vs partial" boundary is correct.
func TestOrphanClusters_PartiallyOrphaned(t *testing.T) {
	idx := newIndex()
	idx.SegmentGroups["grp1"] = segGroup("grp1", "Grp1", "seg1", "seg2")
	idx.Segments["seg1"] = seg("seg1", "Seg1", "grp1")
	idx.Segments["seg2"] = seg("seg2", "Seg2", "grp1")
	registerPolicy(idx, policy("pol1", "P1", "ALLOW", "1",
		cond("AND", op("APP", "seg1"), op("SCIM_GROUP", "100"))))
	registerOrphans(idx)

	clusters := OrphanClusters(idx)
	if len(clusters) != 1 || clusters[0].FullyOrphaned {
		t.Errorf("want partial cluster, got %+v", clusters)
	}
}

// TestOrphanClusters_Empty verifies that an empty index returns an empty
// cluster slice without panicking. Guards edge case of a fresh or filtered
// index with no orphans.
func TestOrphanClusters_Empty(t *testing.T) {
	idx := newIndex()
	if got := OrphanClusters(idx); len(got) != 0 {
		t.Errorf("want empty, got %+v", got)
	}
}

// TestDomainOverlapDetails_ConflictDetection verifies that when two
// segments share a domain and their policies disagree on action
// (ALLOW vs DENY), HasConflict=true. This is the primary signal for
// misconfigured overlapping domain coverage.
func TestDomainOverlapDetails_ConflictDetection(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "", "app.foo.com")
	idx.Segments["seg2"] = seg("seg2", "Seg2", "", "app.foo.com")
	idx.OverlappingDomains["app.foo.com"] = []string{"seg1", "seg2"}

	registerPolicy(idx, policy("pA", "A", "ALLOW", "1",
		cond("AND", op("APP", "seg1"), op("SCIM_GROUP", "100"))))
	registerPolicy(idx, policy("pB", "B", "DENY", "2",
		cond("AND", op("APP", "seg2"), op("SCIM_GROUP", "200"))))

	details := DomainOverlapDetails(idx)
	if len(details) != 1 {
		t.Fatalf("want 1 detail, got %d", len(details))
	}
	if !details[0].HasConflict {
		t.Errorf("want HasConflict=true (ALLOW+DENY)")
	}
}

// TestDomainOverlapDetails_NoConflictSameAction verifies that overlapping
// domains with policies agreeing on action (both ALLOW) are reported
// without HasConflict. Overlap alone is not a conflict.
func TestDomainOverlapDetails_NoConflictSameAction(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "", "app.foo.com")
	idx.Segments["seg2"] = seg("seg2", "Seg2", "", "app.foo.com")
	idx.OverlappingDomains["app.foo.com"] = []string{"seg1", "seg2"}

	registerPolicy(idx, policy("pA", "A", "ALLOW", "1",
		cond("AND", op("APP", "seg1"), op("SCIM_GROUP", "100"))))
	registerPolicy(idx, policy("pB", "B", "ALLOW", "2",
		cond("AND", op("APP", "seg2"), op("SCIM_GROUP", "200"))))

	details := DomainOverlapDetails(idx)
	if details[0].HasConflict {
		t.Errorf("want HasConflict=false")
	}
}

// TestConnectorLoad_Counts verifies that when a policy targets a segment
// group containing two segments, the connector group serving that policy
// reports SegmentCount=2 (via APP_GROUP expansion), SegmentGroupCount=1,
// ScimGroupCount=1, and PolicyCount=1. Guards the fan-out arithmetic.
func TestConnectorLoad_Counts(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "grp1")
	idx.Segments["seg2"] = seg("seg2", "Seg2", "grp1")
	idx.SegmentGroups["grp1"] = segGroup("grp1", "Grp1", "seg1", "seg2")
	idx.ConnectorGroupNames["cg1"] = "CG1"

	registerPolicy(idx, withConnectorGroup(policy("pol1", "P1", "ALLOW", "1",
		cond("AND", op("APP_GROUP", "grp1"), op("SCIM_GROUP", "100"))), "cg1", "CG1"))

	entries := ConnectorLoad(idx)
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.PolicyCount != 1 {
		t.Errorf("PolicyCount = %d", e.PolicyCount)
	}
	if e.SegmentCount != 2 {
		t.Errorf("SegmentCount = %d (want 2 via APP_GROUP expansion)", e.SegmentCount)
	}
	if e.SegmentGroupCount != 1 {
		t.Errorf("SegmentGroupCount = %d", e.SegmentGroupCount)
	}
	if e.ScimGroupCount != 1 {
		t.Errorf("ScimGroupCount = %d", e.ScimGroupCount)
	}
}

// TestScimReach_TransitiveReach verifies that a SCIM group referenced by a
// policy that targets a segment group reaches every segment in that group
// transitively (SCIM -> policy -> APP_GROUP -> segments). The group name
// is resolved from ScimGroups by parsing the numeric ID.
func TestScimReach_TransitiveReach(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "grp1")
	idx.Segments["seg2"] = seg("seg2", "Seg2", "grp1")
	idx.SegmentGroups["grp1"] = segGroup("grp1", "Grp1", "seg1", "seg2")
	idx.ScimGroups[100] = scim(100, "Admins")

	registerPolicy(idx, policy("pol1", "P1", "ALLOW", "1",
		cond("AND", op("APP_GROUP", "grp1"), op("SCIM_GROUP", "100"))))

	entries := ScimReach(idx)
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.ScimGroupID != "100" || e.ScimGroupName != "Admins" {
		t.Errorf("entry = %+v", e)
	}
	if e.SegmentCount != 2 {
		t.Errorf("SegmentCount = %d (want 2)", e.SegmentCount)
	}
	if e.PolicyCount != 1 {
		t.Errorf("PolicyCount = %d", e.PolicyCount)
	}
}

// TestScimReach_UnknownScimIDReturnsRawID verifies the fallback: when a
// SCIM group ID referenced by a policy is not present in idx.ScimGroups,
// the report uses the raw ID string as the name. Prevents blank labels
// in the UI for unresolved references.
func TestScimReach_UnknownScimIDReturnsRawID(t *testing.T) {
	idx := newIndex()
	idx.Segments["seg1"] = seg("seg1", "Seg1", "grp1")
	registerPolicy(idx, policy("pol1", "P1", "ALLOW", "1",
		cond("AND", op("APP", "seg1"), op("SCIM_GROUP", "999"))))

	entries := ScimReach(idx)
	if len(entries) != 1 || entries[0].ScimGroupName != "999" {
		t.Errorf("want raw id as name fallback, got %+v", entries)
	}
}
