// seedgen emits a synthetic fetcher.Snapshot as JSON. The output drives the
// public demo deployment via PAINSCALER_DEMO_SEED, so it must stay shape-
// compatible with the live ZPA fetch path while containing no real tenant
// data. Output is deterministic for a given -seed value.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/painscaler/painscaler/internal/fetcher"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/appconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/idpcontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontrollerv2"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/postureprofile"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/scimattributeheader"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/scimgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/segmentgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/servergroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/trustednetwork"
)

func main() {
	out := flag.String("out", "", "output file (default stdout)")
	flag.Parse()

	snap := build()
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}
	if *out == "" {
		if _, err := os.Stdout.Write(b); err != nil {
			log.Fatalf("write stdout: %v", err)
		}
		return
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		log.Fatalf("write %s: %v", *out, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", *out, len(b))
}

// IDs are stable strings so references line up without bookkeeping.
const (
	idpPrimary   = "idp-okta"
	idpSecondary = "idp-azure"

	cgUSEast = "cg-us-east"
	cgEUWest = "cg-eu-west"
	cgAPAC   = "cg-apac"

	sgProd       = "sg-prod"
	sgStaging    = "sg-staging"
	sgInternal   = "sg-internal"
	sgFinance    = "sg-finance"
	sgLegacy     = "sg-legacy"
	sgUnassigned = "sg-unassigned"

	postureMDM     = "posture-mdm"
	postureAV      = "posture-av"
	postureDiskEnc = "posture-disk-enc"

	tnHQ = "tn-hq"
	tnEU = "tn-eu"
)

// SCIM group IDs are int64 per SDK; keep them contiguous for readability.
const (
	scimEng     int64 = 100001
	scimFinance int64 = 100002
	scimOps     int64 = 100003
	scimExecs   int64 = 100004
)

func build() fetcher.Snapshot {
	segments := buildSegments()
	return fetcher.Snapshot{
		ClientTypes:          buildClientTypes(),
		Platforms:            []string{"Linux", "Android", "Windows", "MacOS"},
		Segments:             segments,
		SegmentGroups:        buildSegmentGroups(segments),
		AppConnectorGroups:   buildConnectorGroups(),
		AppConnectors:        nil,
		ServerGroups:         buildServerGroups(),
		ApplicationServers:   nil,
		AccessPolicies:       buildPolicies(),
		ScimGroups:           buildScimGroups(),
		ScimAttributeHeaders: buildScimAttributeHeaders(),
		IdpControllers:       buildIdpControllers(),
		TrustedNetworks:      buildTrustedNetworks(),
		PostureProfiles:      buildPostureProfiles(),
		Certificates:         nil,
	}
}

func buildClientTypes() []string {
	return []string{
		"zpn_client_type_exporter",
		"zpn_client_type_machine_tunnel",
		"zpn_client_type_zapp",
		"zpn_client_type_edge_connector",
		"zpn_client_type_branch_connector",
	}
}

// segmentDef is the compact form of one app segment; expanded into the SDK
// struct by buildSegments. Keeping the table separate makes the topology
// easy to audit at a glance.
type segmentDef struct {
	id       string
	name     string
	domain   string
	group    string
	enabled  bool
	tcpPort  string
	showcase string // "orphan", "overlap-a", "overlap-b", or ""
}

var segmentDefs = []segmentDef{
	// Production
	{"seg-jira", "Jira", "jira.acme.internal", sgProd, true, "443", ""},
	{"seg-confluence", "Confluence", "confluence.acme.internal", sgProd, true, "443", ""},
	{"seg-grafana", "Grafana", "grafana.acme.internal", sgProd, true, "443", ""},
	{"seg-sonarqube", "SonarQube", "sonarqube.acme.internal", sgProd, true, "443", ""},
	{"seg-gitea", "Gitea", "git.acme.internal", sgProd, true, "443", ""},
	{"seg-argo", "ArgoCD", "argo.acme.internal", sgProd, true, "443", ""},
	{"seg-vault", "HashiCorp Vault", "vault.acme.internal", sgProd, true, "8200", ""},
	{"seg-rabbit", "RabbitMQ", "rabbit.acme.internal", sgProd, true, "15672", ""},

	// Staging (showcase: same domain also covered in prod to surface overlap)
	{"seg-jira-stg", "Jira (staging)", "jira-staging.acme.internal", sgStaging, true, "443", ""},
	{"seg-grafana-stg", "Grafana (staging)", "grafana-staging.acme.internal", sgStaging, true, "443", ""},
	{"seg-gitea-stg", "Gitea (staging)", "git-staging.acme.internal", sgStaging, true, "443", ""},

	// Internal Tools
	{"seg-wiki", "Wiki", "wiki.acme.internal", sgInternal, true, "443", ""},
	{"seg-nextcloud", "Nextcloud", "files.acme.internal", sgInternal, true, "443", ""},
	{"seg-mattermost", "Mattermost", "chat.acme.internal", sgInternal, true, "443", ""},
	{"seg-bookstack", "BookStack", "books.acme.internal", sgInternal, true, "443", ""},

	// Finance
	{"seg-erp", "ERP", "erp.acme.internal", sgFinance, true, "443", ""},
	{"seg-netsuite", "NetSuite Proxy", "ns.acme.internal", sgFinance, true, "443", ""},
	{"seg-billing", "Billing", "billing.acme.internal", sgFinance, true, "443", ""},

	// Legacy (disabled, to showcase hygiene)
	{"seg-svn", "SVN", "svn.acme.internal", sgLegacy, false, "3690", ""},
	{"seg-jenkins-old", "Legacy Jenkins", "jenkins-old.acme.internal", sgLegacy, false, "8080", ""},
	{"seg-wiki-old", "Legacy Wiki", "wiki-old.acme.internal", sgLegacy, false, "443", ""},

	// Overlap showcase: two enabled segments share a domain.
	{"seg-grafana-dup", "Grafana (alt owner)", "grafana.acme.internal", sgInternal, true, "443", "overlap-b"},

	// Orphans: enabled, belong to a real segment group, but referenced by no policy.
	{"seg-orphan-kibana", "Kibana (orphan)", "kibana.acme.internal", sgUnassigned, true, "443", "orphan"},
	{"seg-orphan-prom", "Prometheus (orphan)", "prom.acme.internal", sgUnassigned, true, "9090", "orphan"},
}

func buildSegments() []applicationsegment.ApplicationSegmentResource {
	out := make([]applicationsegment.ApplicationSegmentResource, 0, len(segmentDefs))
	for _, d := range segmentDefs {
		out = append(out, applicationsegment.ApplicationSegmentResource{
			ID:              d.id,
			Name:            d.name,
			DomainNames:     []string{d.domain},
			Enabled:         d.enabled,
			SegmentGroupID:  d.group,
			TCPPortRanges:   []string{d.tcpPort, d.tcpPort},
			BypassType:      "NEVER",
			HealthReporting: "ON_ACCESS",
		})
	}
	return out
}

func buildSegmentGroups(segs []applicationsegment.ApplicationSegmentResource) []segmentgroup.SegmentGroup {
	groups := []struct {
		id      string
		name    string
		enabled bool
	}{
		{sgProd, "Production", true},
		{sgStaging, "Staging", true},
		{sgInternal, "Internal Tools", true},
		{sgFinance, "Finance", true},
		{sgLegacy, "Legacy (retiring)", false},
		{sgUnassigned, "Unassigned", true},
	}

	bySegmentGroup := make(map[string][]segmentgroup.Application)
	for _, s := range segs {
		if s.SegmentGroupID == "" {
			continue
		}
		bySegmentGroup[s.SegmentGroupID] = append(bySegmentGroup[s.SegmentGroupID], segmentgroup.Application{
			ID:          s.ID,
			Name:        s.Name,
			Enabled:     s.Enabled,
			DomainNames: s.DomainNames,
		})
	}

	out := make([]segmentgroup.SegmentGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, segmentgroup.SegmentGroup{
			ID:           g.id,
			Name:         g.name,
			Enabled:      g.enabled,
			Applications: bySegmentGroup[g.id],
		})
	}
	return out
}

func buildConnectorGroups() []appconnectorgroup.AppConnectorGroup {
	return []appconnectorgroup.AppConnectorGroup{
		{ID: cgUSEast, Name: "Connector Group - US East", Enabled: true, CityCountry: "Ashburn, US", CountryCode: "US", Location: "Ashburn, VA"},
		{ID: cgEUWest, Name: "Connector Group - EU West", Enabled: true, CityCountry: "Dublin, IE", CountryCode: "IE", Location: "Dublin"},
		{ID: cgAPAC, Name: "Connector Group - APAC", Enabled: true, CityCountry: "Singapore, SG", CountryCode: "SG", Location: "Singapore"},
	}
}

func buildServerGroups() []servergroup.ServerGroup {
	return []servergroup.ServerGroup{
		{
			ID: "sgrp-prod-us", Name: "Prod Servers - US", Enabled: true, DynamicDiscovery: true,
			AppConnectorGroups: []appconnectorgroup.AppConnectorGroup{{ID: cgUSEast, Name: "Connector Group - US East"}},
		},
		{
			ID: "sgrp-prod-eu", Name: "Prod Servers - EU", Enabled: true, DynamicDiscovery: true,
			AppConnectorGroups: []appconnectorgroup.AppConnectorGroup{{ID: cgEUWest, Name: "Connector Group - EU West"}},
		},
		{
			ID: "sgrp-finance", Name: "Finance Servers", Enabled: true, DynamicDiscovery: true,
			AppConnectorGroups: []appconnectorgroup.AppConnectorGroup{{ID: cgUSEast, Name: "Connector Group - US East"}},
		},
		{
			ID: "sgrp-internal", Name: "Internal Tools", Enabled: true, DynamicDiscovery: true,
			AppConnectorGroups: []appconnectorgroup.AppConnectorGroup{{ID: cgEUWest, Name: "Connector Group - EU West"}, {ID: cgAPAC, Name: "Connector Group - APAC"}},
		},
		{
			ID: "sgrp-legacy", Name: "Legacy Servers", Enabled: false, DynamicDiscovery: false,
			AppConnectorGroups: []appconnectorgroup.AppConnectorGroup{{ID: cgUSEast, Name: "Connector Group - US East"}},
		},
	}
}

func buildScimGroups() []scimgroup.ScimGroup {
	return []scimgroup.ScimGroup{
		{ID: scimEng, Name: "Engineering", IdpID: 1, IdpName: "Okta Primary"},
		{ID: scimFinance, Name: "Finance", IdpID: 1, IdpName: "Okta Primary"},
		{ID: scimOps, Name: "Operations", IdpID: 1, IdpName: "Okta Primary"},
		{ID: scimExecs, Name: "Executives", IdpID: 1, IdpName: "Okta Primary"},
	}
}

func buildScimAttributeHeaders() []scimattributeheader.ScimAttributeHeader {
	return []scimattributeheader.ScimAttributeHeader{
		{ID: "attr-dept", Name: "department", IdpID: idpPrimary, DataType: "string"},
		{ID: "attr-cost", Name: "costCenter", IdpID: idpPrimary, DataType: "string"},
		{ID: "attr-etype", Name: "employeeType", IdpID: idpPrimary, DataType: "string"},
	}
}

func buildIdpControllers() []idpcontroller.IdpController {
	return []idpcontroller.IdpController{
		{ID: idpPrimary, Name: "Okta Primary", Enabled: true, ScimEnabled: true, LoginURL: "https://acme.okta.com/sso/saml"},
		{ID: idpSecondary, Name: "Azure AD (break-glass)", Enabled: true, ScimEnabled: false, LoginURL: "https://login.microsoftonline.com/acme/saml2"},
	}
}

func buildTrustedNetworks() []trustednetwork.TrustedNetwork {
	return []trustednetwork.TrustedNetwork{
		{ID: tnHQ, Name: "Office HQ (San Francisco)", NetworkID: "net-hq-sf"},
		{ID: tnEU, Name: "Office EU (Dublin)", NetworkID: "net-eu-dub"},
	}
}

func buildPostureProfiles() []postureprofile.PostureProfile {
	return []postureprofile.PostureProfile{
		{ID: postureMDM, Name: "MDM enrolled", PostureType: "MDM"},
		{ID: postureAV, Name: "Antivirus running", PostureType: "ANTIVIRUS"},
		{ID: postureDiskEnc, Name: "Disk encryption enabled", PostureType: "DISK_ENCRYPTION"},
	}
}

// policyDef captures the rule shape without the SDK-struct boilerplate.
type policyDef struct {
	id            string
	name          string
	action        string
	order         int
	disabled      bool
	operands      []policysetcontrollerv2.PolicyRuleResourceOperands
	connectorGrps []string
}

func buildPolicies() []policysetcontrollerv2.PolicyRuleResource {
	defs := []policyDef{
		{
			id: "pol-eng-prod", name: "Engineers to Production", action: "ALLOW", order: 1,
			operands: []policysetcontrollerv2.PolicyRuleResourceOperands{
				{ObjectType: "APP_GROUP", RHS: sgProd},
				{ObjectType: "SCIM_GROUP", RHS: strconv.FormatInt(scimEng, 10), IDPID: idpPrimary},
				{ObjectType: "POSTURE", RHS: postureMDM, LHS: "true"},
			},
			connectorGrps: []string{cgUSEast, cgEUWest},
		},
		{
			id: "pol-finance", name: "Finance team to Finance apps", action: "ALLOW", order: 2,
			operands: []policysetcontrollerv2.PolicyRuleResourceOperands{
				{ObjectType: "APP_GROUP", RHS: sgFinance},
				{ObjectType: "SCIM_GROUP", RHS: strconv.FormatInt(scimFinance, 10), IDPID: idpPrimary},
			},
			connectorGrps: []string{cgUSEast},
		},
		{
			id: "pol-staging", name: "Staging - broad engineering access", action: "ALLOW", order: 3,
			operands: []policysetcontrollerv2.PolicyRuleResourceOperands{
				{ObjectType: "APP_GROUP", RHS: sgStaging},
				{ObjectType: "SCIM_GROUP", RHS: strconv.FormatInt(scimEng, 10), IDPID: idpPrimary},
			},
			connectorGrps: []string{cgUSEast},
		},
		{
			id: "pol-legacy-block", name: "Legacy apps - block all", action: "DENY", order: 4,
			operands: []policysetcontrollerv2.PolicyRuleResourceOperands{
				{ObjectType: "APP_GROUP", RHS: sgLegacy},
			},
		},
		{
			id: "pol-internal-office", name: "Internal Tools - office networks only", action: "ALLOW", order: 5,
			operands: []policysetcontrollerv2.PolicyRuleResourceOperands{
				{ObjectType: "APP_GROUP", RHS: sgInternal},
				{ObjectType: "TRUSTED_NETWORK", RHS: tnHQ, LHS: "true"},
			},
			connectorGrps: []string{cgEUWest, cgAPAC},
		},
		{
			id: "pol-exec-broad", name: "Executives - broad access", action: "ALLOW", order: 6,
			operands: []policysetcontrollerv2.PolicyRuleResourceOperands{
				{ObjectType: "APP_GROUP", RHS: sgProd},
				{ObjectType: "APP_GROUP", RHS: sgFinance},
				{ObjectType: "SCIM_GROUP", RHS: strconv.FormatInt(scimExecs, 10), IDPID: idpPrimary},
			},
			connectorGrps: []string{cgUSEast, cgEUWest, cgAPAC},
		},
		{
			id: "pol-platform-gate", name: "Managed endpoints only (Win/Mac)", action: "ALLOW", order: 7,
			operands: []policysetcontrollerv2.PolicyRuleResourceOperands{
				{ObjectType: "APP", RHS: "seg-vault"},
				{ObjectType: "PLATFORM", RHS: "Windows", LHS: "true"},
				{ObjectType: "PLATFORM", RHS: "MacOS", LHS: "true"},
				{ObjectType: "POSTURE", RHS: postureDiskEnc, LHS: "true"},
			},
			connectorGrps: []string{cgUSEast},
		},
		{
			id: "pol-draft", name: "Draft - Ops access (disabled)", action: "ALLOW", order: 8, disabled: true,
			operands: []policysetcontrollerv2.PolicyRuleResourceOperands{
				{ObjectType: "APP_GROUP", RHS: sgInternal},
				{ObjectType: "SCIM_GROUP", RHS: strconv.FormatInt(scimOps, 10), IDPID: idpPrimary},
			},
		},
	}

	out := make([]policysetcontrollerv2.PolicyRuleResource, 0, len(defs))
	for _, d := range defs {
		disabled := "FALSE"
		if d.disabled {
			disabled = "TRUE"
		}
		cgs := make([]appconnectorgroup.AppConnectorGroup, 0, len(d.connectorGrps))
		for _, id := range d.connectorGrps {
			cgs = append(cgs, appconnectorgroup.AppConnectorGroup{ID: id, Name: connectorGroupName(id)})
		}
		out = append(out, policysetcontrollerv2.PolicyRuleResource{
			ID:                 d.id,
			Name:               d.name,
			Action:             d.action,
			RuleOrder:          strconv.Itoa(d.order),
			Priority:           strconv.Itoa(d.order),
			Disabled:           disabled,
			Operator:           "AND",
			PolicyType:         "1",
			Conditions:         []policysetcontrollerv2.PolicyRuleResourceConditions{{Operator: "OR", Operands: d.operands}},
			AppConnectorGroups: cgs,
		})
	}
	return out
}

func connectorGroupName(id string) string {
	switch id {
	case cgUSEast:
		return "Connector Group - US East"
	case cgEUWest:
		return "Connector Group - EU West"
	case cgAPAC:
		return "Connector Group - APAC"
	}
	return id
}
