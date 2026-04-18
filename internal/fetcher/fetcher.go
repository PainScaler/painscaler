package fetcher

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/painscaler/painscaler/internal/logging"
	"github.com/joho/godotenv"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/appconnectorcontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/appconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/appservercontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/bacertificate"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/clienttypes"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/idpcontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/platforms"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontrollerv2"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/postureprofile"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/scimattributeheader"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/scimgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/segmentgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/servergroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/trustednetwork"
)

type StatusEventData struct {
	Message string
}

// Snapshot holds the raw API responses -- flat lists, no cross-references yet.
type Snapshot struct {
	ClientTypes          []string
	Segments             []applicationsegment.ApplicationSegmentResource
	SegmentGroups        []segmentgroup.SegmentGroup
	AppConnectors        []appconnectorcontroller.AppConnector
	AppConnectorGroups   []appconnectorgroup.AppConnectorGroup
	AccessPolicies       []policysetcontrollerv2.PolicyRuleResource
	ScimGroups           []scimgroup.ScimGroup
	ServerGroups         []servergroup.ServerGroup
	ApplicationServers   []appservercontroller.ApplicationServer
	TrustedNetworks      []trustednetwork.TrustedNetwork
	PostureProfiles      []postureprofile.PostureProfile
	Platforms            []string
	IdpControllers       []idpcontroller.IdpController
	ScimAttributeHeaders []scimattributeheader.ScimAttributeHeader
	Certificates         []bacertificate.BaCertificate
}

// FetchError collects non-fatal load failures so the caller can decide
// whether to abort or continue with partial data.
type FetchError struct {
	Resource string
	Err      error
}

func (e FetchError) Error() string {
	return fmt.Sprintf("fetch %s: %v", e.Resource, e.Err)
}

var (
	apiClient     *zscaler.Service
	apiClientErr  error
	apiClientOnce sync.Once
)

var (
	cachedSnapshot     *CachedSnapshot
	cachedSnapshotOnce sync.Once
)

func GetCache() *CachedSnapshot {
	cachedSnapshotOnce.Do(func() {
		short, long := 5*time.Minute, time.Hour
		// In demo mode the cache is seeded from disk and never refreshed from
		// ZPA, so TTL must never expire or the CachedFetch fallback would fire
		// (and fail for lack of a client).
		if DemoSeedPath() != "" {
			short, long = 100*365*24*time.Hour, 100*365*24*time.Hour
		}
		cachedSnapshot = &CachedSnapshot{
			ClientTypes:          Cache[[]string]{ttl: long},
			Segments:             Cache[[]applicationsegment.ApplicationSegmentResource]{ttl: short},
			SegmentGroups:        Cache[[]segmentgroup.SegmentGroup]{ttl: short},
			AppConnectors:        Cache[[]appconnectorcontroller.AppConnector]{ttl: short},
			AppConnectorGroups:   Cache[[]appconnectorgroup.AppConnectorGroup]{ttl: short},
			AccessPolicies:       Cache[[]policysetcontrollerv2.PolicyRuleResource]{ttl: short},
			ScimGroups:           Cache[[]scimgroup.ScimGroup]{ttl: short},
			ServerGroups:         Cache[[]servergroup.ServerGroup]{ttl: short},
			ApplicationServers:   Cache[[]appservercontroller.ApplicationServer]{ttl: short},
			TrustedNetworks:      Cache[[]trustednetwork.TrustedNetwork]{ttl: short},
			PostureProfiles:      Cache[[]postureprofile.PostureProfile]{ttl: short},
			Platforms:            Cache[[]string]{ttl: long},
			IdpControllers:       Cache[[]idpcontroller.IdpController]{ttl: long},
			ScimAttributeHeaders: Cache[[]scimattributeheader.ScimAttributeHeader]{ttl: long},
			ScimAttributeValues:  map[string]*Cache[[]string]{},
			Certificates:         Cache[[]bacertificate.BaCertificate]{ttl: long},
		}
	})
	return cachedSnapshot
}

// GetClient returns the shared ZPA client, creating it on the first call.
func GetClient() (*zscaler.Service, error) {
	apiClientOnce.Do(func() {
		if err := godotenv.Load(); err != nil {
			slog.Debug("godotenv.Load skipped", slog.String("error", err.Error()))
		}

		required := map[string]string{
			"ZPA_CLIENT_ID":     os.Getenv("ZPA_CLIENT_ID"),
			"ZPA_CLIENT_SECRET": os.Getenv("ZPA_CLIENT_SECRET"),
			"ZPA_CUSTOMER_ID":   os.Getenv("ZPA_CUSTOMER_ID"),
			"ZPA_VANITY":        os.Getenv("ZPA_VANITY"),
		}
		for k, v := range required {
			if v == "" {
				apiClientErr = fmt.Errorf("%s is not set", k)
				return
			}
		}

		config, err := zscaler.NewConfiguration(
			zscaler.WithClientID(os.Getenv("ZPA_CLIENT_ID")),
			zscaler.WithClientSecret(os.Getenv("ZPA_CLIENT_SECRET")),
			zscaler.WithZPACustomerID(os.Getenv("ZPA_CUSTOMER_ID")),
			zscaler.WithVanityDomain(os.Getenv("ZPA_VANITY")),
		)
		if err != nil {
			apiClientErr = err
			return
		}

		apiClient, apiClientErr = zscaler.NewOneAPIClient(config)
		if apiClientErr == nil {
			slog.Info("zpa authentication successful")
		}
	})
	return apiClient, apiClientErr
}

// Fetch loads all ZPA resources in parallel. It returns a Snapshot and a
// slice of non-fatal errors for resources that failed to load. A nil
// Snapshot means the client itself could not be created.
//
// In demo mode (PAINSCALER_DEMO_SEED set, cache pre-seeded by SeedDemoCache)
// every CachedFetch below returns the seeded data and GetClient is never
// invoked, so no ZPA credentials are required.
func Fetch(ctx context.Context) (*Snapshot, []FetchError) {
	// When a demo cache has been seeded, skip the upfront client check; each
	// CachedFetch lazily authenticates only when it actually needs to fetch.
	if DemoSeedPath() == "" {
		if _, err := GetClient(); err != nil {
			return nil, []FetchError{{Resource: "client", Err: err}}
		}
	}

	snap := &Snapshot{}
	var (
		errs   []FetchError
		errsMu sync.Mutex
		wg     sync.WaitGroup
	)

	addErr := func(name string, e error) {
		if e == nil {
			return
		}
		errsMu.Lock()
		errs = append(errs, FetchError{Resource: name, Err: e})
		errsMu.Unlock()
	}

	// Each CachedFetch targets a distinct Cache[T]; no lock contention between
	// them. Writes to distinct snap fields are also safe without a mutex.
	run := wg.Go

	run(func() {
		v, err := namedFetch(ctx, "client_types", &GetCache().ClientTypes, LoadClientTypes)
		addErr("client_types", err)
		snap.ClientTypes = v
	})
	run(func() {
		v, err := namedFetch(ctx, "platforms", &GetCache().Platforms, LoadPlatforms)
		addErr("platforms", err)
		snap.Platforms = v
	})
	run(func() {
		v, err := namedFetch(ctx, "segments", &GetCache().Segments, LoadSegments)
		addErr("segments", err)
		snap.Segments = v
	})
	run(func() {
		v, err := namedFetch(ctx, "segment_groups", &GetCache().SegmentGroups, LoadSegmentGroups)
		addErr("segment_groups", err)
		snap.SegmentGroups = v
	})
	run(func() {
		v, err := namedFetch(ctx, "app_connectors", &GetCache().AppConnectors, LoadAppConnectors)
		addErr("app_connectors", err)
		snap.AppConnectors = v
	})
	run(func() {
		v, err := namedFetch(ctx, "app_connector_groups", &GetCache().AppConnectorGroups, LoadAppConnectorGroups)
		addErr("app_connector_groups", err)
		snap.AppConnectorGroups = v
	})
	run(func() {
		v, err := namedFetch(ctx, "access_policies", &GetCache().AccessPolicies, LoadAccessPolicies)
		addErr("access_policies", err)
		snap.AccessPolicies = v
	})
	run(func() {
		v, err := namedFetch(ctx, "server_groups", &GetCache().ServerGroups, LoadServerGroups)
		addErr("server_groups", err)
		snap.ServerGroups = v
	})
	run(func() {
		v, err := namedFetch(ctx, "application_servers", &GetCache().ApplicationServers, LoadApplicationServers)
		addErr("application_servers", err)
		snap.ApplicationServers = v
	})
	run(func() {
		v, err := namedFetch(ctx, "idp_controllers", &GetCache().IdpControllers, LoadIdpControllers)
		addErr("idp_controllers", err)
		snap.IdpControllers = v
	})
	run(func() {
		v, err := namedFetch(ctx, "trusted_networks", &GetCache().TrustedNetworks, LoadTrustedNetworks)
		addErr("trusted_networks", err)
		snap.TrustedNetworks = v
	})
	run(func() {
		v, err := namedFetch(ctx, "posture_profiles", &GetCache().PostureProfiles, LoadPostureProfiles)
		addErr("posture_profiles", err)
		snap.PostureProfiles = v
	})
	run(func() {
		v, err := namedFetch(ctx, "certificates", &GetCache().Certificates, LoadCertificates)
		addErr("certificates", err)
		snap.Certificates = v
	})
	run(func() {
		v, err := namedFetch(ctx, "scim_groups", &GetCache().ScimGroups, LoadScimGroups)
		addErr("scim_groups", err)
		snap.ScimGroups = v
	})
	run(func() {
		v, err := namedFetch(ctx, "scim_attribute_headers", &GetCache().ScimAttributeHeaders, LoadScimAttributeHeaders)
		addErr("scim_attribute_headers", err)
		snap.ScimAttributeHeaders = v
	})

	wg.Wait()
	return snap, errs
}

// CachedFetch retrieves a resource via c, calling fn only when the cache is
// stale. GetClient is deferred into the fetch path so demo mode (with a
// pre-seeded cache and no ZPA credentials) never attempts authentication.
func CachedFetch[T any](ctx context.Context, c *Cache[T], fn func(context.Context, *zscaler.Service) (T, error)) (T, error) {
	return c.Get(func() (T, error) {
		client, err := GetClient()
		if err != nil {
			var zero T
			return zero, err
		}
		return fn(ctx, client)
	})
}

// namedFetch wraps CachedFetch with per-resource prom instrumentation. Used
// by Fetch's fan-out so each upstream call records its duration and error
// count even if the underlying request was served from cache; timing a cache
// hit is near-zero and still useful for distinguishing hit vs miss by bucket.
func namedFetch[T any](ctx context.Context, resource string, c *Cache[T], fn func(context.Context, *zscaler.Service) (T, error)) (T, error) {
	start := time.Now()
	v, err := CachedFetch(ctx, c, fn)
	logging.FetchResourceDurationSeconds.WithLabelValues(resource).Observe(time.Since(start).Seconds())
	if err != nil {
		logging.FetchResourceErrorsTotal.WithLabelValues(resource).Inc()
	}
	return v, err
}

func LoadClientTypes(ctx context.Context, client *zscaler.Service) ([]string, error) {
	ct, resp, err := clienttypes.GetAllClientTypes(ctx, client)
	if err != nil || !ok(resp) {
		return nil, coalesce(err, resp)
	}
	return clientTypeSlice(*ct), nil
}

func LoadPlatforms(ctx context.Context, client *zscaler.Service) ([]string, error) {
	plat, resp, err := platforms.GetAllPlatforms(ctx, client)
	if err != nil || !ok(resp) {
		return nil, coalesce(err, resp)
	}
	return []string{plat.Linux, plat.Android, plat.Windows, plat.MacOS}, nil
}

func LoadSegments(ctx context.Context, client *zscaler.Service) ([]applicationsegment.ApplicationSegmentResource, error) {
	segs, resp, err := applicationsegment.GetAll(ctx, client)
	if err != nil || !ok(resp) {
		return nil, coalesce(err, resp)
	}
	return segs, nil
}

func LoadSegmentGroups(ctx context.Context, client *zscaler.Service) ([]segmentgroup.SegmentGroup, error) {
	grps, resp, err := segmentgroup.GetAll(ctx, client)
	if err != nil || !ok(resp) {
		return nil, coalesce(err, resp)
	}
	return grps, nil
}

func LoadAppConnectors(ctx context.Context, client *zscaler.Service) ([]appconnectorcontroller.AppConnector, error) {
	ac, resp, err := appconnectorcontroller.GetAll(ctx, client)
	if err != nil || !ok(resp) {
		return nil, coalesce(err, resp)
	}
	return ac, nil
}

func LoadAppConnectorGroups(ctx context.Context, client *zscaler.Service) ([]appconnectorgroup.AppConnectorGroup, error) {
	acg, resp, err := appconnectorgroup.GetAll(ctx, client)
	if err != nil || !ok(resp) {
		return nil, coalesce(err, resp)
	}
	return acg, nil
}

func LoadAccessPolicies(ctx context.Context, client *zscaler.Service) ([]policysetcontrollerv2.PolicyRuleResource, error) {
	pols, resp, err := policysetcontrollerv2.GetAllByType(ctx, client, "ACCESS_POLICY")
	if err != nil || !ok(resp) {
		return nil, coalesce(err, resp)
	}
	return pols, nil
}

func LoadScimGroups(ctx context.Context, client *zscaler.Service) ([]scimgroup.ScimGroup, error) {
	var groups []scimgroup.ScimGroup
	for _, id := range splitTrim(os.Getenv("ZPA_IDP"), ",") {
		grps, resp, err := scimgroup.GetAllByIdpId(ctx, client, id)
		if err != nil || !ok(resp) {
			return nil, err
		}
		groups = append(groups, grps...)
	}
	return groups, nil
}

func LoadScimAttributeHeaders(ctx context.Context, client *zscaler.Service) ([]scimattributeheader.ScimAttributeHeader, error) {
	var headers []scimattributeheader.ScimAttributeHeader
	for _, id := range splitTrim(os.Getenv("ZPA_IDP"), ",") {
		sah, resp, err := scimattributeheader.GetAllByIdpId(ctx, client, id)
		if err != nil || !ok(resp) {
			return nil, coalesce(err, resp)
		}
		headers = append(headers, sah...)
	}
	return headers, nil
}

func LoadScimAttributeValues(ctx context.Context, client *zscaler.Service, idpID, headerID string) ([]string, error) {
	return scimattributeheader.GetValues(ctx, client, idpID, headerID)
}

func LoadApplicationServers(ctx context.Context, client *zscaler.Service) ([]appservercontroller.ApplicationServer, error) {
	srvs, resp, err := appservercontroller.GetAll(ctx, client)
	if err != nil || !ok(resp) {
		return nil, coalesce(err, resp)
	}
	return srvs, nil
}

func LoadServerGroups(ctx context.Context, client *zscaler.Service) ([]servergroup.ServerGroup, error) {
	sgs, resp, err := servergroup.GetAll(ctx, client)
	if err != nil || !ok(resp) {
		return nil, coalesce(err, resp)
	}
	return sgs, nil
}

func LoadIdpControllers(ctx context.Context, client *zscaler.Service) ([]idpcontroller.IdpController, error) {
	idpcs, resp, err := idpcontroller.GetAll(ctx, client)
	if err != nil || !ok(resp) {
		return nil, coalesce(err, resp)
	}
	return idpcs, nil
}

func LoadTrustedNetworks(ctx context.Context, client *zscaler.Service) ([]trustednetwork.TrustedNetwork, error) {
	tns, resp, err := trustednetwork.GetAll(ctx, client)
	if err != nil || !ok(resp) {
		return nil, coalesce(err, resp)
	}
	return tns, nil
}

func LoadPostureProfiles(ctx context.Context, client *zscaler.Service) ([]postureprofile.PostureProfile, error) {
	pps, resp, err := postureprofile.GetAll(ctx, client)
	if err != nil || !ok(resp) {
		return nil, coalesce(err, resp)
	}
	return pps, nil
}

func LoadCertificates(ctx context.Context, client *zscaler.Service) ([]bacertificate.BaCertificate, error) {
	crts, resp, err := bacertificate.GetAll(ctx, client)
	if err != nil || !ok(resp) {
		return nil, coalesce(err, resp)
	}
	return crts, nil
}

// --- helpers ---

func ok(r *http.Response) bool {
	return r != nil && r.StatusCode == http.StatusOK
}

func coalesce(err error, r *http.Response) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("HTTP %d", r.StatusCode)
}

func clientTypeSlice(ct clienttypes.ClientTypes) []string {
	return []string{
		ct.ZPNClientTypeExplorer,
		ct.ZPNClientTypeNoAuth,
		ct.ZPNClientTypeBrowserIsolation,
		ct.ZPNClientTypeMachineTunnel,
		ct.ZPNClientTypeIPAnchoring,
		ct.ZPNClientTypeEdgeConnector,
		ct.ZPNClientTypeZAPP,
		ct.ZPNClientTypeSlogger,
		ct.ZPNClientTypeBranchConnector,
		ct.ZPNClientTypePartner,
		ct.ZPNClientTypeVDI,
		ct.ZPNClientTypeZIAInspection,
	}
}

func splitTrim(s, sep string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for p := range strings.SplitSeq(s, sep) {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
