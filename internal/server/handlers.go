package server

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/painscaler/painscaler/internal/analysis"
	"github.com/painscaler/painscaler/internal/fetcher"
	"github.com/painscaler/painscaler/internal/index"
	"github.com/painscaler/painscaler/internal/logging"
	"github.com/painscaler/painscaler/internal/simulator"
	"github.com/painscaler/painscaler/internal/storage"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/appconnectorcontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/appconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/bacertificate"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/idpcontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontrollerv2"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/postureprofile"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/scimattributeheader"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/scimgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/segmentgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/servergroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/trustednetwork"
	"golang.org/x/sync/singleflight"
)

type Server struct {
	about    About
	mu       sync.RWMutex
	ctx      context.Context
	store    *storage.Store
	idxCache indexCache

	refreshThrottle refreshThrottle

	// buildIndexFn is the function used to rebuild the index. Overridden
	// in tests to count builds or inject fixtures; production path is nil
	// and falls back to index.BuildIndex.
	buildIndexFn func(context.Context) (*index.Index, error)
}

// refreshThrottle gates /api/v1/refresh to at most one invocation per
// refreshMinInterval, globally across all callers. The upstream fetch is a
// single shared cache so per-user fairness buys nothing.
type refreshThrottle struct {
	mu          sync.Mutex
	lastAllowed time.Time
}

const refreshMinInterval = 30 * time.Second

// allow records an attempt and returns true if refreshMinInterval has
// elapsed since the previous allowed attempt.
func (r *refreshThrottle) allow(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.lastAllowed.IsZero() && now.Sub(r.lastAllowed) < refreshMinInterval {
		return false
	}
	r.lastAllowed = now
	return true
}

// indexCache memoizes *index.Index across handlers. TTL is deliberately
// short: it only coalesces burst loads (a dashboard fetching N widgets in
// parallel), not long-term caching. Refresh() invalidates synchronously.
type indexCache struct {
	mu      sync.Mutex
	idx     *index.Index
	builtAt time.Time
	sf      singleflight.Group
}

// indexTTL is how long a built index is considered fresh. The background
// warmer rebuilds before it expires, so in steady state handlers always hit
// a warm cache. Set generously relative to warmerInterval.
const indexTTL = 5 * time.Minute

// warmerInterval is how often the background warmer forces a rebuild. Must
// be shorter than indexTTL so handlers never race an expiring cache.
const warmerInterval = 4 * time.Minute

type About struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	Demo    bool   `json:"demo"`
}

type Identity struct {
	User   string `json:"user"`
	Email  string `json:"email"`
	Groups string `json:"groups"`
	Name   string `json:"name"`
}

func New(about About) (*Server, error) {
	s := &Server{about: about, ctx: context.Background()}

	dbPath, err := resolveDBPath()
	if err != nil {
		slog.Warn("could not resolve db path", slog.String("error", err.Error()))
	} else if store, err := storage.Open(dbPath); err != nil {
		slog.Warn("could not open db", slog.String("path", dbPath), slog.String("error", err.Error()))
	} else {
		s.store = store
	}

	return s, nil
}

func (s *Server) Close() {
	if s.store != nil {
		s.store.Close()
	}
}

func resolveDBPath() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cfgDir, "painscaler")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "runs.db"), nil
}

// logFetchErrs surfaces non-fatal partial-fetch failures without failing the
// request. Fatal failures (nil snapshot) are returned to the caller directly.
func logFetchErrs(route string, errs []fetcher.FetchError) {
	for _, e := range errs {
		slog.Warn("partial fetch",
			slog.String("route", route),
			slog.String("resource", e.Resource),
			slog.String("error", e.Err.Error()))
	}
}

// firstFetchErr returns the first fetch error or ErrUnavailable when the slice
// is empty. Keeps call sites safe from panicking on errs[0] when an upstream
// returns a nil snapshot without populating the error list.
func firstFetchErr(errs []fetcher.FetchError) error {
	if len(errs) == 0 {
		return ErrUnavailable
	}
	return errs[0]
}

// readyCheck reports whether the server has a warm index (and, if a DB was
// configured, that the connection is alive). Used by /readyz.
func (s *Server) readyCheck() error {
	s.idxCache.mu.Lock()
	idx := s.idxCache.idx
	s.idxCache.mu.Unlock()
	if idx == nil {
		return errors.New("index not built")
	}
	if s.store != nil {
		if err := s.store.Ping(s.ctx); err != nil {
			return err
		}
	}
	return nil
}

// getIndex returns a cached *index.Index rebuilt at most once per indexTTL.
// Concurrent callers share a single rebuild via singleflight, so a burst of
// handler requests triggers one BuildIndex rather than N. The cache check
// runs inside the singleflight callback so a late-arriving group sees a
// freshly populated cache and skips the rebuild entirely.
func (s *Server) getIndex() (*index.Index, error) {
	v, err, _ := s.idxCache.sf.Do("idx", func() (any, error) {
		s.idxCache.mu.Lock()
		if s.idxCache.idx != nil && time.Since(s.idxCache.builtAt) < indexTTL {
			idx := s.idxCache.idx
			s.idxCache.mu.Unlock()
			return idx, nil
		}
		s.idxCache.mu.Unlock()
		return s.rebuildIndex(s.ctx)
	})
	if err != nil {
		return nil, err
	}
	return v.(*index.Index), nil
}

// rebuildIndex unconditionally builds the index and stores it in the cache.
// Callers should go through singleflight so concurrent rebuilds coalesce.
func (s *Server) rebuildIndex(ctx context.Context) (*index.Index, error) {
	build := s.buildIndexFn
	if build == nil {
		build = index.BuildIndex
	}
	idx, err := build(ctx)
	if err != nil {
		return nil, err
	}
	s.idxCache.mu.Lock()
	s.idxCache.idx = idx
	s.idxCache.builtAt = time.Now()
	s.idxCache.mu.Unlock()
	slog.Debug("index rebuilt")
	return idx, nil
}

// StartIndexWarmer builds the index once immediately, then rebuilds it every
// warmerInterval in the background. With warmerInterval < indexTTL the cache
// never expires under normal operation, so handlers never wait on a cold
// BuildIndex. Returns when ctx is cancelled.
func (s *Server) StartIndexWarmer(ctx context.Context) {
	go func() {
		if _, err, _ := s.idxCache.sf.Do("idx", func() (any, error) {
			return s.rebuildIndex(ctx)
		}); err != nil {
			slog.Warn("initial index warm failed", slog.String("error", err.Error()))
		}
		t := time.NewTicker(warmerInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err, _ := s.idxCache.sf.Do("idx", func() (any, error) {
					return s.rebuildIndex(ctx)
				}); err != nil {
					slog.Warn("index warmer rebuild failed", slog.String("error", err.Error()))
				}
			}
		}
	}()
}

func (s *Server) invalidateIndex() {
	s.idxCache.mu.Lock()
	s.idxCache.idx = nil
	s.idxCache.builtAt = time.Time{}
	s.idxCache.mu.Unlock()
}

//api:route POST /api/v1/refresh
//api:header Remote-User={user}
func (s *Server) Refresh(user string) error {
	if user == "" {
		return ErrUnauthenticated
	}
	if !s.refreshThrottle.allow(time.Now()) {
		return ErrRateLimited
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fetcher.GetCache().InvalidateAll()
	s.invalidateIndex()
	if _, errs := fetcher.Fetch(s.ctx); len(errs) > 0 {
		return errs[0]
	}
	return nil
}

//api:route GET /api/v1/index
func (s *Server) GetIndex() (index.Index, error) {
	idx, err := s.getIndex()
	if err != nil {
		return index.Index{}, err
	}
	return *idx, nil
}

//api:route GET /api/v1/search
//api:query q={term}
func (s *Server) Search(term string) ([]index.SearchResult, error) {
	s.mu.RLock()
	snap, fetchErrs := fetcher.Fetch(s.ctx)
	idx, idxErr := s.getIndex()
	s.mu.RUnlock()
	if snap == nil {
		return []index.SearchResult{}, firstFetchErr(fetchErrs)
	}
	if idxErr != nil {
		return []index.SearchResult{}, idxErr
	}
	logFetchErrs("search", fetchErrs)
	return index.Search(idx, snap, term), nil
}

//api:route GET /api/v1/segment/{segmentID}/policies
func (s *Server) PoliciesForSegment(segmentID string) ([]index.PolicyCoverage, error) {
	s.mu.RLock()
	idx, err := s.getIndex()
	s.mu.RUnlock()
	if err != nil {
		return []index.PolicyCoverage{}, err
	}
	return index.PoliciesForSegment(idx, segmentID), nil
}

//api:route GET /api/v1/reachability
//api:query q={hostname}
func (s *Server) WhoCanReach(hostname string) (index.ReachabilityResult, error) {
	s.mu.RLock()
	idx, err := s.getIndex()
	s.mu.RUnlock()
	if err != nil {
		return index.ReachabilityResult{}, err
	}
	return index.WhoCanReach(idx, hostname), nil
}

//api:route GET /api/v1/reports/orphans
func (s *Server) GetOrphans() ([]index.OrphanReport, error) {
	s.mu.RLock()
	snap, fetchErrs := fetcher.Fetch(s.ctx)
	idx, idxErr := s.getIndex()
	s.mu.RUnlock()
	if snap == nil {
		return []index.OrphanReport{}, firstFetchErr(fetchErrs)
	}
	if idxErr != nil {
		return []index.OrphanReport{}, idxErr
	}
	logFetchErrs("orphans", fetchErrs)
	return index.Orphans(idx, snap), nil
}

//api:route GET /api/v1/reports/overlaps
func (s *Server) GetOverlaps() ([]index.OverlapReport, error) {
	s.mu.RLock()
	idx, err := s.getIndex()
	s.mu.RUnlock()
	if err != nil {
		return []index.OverlapReport{}, err
	}
	return index.Overlaps(idx), nil
}

//api:route GET /api/v1/about
func (s *Server) GetAbout() About {
	return s.about
}

type Library struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Libraries struct {
	Go      string    `json:"go"`
	Backend []Library `json:"backend"`
}

// backendDirectDeps maps module paths to display names for libraries
// listed as direct dependencies in go.mod.
var backendDirectDeps = map[string]string{
	"github.com/gin-gonic/gin":             "Gin",
	"github.com/google/uuid":               "google/uuid",
	"github.com/joho/godotenv":             "godotenv",
	"github.com/looplab/fsm":               "looplab/fsm",
	"github.com/prometheus/client_golang":  "prometheus/client_golang",
	"github.com/zscaler/zscaler-sdk-go/v3": "zscaler-sdk-go",
	"golang.org/x/tools":                   "golang.org/x/tools",
	"gopkg.in/natefinch/lumberjack.v2":     "lumberjack",
	"modernc.org/sqlite":                   "modernc/sqlite",
}

//api:route GET /api/v1/libraries
func (s *Server) GetLibraries() Libraries {
	libs := Libraries{Go: runtime.Version()}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return libs
	}
	for _, m := range info.Deps {
		if name, ok := backendDirectDeps[m.Path]; ok {
			libs.Backend = append(libs.Backend, Library{Name: name, Version: m.Version})
		}
	}
	sort.Slice(libs.Backend, func(i, j int) bool {
		return libs.Backend[i].Name < libs.Backend[j].Name
	})
	return libs
}

//api:route POST /api/v1/simulation/run
//api:header Remote-User={user}
func (s *Server) RunSimulation(user string, simCtx simulator.SimContext) (*simulator.DecisionResult, error) {
	idx, err := s.getIndex()
	if err != nil {
		return nil, err
	}
	sim := simulator.NewSimulator(idx)
	result, err := sim.Run(s.ctx, simCtx)
	if err != nil {
		return nil, err
	}

	if s.store != nil {
		if _, err := s.store.SaveRun(s.ctx, simCtx, result, user); err != nil {
			slog.Warn("save simulation run",
				slog.String("user", user),
				slog.String("error", err.Error()))
		}
	}

	return result, nil
}

type VirtualPolicyInput struct {
	Name            string   `json:"name"`
	Action          string   `json:"action"`
	RuleOrder       string   `json:"ruleOrder"`
	ScimGroupIDs    []string `json:"scimGroupIds,omitempty"`
	SegmentIDs      []string `json:"segmentIds,omitempty"`
	SegmentGroupIDs []string `json:"segmentGroupIds,omitempty"`
}

type CompareRequest struct {
	Context       simulator.SimContext `json:"context"`
	VirtualPolicy VirtualPolicyInput   `json:"virtualPolicy"`
}

type CompareResult struct {
	Baseline    *simulator.DecisionResult                 `json:"baseline"`
	WithVirtual *simulator.DecisionResult                 `json:"withVirtual"`
	VirtualRule *policysetcontrollerv2.PolicyRuleResource `json:"virtualRule"`
}

//api:route POST /api/v1/simulation/compare
func (s *Server) CompareSimulation(req CompareRequest) (*CompareResult, error) {
	idx, err := s.getIndex()
	if err != nil {
		return nil, err
	}

	baseline, err := simulator.NewSimulator(idx).Run(s.ctx, req.Context)
	if err != nil {
		return nil, err
	}

	virtual := buildVirtualRule(req.VirtualPolicy)
	overlay := cloneIndexWithVirtual(idx, virtual)

	withVirtual, err := simulator.NewSimulator(overlay).Run(s.ctx, req.Context)
	if err != nil {
		return nil, err
	}

	return &CompareResult{
		Baseline:    baseline,
		WithVirtual: withVirtual,
		VirtualRule: virtual,
	}, nil
}

func buildVirtualRule(in VirtualPolicyInput) *policysetcontrollerv2.PolicyRuleResource {
	var operands []policysetcontrollerv2.PolicyRuleResourceOperands
	for _, id := range in.ScimGroupIDs {
		operands = append(operands, policysetcontrollerv2.PolicyRuleResourceOperands{
			ObjectType: "SCIM_GROUP", RHS: id,
		})
	}
	for _, id := range in.SegmentIDs {
		operands = append(operands, policysetcontrollerv2.PolicyRuleResourceOperands{
			ObjectType: "APP", RHS: id,
		})
	}
	for _, id := range in.SegmentGroupIDs {
		operands = append(operands, policysetcontrollerv2.PolicyRuleResourceOperands{
			ObjectType: "APP_GROUP", RHS: id,
		})
	}

	return &policysetcontrollerv2.PolicyRuleResource{
		ID:        "virtual:" + uuid.NewString(),
		Name:      in.Name,
		Action:    in.Action,
		RuleOrder: in.RuleOrder,
		Disabled:  "0",
		Operator:  "AND",
		Conditions: []policysetcontrollerv2.PolicyRuleResourceConditions{
			{Operator: "OR", Operands: operands},
		},
	}
}

// cloneIndexWithVirtual returns a shallow clone of idx with a deep-cloned
// Policies map containing the injected virtual rule. Other maps stay shared,
// which is safe because the simulator only reads them.
func cloneIndexWithVirtual(idx *index.Index, virtual *policysetcontrollerv2.PolicyRuleResource) *index.Index {
	out := *idx
	out.Policies = make(map[string]*policysetcontrollerv2.PolicyRuleResource, len(idx.Policies)+1)
	maps.Copy(out.Policies, idx.Policies)
	out.Policies[virtual.ID] = virtual
	return &out
}

//api:route GET /api/v1/me
//api:header Remote-User={user}
//api:header Remote-Email={email}
//api:header Remote-Groups={groups}
//api:header Remote-Name={name}
func (s *Server) GetMe(user, email, groups, name string) (Identity, error) {
	return Identity{
		User:   user,
		Email:  email,
		Groups: groups,
		Name:   name,
	}, nil
}

//api:route POST /api/v1/telemetry
//api:header Remote-User={user}
func (s *Server) PostTelemetry(user string, batch logging.TelemetryBatch) error {
	return logging.RecordTelemetryBatch(s.ctx, user, batch)
}

const (
	listSimulationRunsMaxLimit     = 500
	listSimulationRunsDefaultLimit = 50
)

//api:route GET /api/v1/simulation
//api:query limit={limit:50}
//api:query offset={offset:0}
func (s *Server) ListSimulationRuns(limit, offset int64) ([]storage.SimulationRun, error) {
	if s.store == nil {
		return nil, nil
	}
	switch {
	case limit <= 0:
		limit = listSimulationRunsDefaultLimit
	case limit > listSimulationRunsMaxLimit:
		limit = listSimulationRunsMaxLimit
	}
	if offset < 0 {
		offset = 0
	}
	return s.store.ListRuns(s.ctx, limit, offset)
}

//api:route GET /api/v1/simulation/{id}
func (s *Server) GetSimulationRun(id int64) (storage.SimulationRun, error) {
	if s.store == nil {
		return storage.SimulationRun{}, ErrUnavailable
	}
	run, err := s.store.GetRun(s.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.SimulationRun{}, ErrNotFound
	}
	return run, err
}

//api:route DELETE /api/v1/simulation/{id}
func (s *Server) DeleteSimulationRun(id int64) error {
	if s.store == nil {
		return nil
	}
	return s.store.DeleteRun(s.ctx, id)
}

//api:route GET /api/v1/simulation/count
func (s *Server) CountSimulationRuns() (int64, error) {
	if s.store == nil {
		return 0, nil
	}
	return s.store.CountRuns(s.ctx)
}

//api:route POST /api/v1/graph
func (s *Server) GetFlowGraph(data analysis.GraphQueryBody) (*analysis.FlowGraph, error) {
	s.mu.RLock()
	idx, err := s.getIndex()
	s.mu.RUnlock()
	if err != nil {
		return nil, err
	}

	graph := analysis.BuildFlowGraph(idx, data)
	return &graph, nil
}

//api:route GET /api/v1/zpa/client-types
func (s *Server) GetClientTypes() ([]string, error) {
	return fetcher.CachedFetch(s.ctx, &fetcher.GetCache().ClientTypes, fetcher.LoadClientTypes)
}

//api:route GET /api/v1/zpa/platforms
func (s *Server) GetPlatforms() ([]string, error) {
	return fetcher.CachedFetch(s.ctx, &fetcher.GetCache().Platforms, fetcher.LoadPlatforms)
}

//api:route GET /api/v1/zpa/segments
func (s *Server) GetSegments() ([]applicationsegment.ApplicationSegmentResource, error) {
	return fetcher.CachedFetch(s.ctx, &fetcher.GetCache().Segments, fetcher.LoadSegments)
}

//api:route GET /api/v1/zpa/segment-groups
func (s *Server) GetSegmentGroups() ([]segmentgroup.SegmentGroup, error) {
	return fetcher.CachedFetch(s.ctx, &fetcher.GetCache().SegmentGroups, fetcher.LoadSegmentGroups)
}

//api:route GET /api/v1/zpa/app-connectors
func (s *Server) GetAppConnectors() ([]appconnectorcontroller.AppConnector, error) {
	return fetcher.CachedFetch(s.ctx, &fetcher.GetCache().AppConnectors, fetcher.LoadAppConnectors)
}

//api:route GET /api/v1/zpa/app-connector-groups
func (s *Server) GetAppConnectorGroups() ([]appconnectorgroup.AppConnectorGroup, error) {
	return fetcher.CachedFetch(s.ctx, &fetcher.GetCache().AppConnectorGroups, fetcher.LoadAppConnectorGroups)
}

//api:route GET /api/v1/zpa/access-policies
func (s *Server) GetAccessPolicies() ([]policysetcontrollerv2.PolicyRuleResource, error) {
	return fetcher.CachedFetch(s.ctx, &fetcher.GetCache().AccessPolicies, fetcher.LoadAccessPolicies)
}

//api:route GET /api/v1/zpa/scim-groups
func (s *Server) GetScimGroups() ([]scimgroup.ScimGroup, error) {
	cache := fetcher.GetCache()
	client, err := fetcher.GetClient()
	if err != nil {
		return nil, err
	}
	return cache.ScimGroups.Get(func() ([]scimgroup.ScimGroup, error) {
		grps, errs := fetcher.LoadScimGroups(s.ctx, client)
		if errs != nil {
			return nil, errs
		}
		return grps, nil
	})
}

//api:route GET /api/v1/zpa/scim-attribute-headers
func (s *Server) GetScimAttributeHeaders() ([]scimattributeheader.ScimAttributeHeader, error) {
	return fetcher.CachedFetch(s.ctx, &fetcher.GetCache().ScimAttributeHeaders, fetcher.LoadScimAttributeHeaders)
}

//api:route GET /api/v1/zpa/scim-attribute-values
//api:query idpID={idpID}
//api:query headerID={headerID}
func (s *Server) GetScimAttributeValues(idpID, headerID string) ([]string, error) {
	client, err := fetcher.GetClient()
	if err != nil {
		return nil, err
	}
	entry := fetcher.GetCache().ScimValueCacheFor(idpID, headerID)
	return entry.Get(func() ([]string, error) {
		return fetcher.LoadScimAttributeValues(s.ctx, client, idpID, headerID)
	})
}

//api:route GET /api/v1/zpa/server-groups
func (s *Server) GetServerGroups() ([]servergroup.ServerGroup, error) {
	return fetcher.CachedFetch(s.ctx, &fetcher.GetCache().ServerGroups, fetcher.LoadServerGroups)
}

//api:route GET /api/v1/zpa/idp-controllers
func (s *Server) GetIdpControllers() ([]idpcontroller.IdpController, error) {
	return fetcher.CachedFetch(s.ctx, &fetcher.GetCache().IdpControllers, fetcher.LoadIdpControllers)
}

//api:route GET /api/v1/zpa/trusted-networks
func (s *Server) GetTrustedNetworks() ([]trustednetwork.TrustedNetwork, error) {
	return fetcher.CachedFetch(s.ctx, &fetcher.GetCache().TrustedNetworks, fetcher.LoadTrustedNetworks)
}

//api:route GET /api/v1/zpa/posture-profiles
func (s *Server) GetPostureProfiles() ([]postureprofile.PostureProfile, error) {
	return fetcher.CachedFetch(s.ctx, &fetcher.GetCache().PostureProfiles, fetcher.LoadPostureProfiles)
}

//api:route GET /api/v1/zpa/certificates
func (s *Server) GetCertificates() ([]bacertificate.BaCertificate, error) {
	return fetcher.CachedFetch(s.ctx, &fetcher.GetCache().Certificates, fetcher.LoadCertificates)
}

//api:route GET /api/v1/analytics/blast-radius
//api:query targetId={targetID}
//api:query targetType={targetType}
func (s *Server) GetBlastRadius(targetID, targetType string) (analysis.BlastRadiusReport, error) {
	idx, err := s.getIndex()
	if err != nil {
		return analysis.BlastRadiusReport{}, err
	}
	return analysis.BlastRadius(idx, targetID, targetType), nil
}

//api:route GET /api/v1/analytics/policy-shadows
func (s *Server) GetPolicyShadows() ([]analysis.PolicyShadowReport, error) {
	idx, err := s.getIndex()
	if err != nil {
		return nil, err
	}
	return analysis.PolicyShadows(idx), nil
}

//api:route GET /api/v1/analytics/orphan-clusters
func (s *Server) GetOrphanClusters() ([]analysis.OrphanCluster, error) {
	idx, err := s.getIndex()
	if err != nil {
		return nil, err
	}
	return analysis.OrphanClusters(idx), nil
}

//api:route GET /api/v1/analytics/domain-overlaps
func (s *Server) GetDomainOverlaps() ([]analysis.DomainOverlapDetail, error) {
	idx, err := s.getIndex()
	if err != nil {
		return nil, err
	}
	return analysis.DomainOverlapDetails(idx), nil
}

//api:route GET /api/v1/analytics/connector-load
func (s *Server) GetConnectorLoad() ([]analysis.ConnectorLoadEntry, error) {
	idx, err := s.getIndex()
	if err != nil {
		return nil, err
	}
	return analysis.ConnectorLoad(idx), nil
}

//api:route GET /api/v1/analytics/scim-reach
func (s *Server) GetScimReach() ([]analysis.ScimReachEntry, error) {
	idx, err := s.getIndex()
	if err != nil {
		return nil, err
	}
	return analysis.ScimReach(idx), nil
}

//api:route GET /api/v1/routes
func (s *Server) GetRoutes() (*analysis.RouteMatrix, error) {
	idx, err := s.getIndex()
	if err != nil {
		return nil, err
	}
	rm := analysis.BuildRoutes(idx)
	return &rm, nil
}
