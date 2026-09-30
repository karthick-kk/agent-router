// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package extensionserver

import (
	"context"
	"fmt"
	"strings"

	egextension "github.com/envoyproxy/gateway/proto/extension"
	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	fileaccesslog "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	a2av3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/a2a/v3"
	luav3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	httpconnectionmanagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/controller-runtime/pkg/client"

	aigv1a1 "github.com/envoyproxy/ai-gateway/api/v1alpha1"
	"github.com/envoyproxy/ai-gateway/internal/internalapi"
)

const (
	// a2aBackendListenerName is the shared internal listener that runs the native A2A
	// filter and forwards to the agent backends.
	a2aBackendListenerName = "aigateway-a2a-backend-listener"

	// a2aBackendClusterName is the local static cluster (127.0.0.1:10089) that public rpc
	// routes are rewritten to. The backend route copies keep the real agent cluster.
	a2aBackendClusterName = "aigateway-a2a-backend-cluster"

	// a2aBackendRouteConfigName is the RouteConfiguration served to the backend listener.
	a2aBackendRouteConfigName = a2aBackendListenerName + "-route-config"

	// a2aBackendWildcardVhost is the single wildcard virtual host on the backend listener.
	a2aBackendWildcardVhost = a2aBackendListenerName + "-wildcard"

	// a2aRBACFilterName is the Envoy RBAC filter name, used as the backend-listener chain
	// filter and as the per-route typed_per_filter_config key written by EG's authorization
	// translator.
	a2aRBACFilterName = "envoy.filters.http.rbac"

	// a2aMaxRequestBodySizeCap is the maximum the native filter accepts (10 MiB).
	a2aMaxRequestBodySizeCap uint32 = 10 * 1024 * 1024
)

// a2aRPCRoute is one A2A rpc (POST) route discovered in the generated xDS, plus the context
// needed to build its backend-listener copy.
type a2aRPCRoute struct {
	// route is the public rpc route (owned by a main route config); its cluster reference is
	// rewritten to a2aBackendClusterName.
	route *routev3.Route
	// backendCopy is the deep copy that lives on the backend listener; it keeps the real
	// agent cluster and carries the (moved) RBAC per-route config.
	backendCopy *routev3.Route
	// a2aRouteKey identifies the owning A2ARoute ("<namespace>/<name>" from the route header).
	a2aRouteKey client.ObjectKey
	// hostRouteConfigName is the RouteConfiguration that owns the public route, used to find
	// the listener whose HCM hosts it (to copy its jwt_authn chain filter).
	hostRouteConfigName string
}

// maybeGenerateResourcesForA2AGateway builds the shared A2A backend listener and rewires the
// public rpc routes to it. It is the data-plane half of the A2ARoute pipeline.
//
// For every A2A rpc route it:
//  1. deep-copies the route onto the backend listener (keeping the real agent cluster),
//  2. moves the SecurityPolicy RBAC per-route config from the public entry onto the copy so
//     authz evaluates after the a2a filter,
//  3. rewrites the public route's cluster to the local static cluster pointing at the backend
//     listener, so the shared main listener never runs the a2a filter (blast-radius isolation).
func (s *Server) maybeGenerateResourcesForA2AGateway(ctx context.Context, req *egextension.PostTranslateModifyRequest) error {
	if len(req.Listeners) == 0 || len(req.Routes) == 0 {
		return nil
	}

	rpcRoutes, err := s.collectA2ARPCRoutes(req.Routes)
	if err != nil {
		return err
	}
	if len(rpcRoutes) == 0 {
		return nil
	}

	// The backend listener is shared (single port, mirrors MCP), so all A2A routes share
	// one a2a filter config, sourced from the first A2ARoute.
	first, err := s.retrieveA2ARoute(ctx, rpcRoutes[0].a2aRouteKey)
	if err != nil {
		return err
	}
	if first == nil {
		// The A2ARoute was deleted between xDS generation and this call. Leave the routes as
		// EG generated them; the controller will clean up on the next reconcile.
		s.log.Info("A2ARoute not found, skipping A2A backend listener generation", "route", rpcRoutes[0].a2aRouteKey.String())
		return nil
	}

	// 1. Ensure the shared backend listener exists (idempotent across multiple A2ARoutes).
	if !s.listenerExists(req.Listeners, a2aBackendListenerName) {
		jwtFilter := s.findJWTAuthnFilter(req.Listeners, rpcRoutes[0].hostRouteConfigName)
		a2aFilter, err := s.buildA2AFilter(first)
		if err != nil {
			return fmt.Errorf("failed to build A2A filter: %w", err)
		}
		l, err := s.createA2ABackendListener(a2aFilter, jwtFilter)
		if err != nil {
			return fmt.Errorf("failed to create A2A backend listener: %w", err)
		}
		req.Listeners = append(req.Listeners, l)
	}

	// 2. Ensure the local static cluster to the backend listener exists.
	if !s.clusterExists(req.Clusters, a2aBackendClusterName) {
		req.Clusters = append(req.Clusters, s.buildA2ABackendCluster())
	}

	// 3. Move the RBAC per-route config off the public rpc entries (the backend copy made in
	//    collectA2ARPCRoutes already carries it) and rewrite their cluster.
	for _, rr := range rpcRoutes {
		if cfg := rr.route.TypedPerFilterConfig[a2aRBACFilterName]; cfg != nil {
			delete(rr.route.TypedPerFilterConfig, a2aRBACFilterName)
			s.log.Info("moved A2A RBAC per-route config to backend listener", "route", rr.route.Name)
		}
		if action := rr.route.GetRoute(); action != nil {
			if _, ok := action.ClusterSpecifier.(*routev3.RouteAction_Cluster); ok {
				action.ClusterSpecifier = &routev3.RouteAction_Cluster{Cluster: a2aBackendClusterName}
			}
		}
	}

	// 4. Add the backend route config (wildcard vhost with the backend copies).
	req.Routes = append(req.Routes, s.buildA2ABackendRouteConfig(rpcRoutes))
	return nil
}

// collectA2ARPCRoutes finds A2A rpc routes in the generated route configs: routes named after
// an A2ARoute-generated HTTPRoute that carry the A2A route identity header, which the
// controller sets on the rpc rule only. Each match is deep-copied for the backend listener,
// keeping the real agent cluster.
func (s *Server) collectA2ARPCRoutes(routes []*routev3.RouteConfiguration) ([]*a2aRPCRoute, error) {
	var rpcRoutes []*a2aRPCRoute
	for _, routeConfig := range routes {
		if routeConfig.Name == a2aBackendRouteConfigName {
			// Never re-process the backend listener's own route config on a repeated pass.
			continue
		}
		for _, vh := range routeConfig.VirtualHosts {
			for _, route := range vh.Routes {
				if !strings.Contains(route.Name, internalapi.A2AMainHTTPRoutePrefix) {
					continue
				}
				key, ok := a2aRouteKeyFromRoute(route)
				if !ok {
					continue
				}
				copied, err := deepCopyRoute(route)
				if err != nil {
					return nil, fmt.Errorf("failed to copy A2A rpc route %s: %w", route.Name, err)
				}
				rpcRoutes = append(rpcRoutes, &a2aRPCRoute{
					route:               route,
					backendCopy:         copied,
					a2aRouteKey:         key,
					hostRouteConfigName: routeConfig.Name,
				})
			}
		}
	}
	return rpcRoutes, nil
}

// stripA2ARouteHeader removes any request-header mutation that sets the A2A route identity
// header, so the backend route copy does not forward it to the agent.
func stripA2ARouteHeader(headers []*corev3.HeaderValueOption) []*corev3.HeaderValueOption {
	stripped := make([]*corev3.HeaderValueOption, 0, len(headers))
	for _, h := range headers {
		if h != nil && h.Header != nil && h.Header.Key == internalapi.A2ARouteHeader {
			continue
		}
		stripped = append(stripped, h)
	}
	return stripped
}

// a2aRouteKeyFromRoute extracts the owning A2ARoute key ("<ns>/<name>") from the A2A route
// identity header on the route's RequestHeadersToAdd.
func a2aRouteKeyFromRoute(route *routev3.Route) (client.ObjectKey, bool) {
	for _, h := range route.GetRequestHeadersToAdd() {
		if h == nil || h.Header == nil {
			continue
		}
		if h.Header.Key != internalapi.A2ARouteHeader {
			continue
		}
		parts := strings.SplitN(h.Header.Value, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return client.ObjectKey{}, false
		}
		return client.ObjectKey{Namespace: parts[0], Name: parts[1]}, true
	}
	return client.ObjectKey{}, false
}

// deepCopyRoute returns a deep copy of the route via a proto round-trip.
func deepCopyRoute(route *routev3.Route) (*routev3.Route, error) {
	b, err := proto.Marshal(route)
	if err != nil {
		return nil, err
	}
	copied := &routev3.Route{}
	if err := proto.Unmarshal(b, copied); err != nil {
		return nil, err
	}
	return copied, nil
}

// buildA2AFilter builds the native a2a filter config from the A2ARoute spec: traffic mode from
// rejectNonA2A, the body-size cap, and dynamic-metadata storage for the method bridge and the
// access log.
func (s *Server) buildA2AFilter(route *aigv1a1.A2ARoute) (*httpconnectionmanagerv3.HttpFilter, error) {
	trafficMode := a2av3.A2A_PASS_THROUGH
	if route.Spec.RejectNonA2A != nil && *route.Spec.RejectNonA2A {
		trafficMode = a2av3.A2A_REJECT
	}

	cfg := &a2av3.A2A{
		TrafficMode:  trafficMode,
		StorageMode:  a2av3.A2A_DYNAMIC_METADATA,
		ParserConfig: &a2av3.ParserConfig{},
	}
	if bytes := parseA2AMaxRequestBodySize(route.Spec.MaxRequestBodySize); bytes > 0 {
		cfg.MaxRequestBodySize = wrapperspb.UInt32(bytes)
	}

	a, err := toAny(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal A2A filter config: %w", err)
	}
	return &httpconnectionmanagerv3.HttpFilter{
		Name:       internalapi.A2AFilterName,
		ConfigType: &httpconnectionmanagerv3.HttpFilter_TypedConfig{TypedConfig: a},
	}, nil
}

// parseA2AMaxRequestBodySize parses maxRequestBodySize (a Kubernetes quantity like "1Mi")
// into bytes, clamped to the 10 MiB filter cap. Returns 0 when unset or unparseable.
func parseA2AMaxRequestBodySize(s *string) uint32 {
	if s == nil || *s == "" {
		return 0
	}
	q, err := resource.ParseQuantity(*s)
	if err != nil {
		return 0
	}
	v, ok := q.AsInt64()
	if !ok || v <= 0 {
		return 0
	}
	if v > int64(a2aMaxRequestBodySizeCap) {
		return a2aMaxRequestBodySizeCap
	}
	return uint32(v)
}

// a2aMethodBridgeLua copies the a2a filter's parsed JSON-RPC method from dynamic metadata into
// the internal A2AMethodHeader, because RBAC CEL cannot read metadata or a request.a2a
// attribute. This lets CEL rules gate on request.headers.
//
// Any client-supplied value of the header is removed first, so a client cannot inject it. When
// no method was parsed (non-A2A request, oversized body, parse error) the header stays unset
// and a CEL allow-list denies the request. The a2a filter buffers POST bodies and continues
// the chain only after parsing, so the metadata is populated before this callback runs.
const a2aMethodBridgeLua = `function envoy_on_request(request_handle)
  local headers = request_handle:headers()
  headers:remove("` + internalapi.A2AMethodHeader + `")
  local md = request_handle:streamInfo():dynamicMetadata():get("` + internalapi.A2AFilterName + `")
  if md and md.method then
    headers:add("` + internalapi.A2AMethodHeader + `", tostring(md.method))
  end
end
`

// buildA2AMethodBridgeFilter builds the Lua filter that bridges the a2a filter's dynamic
// metadata into a request header for CEL authz (see a2aMethodBridgeLua).
func (s *Server) buildA2AMethodBridgeFilter() (*httpconnectionmanagerv3.HttpFilter, error) {
	a, err := toAny(&luav3.Lua{InlineCode: a2aMethodBridgeLua})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Lua bridge filter config: %w", err)
	}
	return &httpconnectionmanagerv3.HttpFilter{
		Name:       wellknown.Lua,
		ConfigType: &httpconnectionmanagerv3.HttpFilter_TypedConfig{TypedConfig: a},
	}, nil
}

// createA2ABackendListener builds the shared A2A backend listener. The HCM filter order is
// a2a -> lua (method bridge) -> jwt_authn -> rbac -> router, so the a2a filter populates
// metadata, the bridge copies the method into a request header, and the RBAC filter can
// evaluate CEL rules keyed on that header. jwt_authn is copied from the owning
// main listener so JWT-principal rules resolve; double validation is harmless.
func (s *Server) createA2ABackendListener(a2aFilter, jwtFilter *httpconnectionmanagerv3.HttpFilter) (*listenerv3.Listener, error) {
	// RBAC chain filter with an empty config: the per-route config (moved from the public entry)
	// carries the actual policy, mirroring how EG's rbac patchHCM + patchRoute split the filter.
	rbacAny, err := toAny(&rbacv3.RBAC{})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RBAC filter config: %w", err)
	}
	rbacFilter := &httpconnectionmanagerv3.HttpFilter{
		Name:       a2aRBACFilterName,
		ConfigType: &httpconnectionmanagerv3.HttpFilter_TypedConfig{TypedConfig: rbacAny},
	}
	routerAny, err := toAny(&routerv3.Router{})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal router filter config: %w", err)
	}
	routerFilter := &httpconnectionmanagerv3.HttpFilter{
		Name:       wellknown.Router,
		ConfigType: &httpconnectionmanagerv3.HttpFilter_TypedConfig{TypedConfig: routerAny},
	}

	bridgeFilter, err := s.buildA2AMethodBridgeFilter()
	if err != nil {
		return nil, fmt.Errorf("failed to build A2A method bridge filter: %w", err)
	}

	var filters []*httpconnectionmanagerv3.HttpFilter
	filters = append(filters, a2aFilter, bridgeFilter)
	if jwtFilter != nil {
		filters = append(filters, jwtFilter)
	}
	filters = append(filters, rbacFilter, routerFilter)

	httpConManager := &httpconnectionmanagerv3.HttpConnectionManager{
		StatPrefix: fmt.Sprintf("%s-http", a2aBackendListenerName),
		AccessLog:  a2aAccessLog(),
		// Match the :scheme pseudo-header to the upstream transport protocol.
		SchemeHeaderTransformation: &corev3.SchemeHeaderTransformation{MatchUpstream: true},
		HttpFilters:                filters,
		RouteSpecifier: &httpconnectionmanagerv3.HttpConnectionManager_Rds{
			Rds: &httpconnectionmanagerv3.Rds{
				RouteConfigName: a2aBackendRouteConfigName,
				ConfigSource: &corev3.ConfigSource{
					ConfigSourceSpecifier: &corev3.ConfigSource_Ads{Ads: &corev3.AggregatedConfigSource{}},
					ResourceApiVersion:    corev3.ApiVersion_V3,
				},
			},
		},
	}

	hcmAny, err := toAny(httpConManager)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal A2A backend listener HCM: %w", err)
	}
	return &listenerv3.Listener{
		Name: a2aBackendListenerName,
		Address: &corev3.Address{
			Address: &corev3.Address_SocketAddress{
				SocketAddress: &corev3.SocketAddress{
					Protocol: corev3.SocketAddress_TCP,
					Address:  "127.0.0.1",
					PortSpecifier: &corev3.SocketAddress_PortValue{
						PortValue: internalapi.A2ABackendListenerPort,
					},
				},
			},
		},
		FilterChains: []*listenerv3.FilterChain{
			{
				Filters: []*listenerv3.Filter{
					{
						Name:       wellknown.HTTPConnectionManager,
						ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: hcmAny},
					},
				},
			},
		},
	}, nil
}

// buildA2ABackendCluster builds the local static cluster that public rpc routes are rewritten to
// point at. It forwards to the backend listener on 127.0.0.1:10089.
func (s *Server) buildA2ABackendCluster() *clusterv3.Cluster {
	name := a2aBackendClusterName
	return &clusterv3.Cluster{
		Name:                 name,
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC},
		ConnectTimeout:       &durationpb.Duration{Seconds: 10},
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*endpointv3.LocalityLbEndpoints{
				{
					LbEndpoints: []*endpointv3.LbEndpoint{
						{
							HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
								Endpoint: &endpointv3.Endpoint{
									Address: &corev3.Address{
										Address: &corev3.Address_SocketAddress{
											SocketAddress: &corev3.SocketAddress{
												Address: "127.0.0.1",
												PortSpecifier: &corev3.SocketAddress_PortValue{
													PortValue: internalapi.A2ABackendListenerPort,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// buildA2ABackendRouteConfig builds the backend listener's RouteConfiguration: a single wildcard
// virtual host carrying the deep-copied rpc routes (each keeping its real agent cluster). The
// internal A2A route identity header is stripped from the copies, and the method bridge header
// is removed, so neither reaches the agent.
func (s *Server) buildA2ABackendRouteConfig(rpcRoutes []*a2aRPCRoute) *routev3.RouteConfiguration {
	backendRoutes := make([]*routev3.Route, 0, len(rpcRoutes))
	for _, rr := range rpcRoutes {
		// The identity header is an internal marker; it must not reach the agent.
		rr.backendCopy.RequestHeadersToAdd = stripA2ARouteHeader(rr.backendCopy.RequestHeadersToAdd)
		// The bridge header is internal-only and set after authz ran; strip it upstream.
		rr.backendCopy.RequestHeadersToRemove = append(rr.backendCopy.RequestHeadersToRemove, internalapi.A2AMethodHeader)
		backendRoutes = append(backendRoutes, rr.backendCopy)
	}
	return &routev3.RouteConfiguration{
		Name: a2aBackendRouteConfigName,
		VirtualHosts: []*routev3.VirtualHost{
			{
				Name:    a2aBackendWildcardVhost,
				Domains: []string{"*"},
				Routes:  backendRoutes,
			},
		},
	}
}

// a2aAccessLog surfaces the a2a filter's parsed method and id from its dynamic metadata.
func a2aAccessLog() []*accesslogv3.AccessLog {
	format := &corev3.SubstitutionFormatString{
		Format: &corev3.SubstitutionFormatString_TextFormatSource{
			TextFormatSource: &corev3.DataSource{
				Specifier: &corev3.DataSource_InlineString{
					InlineString: "a2a_method=%DYNAMIC_METADATA(" + internalapi.A2AFilterName + ":method)%" +
						" a2a_id=%DYNAMIC_METADATA(" + internalapi.A2AFilterName + ":id)%" +
						" %RESPONSE_CODE_DETAILS% %REQ(:METHOD)% %REQ(:PATH)% %REQ(:AUTHORITY)%",
				},
			},
		},
	}
	filelog := &fileaccesslog.FileAccessLog{
		Path: "/dev/stdout",
		AccessLogFormat: &fileaccesslog.FileAccessLog_LogFormat{
			LogFormat: format,
		},
	}
	a, err := toAny(filelog)
	if err != nil {
		// A malformed access log must not block data-plane generation.
		return nil
	}
	return []*accesslogv3.AccessLog{
		{
			Name:       wellknown.FileAccessLog,
			ConfigType: &accesslogv3.AccessLog_TypedConfig{TypedConfig: a},
		},
	}
}

// retrieveA2ARoute returns the A2ARoute for key, or nil when not found.
func (s *Server) retrieveA2ARoute(ctx context.Context, key client.ObjectKey) (*aigv1a1.A2ARoute, error) {
	var r aigv1a1.A2ARoute
	if err := s.k8sClient.Get(ctx, key, &r); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get A2ARoute %s: %w", key.String(), err)
	}
	return &r, nil
}

// findJWTAuthnFilter locates the jwt_authn chain filter on the listener whose HCM serves
// routeConfigName and returns a copy of it, or nil when not found. Copying the providers to the
// backend HCM lets JWT-principal authz rules resolve there.
func (s *Server) findJWTAuthnFilter(listeners []*listenerv3.Listener, routeConfigName string) *httpconnectionmanagerv3.HttpFilter {
	for _, listener := range listeners {
		if listener.Name == a2aBackendListenerName {
			continue
		}
		chains := listener.GetFilterChains()
		if listener.DefaultFilterChain != nil {
			chains = append(chains, listener.DefaultFilterChain)
		}
		for _, chain := range chains {
			hcm, _, err := findHCM(chain)
			if err != nil {
				continue
			}
			if routeConfigName != "" && hcm.GetRds().GetRouteConfigName() != routeConfigName {
				continue
			}
			for _, f := range hcm.HttpFilters {
				if f.Name == filterNameJWTAuthn {
					if copied, err := deepCopyFilter(f); err == nil {
						return copied
					} else {
						s.log.Error(err, "failed to copy jwt_authn filter for A2A backend listener")
					}
				}
			}
		}
	}
	return nil
}

// deepCopyFilter returns a deep copy of an HTTP filter via a proto round-trip.
func deepCopyFilter(f *httpconnectionmanagerv3.HttpFilter) (*httpconnectionmanagerv3.HttpFilter, error) {
	b, err := proto.Marshal(f)
	if err != nil {
		return nil, err
	}
	copied := &httpconnectionmanagerv3.HttpFilter{}
	if err := proto.Unmarshal(b, copied); err != nil {
		return nil, err
	}
	return copied, nil
}

// listenerExists reports whether a listener with name is already present.
func (s *Server) listenerExists(listeners []*listenerv3.Listener, name string) bool {
	for _, l := range listeners {
		if l.Name == name {
			return true
		}
	}
	return false
}

// clusterExists reports whether a cluster with name is already present.
func (s *Server) clusterExists(clusters []*clusterv3.Cluster, name string) bool {
	for _, c := range clusters {
		if c.Name == name {
			return true
		}
	}
	return false
}
