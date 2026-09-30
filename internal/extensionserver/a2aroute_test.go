// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package extensionserver

import (
	"testing"

	a2av3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/a2a/v3"
	luav3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	egextension "github.com/envoyproxy/gateway/proto/extension"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	httpconnectionmanagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	aigv1a1 "github.com/envoyproxy/ai-gateway/api/v1alpha1"
	"github.com/envoyproxy/ai-gateway/internal/internalapi"
)

// TestParseA2AMaxRequestBodySize exercises the quantity parsing and clamping.
func TestParseA2AMaxRequestBodySize(t *testing.T) {
	tests := []struct {
		name   string
		in     *string
		expect uint32
	}{
		{"nil", nil, 0},
		{"empty", ptr.To(""), 0},
		{"one MiB", ptr.To("1Mi"), 1024 * 1024},
		{"8 KiB", ptr.To("8Ki"), 8192},
		{"plain bytes", ptr.To("5000"), 5000},
		{"over cap clamps", ptr.To("100Mi"), a2aMaxRequestBodySizeCap},
		{"exact cap", ptr.To("10Mi"), a2aMaxRequestBodySizeCap},
		{"invalid", ptr.To("abc"), 0},
		{"negative", ptr.To("-5"), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expect, parseA2AMaxRequestBodySize(tt.in))
		})
	}
}

// TestBuildA2AFilter checks traffic_mode, storage mode, parser config, and body-size mapping.
func TestBuildA2AFilter(t *testing.T) {
	tests := []struct {
		name           string
		spec           aigv1a1.A2ARouteSpec
		wantTraffic    a2av3.A2A_TrafficMode
		wantMaxReqBody *wrapperspb.UInt32Value
	}{
		{
			name:           "defaults: pass-through, no body size",
			spec:           aigv1a1.A2ARouteSpec{},
			wantTraffic:    a2av3.A2A_PASS_THROUGH,
			wantMaxReqBody: nil,
		},
		{
			name:           "reject + 1Mi body size",
			spec:           aigv1a1.A2ARouteSpec{RejectNonA2A: ptr.To(true), MaxRequestBodySize: ptr.To("1Mi")},
			wantTraffic:    a2av3.A2A_REJECT,
			wantMaxReqBody: wrapperspb.UInt32(1024 * 1024),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{}
			f, err := s.buildA2AFilter(&aigv1a1.A2ARoute{Spec: tt.spec})
			require.NoError(t, err)
			require.Equal(t, internalapi.A2AFilterName, f.Name)

			cfg := &a2av3.A2A{}
			require.NoError(t, f.GetTypedConfig().UnmarshalTo(cfg))
			require.Equal(t, tt.wantTraffic, cfg.GetTrafficMode())
			require.Equal(t, a2av3.A2A_DYNAMIC_METADATA, cfg.GetStorageMode())
			require.NotNil(t, cfg.GetParserConfig())
			require.Equal(t, tt.wantMaxReqBody, cfg.GetMaxRequestBodySize())
		})
	}
}

// TestA2ABackendListenerFilterOrder pins the HCM filter order on the A2A backend listener:
// a2a -> lua (method bridge) -> jwt_authn -> rbac -> router, so the a2a filter populates
// metadata and the bridge copies the method into a header before RBAC evaluates CEL rules.
func TestA2ABackendListenerFilterOrder(t *testing.T) {
	s := &Server{}
	jwt := &httpconnectionmanagerv3.HttpFilter{Name: filterNameJWTAuthn}
	a2a, err := s.buildA2AFilter(&aigv1a1.A2ARoute{})
	require.NoError(t, err)

	l, err := s.createA2ABackendListener(a2a, jwt)
	require.NoError(t, err)
	require.Equal(t, a2aBackendListenerName, l.Name)
	require.Equal(t, "127.0.0.1", l.Address.GetSocketAddress().Address)
	require.Equal(t, uint32(internalapi.A2ABackendListenerPort), l.Address.GetSocketAddress().GetPortValue())

	hcm, _, err := findHCM(l.FilterChains[0])
	require.NoError(t, err)
	got := make([]string, 0, len(hcm.HttpFilters))
	for _, f := range hcm.HttpFilters {
		got = append(got, f.Name)
	}
	require.Equal(t, []string{
		internalapi.A2AFilterName,
		wellknown.Lua,
		filterNameJWTAuthn,
		a2aRBACFilterName,
		wellknown.Router,
	}, got)
	require.NotEmpty(t, hcm.AccessLog, "A2A backend listener must configure an access log")
}

// TestA2ABackendListenerNoJWT confirms the listener is built without jwt_authn when none is
// found on the owning main listener (RBAC, the a2a filter, and the bridge still present).
func TestA2ABackendListenerNoJWT(t *testing.T) {
	s := &Server{}
	a2a, err := s.buildA2AFilter(&aigv1a1.A2ARoute{})
	require.NoError(t, err)

	l, err := s.createA2ABackendListener(a2a, nil)
	require.NoError(t, err)
	hcm, _, err := findHCM(l.FilterChains[0])
	require.NoError(t, err)
	got := make([]string, 0, len(hcm.HttpFilters))
	for _, f := range hcm.HttpFilters {
		got = append(got, f.Name)
	}
	require.Equal(t, []string{internalapi.A2AFilterName, wellknown.Lua, a2aRBACFilterName, wellknown.Router}, got)
}

// TestBuildA2AMethodBridgeFilter confirms the Lua bridge filter reads the a2a filter's dynamic
// metadata and copies the parsed method into the internal header.
func TestBuildA2AMethodBridgeFilter(t *testing.T) {
	s := &Server{}
	f, err := s.buildA2AMethodBridgeFilter()
	require.NoError(t, err)
	require.Equal(t, wellknown.Lua, f.Name)

	cfg := &luav3.Lua{}
	require.NoError(t, f.GetTypedConfig().UnmarshalTo(cfg))
	require.NotEmpty(t, cfg.GetInlineCode())
	require.Contains(t, cfg.GetInlineCode(), "envoy_on_request")
	require.Contains(t, cfg.GetInlineCode(), internalapi.A2AMethodHeader)
	require.Contains(t, cfg.GetInlineCode(), internalapi.A2AFilterName)
	require.Contains(t, cfg.GetInlineCode(), "headers:remove(")
	require.Contains(t, cfg.GetInlineCode(), "dynamicMetadata():get(")
}

// a2aTestRPCRoute builds a public A2A rpc route: identity header + RBAC per-route config + agent cluster.
func a2aTestRPCRoute(agentCluster string) *routev3.Route {
	return &routev3.Route{
		Name: agentCluster,
		Action: &routev3.Route_Route{
			Route: &routev3.RouteAction{
				ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: agentCluster},
			},
		},
		RequestHeadersToAdd: []*corev3.HeaderValueOption{
			{
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
				Header:       &corev3.HeaderValue{Key: internalapi.A2ARouteHeader, Value: "default/agent"},
			},
		},
		TypedPerFilterConfig: map[string]*anypb.Any{
			a2aRBACFilterName: &anypb.Any{
				TypeUrl: "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBACPerRoute",
				Value:   []byte{0},
			},
		},
	}
}

// TestServer_maybeGenerateResourcesForA2AGateway is the end-to-end golden test: it feeds a
// PostTranslateModifyRequest carrying one A2A rpc route plus the owning main listener (with
// jwt_authn), and asserts the backend listener, static cluster, and route rewiring.
func TestServer_maybeGenerateResourcesForA2AGateway(t *testing.T) {
	t.Run("no A2A routes is a no-op", func(t *testing.T) {
		s := serverWithObjects(t)
		req := &egextension.PostTranslateModifyRequest{
			Listeners: []*listenerv3.Listener{{Name: "other"}},
			Routes:    []*routev3.RouteConfiguration{{Name: "other-rc"}},
		}
		require.NoError(t, s.maybeGenerateResourcesForA2AGateway(t.Context(), req))
		require.Len(t, req.Listeners, 1)
		require.Len(t, req.Routes, 1)
		require.Empty(t, req.Clusters)
	})

	t.Run("rewires the rpc route and builds the backend listener", func(t *testing.T) {
		const agentCluster = "httproute/default/ai-eg-a2a-main-agent/rule/1"
		const publicRC = "listener/envoy-gateway/eg-gateway:80/http"
		rpcRoute := a2aTestRPCRoute(agentCluster)

		mainListener := &listenerv3.Listener{
			Name: "main-listener",
			FilterChains: []*listenerv3.FilterChain{{
				Filters: []*listenerv3.Filter{{
					Name: wellknown.HTTPConnectionManager,
					ConfigType: &listenerv3.Filter_TypedConfig{
						TypedConfig: mustToAny(t, &httpconnectionmanagerv3.HttpConnectionManager{
							StatPrefix: "main-http",
							RouteSpecifier: &httpconnectionmanagerv3.HttpConnectionManager_Rds{
								Rds: &httpconnectionmanagerv3.Rds{RouteConfigName: publicRC},
							},
							HttpFilters: []*httpconnectionmanagerv3.HttpFilter{
								{Name: filterNameJWTAuthn},
								{Name: wellknown.Router},
							},
						}),
					},
				}},
			}},
		}

		req := &egextension.PostTranslateModifyRequest{
			Listeners: []*listenerv3.Listener{mainListener},
			Routes: []*routev3.RouteConfiguration{
				{
					Name: publicRC,
					VirtualHosts: []*routev3.VirtualHost{
						{Name: "vh", Domains: []string{"aigw.example.com"}, Routes: []*routev3.Route{rpcRoute}},
					},
				},
			},
			Clusters: []*clusterv3.Cluster{{Name: agentCluster}},
		}

		s := serverWithObjects(t, &aigv1a1.A2ARoute{
			ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "default"},
			Spec:       aigv1a1.A2ARouteSpec{MaxRequestBodySize: ptr.To("2Mi"), RejectNonA2A: ptr.To(true)},
		})

		require.NoError(t, s.maybeGenerateResourcesForA2AGateway(t.Context(), req))

		// 1. Backend listener added, on port 10089.
		require.Len(t, req.Listeners, 2)
		backend := req.Listeners[1]
		require.Equal(t, a2aBackendListenerName, backend.Name)
		require.Equal(t, uint32(internalapi.A2ABackendListenerPort), backend.Address.GetSocketAddress().GetPortValue())

		// 2. Local static cluster added, pointing at the backend listener.
		var staticCluster *clusterv3.Cluster
		for _, c := range req.Clusters {
			if c.Name == a2aBackendClusterName {
				staticCluster = c
			}
		}
		require.NotNil(t, staticCluster, "local A2A backend cluster must be added")
		require.Equal(t, clusterv3.Cluster_STATIC, staticCluster.GetClusterDiscoveryType().(*clusterv3.Cluster_Type).Type)
		require.Equal(t, uint32(internalapi.A2ABackendListenerPort),
			staticCluster.LoadAssignment.Endpoints[0].LbEndpoints[0].GetEndpoint().GetAddress().GetSocketAddress().GetPortValue())

		// 3. Public rpc route rewritten to the backend cluster; RBAC per-route config removed.
		require.Equal(t, a2aBackendClusterName, rpcRoute.GetRoute().GetCluster())
		_, stillHasRBAC := rpcRoute.TypedPerFilterConfig[a2aRBACFilterName]
		require.False(t, stillHasRBAC, "public rpc route must no longer carry the RBAC per-route config")

		// 4. Backend route config: wildcard vhost, copy keeps the agent cluster + moved RBAC,
		//    and the identity header is stripped from the copy.
		require.Len(t, req.Routes, 2)
		backendRC := req.Routes[1]
		require.Equal(t, a2aBackendRouteConfigName, backendRC.Name)
		require.Len(t, backendRC.VirtualHosts, 1)
		require.Equal(t, []string{"*"}, backendRC.VirtualHosts[0].Domains)
		backendCopy := backendRC.VirtualHosts[0].Routes[0]
		require.Equal(t, agentCluster, backendCopy.GetRoute().GetCluster(), "backend copy must keep the real agent cluster")
		_, hasRBAC := backendCopy.TypedPerFilterConfig[a2aRBACFilterName]
		require.True(t, hasRBAC, "backend copy must carry the moved RBAC per-route config")
		for _, h := range backendCopy.RequestHeadersToAdd {
			require.NotEqual(t, internalapi.A2ARouteHeader, h.GetHeader().Key, "identity header must be stripped from the backend copy")
		}
		require.Contains(t, backendCopy.RequestHeadersToRemove, internalapi.A2AMethodHeader,
			"method bridge header must be removed before the request reaches the agent")
	})
}

// TestServer_maybeGenerateResourcesForA2AGateway_deletedRoute confirms the no-op path when the
// A2ARoute has been deleted between xDS generation and this call.
func TestServer_maybeGenerateResourcesForA2AGateway_deletedRoute(t *testing.T) {
	rpcRoute := a2aTestRPCRoute("httproute/default/ai-eg-a2a-main-agent/rule/1")
	req := &egextension.PostTranslateModifyRequest{
		Listeners: []*listenerv3.Listener{{Name: "main"}},
		Routes: []*routev3.RouteConfiguration{
			{
				Name:         "main-rc",
				VirtualHosts: []*routev3.VirtualHost{{Name: "vh", Domains: []string{"*"}, Routes: []*routev3.Route{rpcRoute}}},
			},
		},
	}
	// No A2ARoute seeded: retrieveA2ARoute returns nil, so nothing is generated.
	s := serverWithObjects(t)
	require.NoError(t, s.maybeGenerateResourcesForA2AGateway(t.Context(), req))
	require.Len(t, req.Listeners, 1)
	require.Len(t, req.Routes, 1)
	require.Empty(t, req.Clusters)
}
