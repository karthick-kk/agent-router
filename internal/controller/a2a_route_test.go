// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	fakekube "k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	aigv1a1 "github.com/envoyproxy/ai-gateway/api/v1alpha1"
	"github.com/envoyproxy/ai-gateway/internal/internalapi"
	internaltesting "github.com/envoyproxy/ai-gateway/internal/testing"
)

// TestA2ARouteController_CardFilterValueRefIsConfigMap pins the directResponse card
// filter's valueRef shape: the EG CRD's CEL rule rejects an empty kind
// (spec.directResponse.body.valueRef.kind must be "ConfigMap"), so a missing Kind
// makes every card-serving A2ARoute fail admission at create time.
func TestA2ARouteController_CardFilterValueRefIsConfigMap(t *testing.T) {
	fakeClient := requireNewFakeClientForA2A(t)
	c := NewA2ARouteController(fakeClient, fakekube.NewClientset(), ctrl.Log, make(chan event.GenericEvent, 1))
	route := &aigv1a1.A2ARoute{ObjectMeta: metav1.ObjectMeta{Name: "my-agent-route", Namespace: "default"}}

	require.NoError(t, c.ensureA2ACardFilterAndConfigMap(t.Context(), route, true))

	var filter egv1a1.HTTPRouteFilter
	require.NoError(t, fakeClient.Get(t.Context(), client.ObjectKey{Name: string(a2aCardFilterName(route.Name)), Namespace: "default"}, &filter))
	require.NotNil(t, filter.Spec.DirectResponse)
	require.NotNil(t, filter.Spec.DirectResponse.Body)
	require.Equal(t, egv1a1.ResponseValueTypeValueRef, *filter.Spec.DirectResponse.Body.Type)
	require.NotNil(t, filter.Spec.DirectResponse.Body.ValueRef)
	require.Equal(t, gwapiv1.Kind("ConfigMap"), filter.Spec.DirectResponse.Body.ValueRef.Kind)
	require.Equal(t, gwapiv1.ObjectName(a2aCardConfigMapName(route.Name)), filter.Spec.DirectResponse.Body.ValueRef.Name)
	require.NotNil(t, filter.Spec.DirectResponse.ContentType)
	require.Equal(t, "application/json", *filter.Spec.DirectResponse.ContentType)
}

func TestA2ARouteController_Reconcile_PassthroughCard(t *testing.T) {
	fakeClient := requireNewFakeClientForA2A(t)
	eventCh := internaltesting.NewControllerEventChan[*gwapiv1.Gateway]()
	c := NewA2ARouteController(fakeClient, fakekube.NewClientset(), ctrl.Log, eventCh.Ch)

	// Target Gateway for the parentRefs.
	require.NoError(t, fakeClient.Create(t.Context(), &gwapiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "mygw", Namespace: "default"},
	}))

	// Agent referenced by the single backendRef: an Envoy Gateway Backend CR whose
	// FQDN endpoint points at the agent. serve:false keeps the card rule a passthrough,
	// so the backend object is created for parity but no network fetch is attempted.
	require.NoError(t, fakeClient.Create(t.Context(), &egv1a1.Backend{
		ObjectMeta: metav1.ObjectMeta{Name: "my-agent", Namespace: "default"},
		Spec: egv1a1.BackendSpec{Endpoints: []egv1a1.BackendEndpoint{
			{FQDN: &egv1a1.FQDNEndpoint{Hostname: "my-agent.default.svc.cluster.local", Port: 8080}},
		}},
	}))

	route := &aigv1a1.A2ARoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-agent-route", Namespace: "default"},
		Spec: aigv1a1.A2ARouteSpec{
			ParentRefs: []gwapiv1.ParentReference{{Name: "mygw"}},
			Hostnames:  []gwapiv1.Hostname{"aigw.example.com"},
			Path:       ptr.To("/agent"),
			BackendRefs: []gwapiv1.BackendObjectReference{
				{Group: ptr.To(gwapiv1.Group(egv1a1.GroupName)), Kind: ptr.To(gwapiv1.Kind(egv1a1.KindBackend)), Name: "my-agent"},
			},
			// serve:false keeps the card rule a passthrough so the test makes no network fetch.
			AgentCard: &aigv1a1.AgentCardConfig{Serve: ptr.To(false)},
		},
	}
	require.NoError(t, fakeClient.Create(t.Context(), route))

	_, err := c.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "my-agent-route"}})
	require.NoError(t, err)

	// Finalizer added.
	var current aigv1a1.A2ARoute
	require.NoError(t, fakeClient.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: "my-agent-route"}, &current))
	require.Contains(t, current.Finalizers, aiGatewayControllerFinalizer)

	// Accepted condition, no CardReady condition (card serving disabled).
	requireAccepted(t, &current)
	requireConditionAbsent(t, &current, aigv1a1.A2AConditionTypeCardReady)

	// The generated main HTTPRoute has exactly two named rules: agent-card + rpc.
	var main gwapiv1.HTTPRoute
	require.NoError(t, fakeClient.Get(t.Context(), client.ObjectKey{
		Name: internalapi.A2AMainHTTPRoutePrefix + "my-agent-route", Namespace: "default",
	}, &main))
	require.Len(t, main.Spec.Rules, 2)
	require.Equal(t, gwapiv1.SectionName("agent-card"), *main.Spec.Rules[0].Name)
	require.Equal(t, gwapiv1.SectionName("rpc"), *main.Spec.Rules[1].Name)

	// Card rule: passthrough (serve:false) → GET on both well-known paths, backendRefs set.
	cardRule := main.Spec.Rules[0]
	require.Len(t, cardRule.Matches, 2)
	require.Equal(t, gwapiv1.HTTPMethodGet, *cardRule.Matches[0].Method)
	require.Equal(t, "/agent/.well-known/agent-card.json", *cardRule.Matches[0].Path.Value)
	require.Equal(t, "/agent/.well-known/agent.json", *cardRule.Matches[1].Path.Value)
	require.Len(t, cardRule.BackendRefs, 1)
	require.Equal(t, gwapiv1.ObjectName("my-agent"), cardRule.BackendRefs[0].Name)

	// rpc rule: POST path-prefix, agent backend, streaming (default) → 0s request timeout,
	// and the A2A route identity header set to <ns>/<name>.
	rpcRule := main.Spec.Rules[1]
	require.Equal(t, gwapiv1.HTTPMethodPost, *rpcRule.Matches[0].Method)
	require.Equal(t, gwapiv1.PathMatchPathPrefix, *rpcRule.Matches[0].Path.Type)
	require.Equal(t, "/agent", *rpcRule.Matches[0].Path.Value)
	require.Len(t, rpcRule.BackendRefs, 1)
	require.Equal(t, gwapiv1.ObjectName("my-agent"), rpcRule.BackendRefs[0].Name)
	require.NotNil(t, rpcRule.Timeouts)
	require.Equal(t, gwapiv1.Duration("0s"), *rpcRule.Timeouts.Request)
	requireA2ARouteHeader(t, rpcRule, "default/my-agent-route")

	// ParentRefs + hostnames copied.
	require.Equal(t, route.Spec.ParentRefs, main.Spec.ParentRefs)
	require.Equal(t, route.Spec.Hostnames, main.Spec.Hostnames)
}

// TestA2ARouteController_Reconcile_NonStreaming checks the explicit 30m timeout when streaming
// is disabled.
func TestA2ARouteController_Reconcile_NonStreaming(t *testing.T) {
	fakeClient := requireNewFakeClientForA2A(t)
	eventCh := internaltesting.NewControllerEventChan[*gwapiv1.Gateway]()
	c := NewA2ARouteController(fakeClient, fakekube.NewClientset(), ctrl.Log, eventCh.Ch)
	require.NoError(t, fakeClient.Create(t.Context(), &gwapiv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "mygw", Namespace: "default"}}))
	require.NoError(t, fakeClient.Create(t.Context(), &egv1a1.Backend{
		ObjectMeta: metav1.ObjectMeta{Name: "my-agent", Namespace: "default"},
		Spec: egv1a1.BackendSpec{Endpoints: []egv1a1.BackendEndpoint{
			{FQDN: &egv1a1.FQDNEndpoint{Hostname: "my-agent.default.svc.cluster.local", Port: 8080}},
		}},
	}))

	route := &aigv1a1.A2ARoute{
		ObjectMeta: metav1.ObjectMeta{Name: "r2", Namespace: "default"},
		Spec: aigv1a1.A2ARouteSpec{
			ParentRefs: []gwapiv1.ParentReference{{Name: "mygw"}},
			Streaming:  ptr.To(false),
			BackendRefs: []gwapiv1.BackendObjectReference{
				{Group: ptr.To(gwapiv1.Group(egv1a1.GroupName)), Kind: ptr.To(gwapiv1.Kind(egv1a1.KindBackend)), Name: "my-agent"},
			},
			AgentCard: &aigv1a1.AgentCardConfig{Serve: ptr.To(false)},
		},
	}
	require.NoError(t, fakeClient.Create(t.Context(), route))
	_, err := c.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "r2"}})
	require.NoError(t, err)

	var main gwapiv1.HTTPRoute
	require.NoError(t, fakeClient.Get(t.Context(), client.ObjectKey{Name: internalapi.A2AMainHTTPRoutePrefix + "r2", Namespace: "default"}, &main))
	rpcRule := main.Spec.Rules[1]
	require.NotNil(t, rpcRule.Timeouts)
	require.Equal(t, gwapiv1.Duration("30m"), *rpcRule.Timeouts.Request)
}

// TestA2ARouteController_Reconcile_CrossNamespaceBackendRejected verifies a cross-namespace
// backendRef is rejected with a NotAccepted status (no HTTPRoute created).
func TestA2ARouteController_Reconcile_CrossNamespaceBackendRejected(t *testing.T) {
	fakeClient := requireNewFakeClientForA2A(t)
	eventCh := internaltesting.NewControllerEventChan[*gwapiv1.Gateway]()
	c := NewA2ARouteController(fakeClient, fakekube.NewClientset(), ctrl.Log, eventCh.Ch)
	require.NoError(t, fakeClient.Create(t.Context(), &gwapiv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "mygw", Namespace: "default"}}))

	route := &aigv1a1.A2ARoute{
		ObjectMeta: metav1.ObjectMeta{Name: "r3", Namespace: "default"},
		Spec: aigv1a1.A2ARouteSpec{
			ParentRefs: []gwapiv1.ParentReference{{Name: "mygw"}},
			BackendRefs: []gwapiv1.BackendObjectReference{
				{Group: ptr.To(gwapiv1.Group(egv1a1.GroupName)), Kind: ptr.To(gwapiv1.Kind(egv1a1.KindBackend)),
					Name: "other-ns-agent", Namespace: ptr.To(gwapiv1.Namespace("other-ns"))},
			},
			AgentCard: &aigv1a1.AgentCardConfig{Serve: ptr.To(false)},
		},
	}
	require.NoError(t, fakeClient.Create(t.Context(), route))

	_, err := c.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "r3"}})
	require.Error(t, err)

	var current aigv1a1.A2ARoute
	require.NoError(t, fakeClient.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: "r3"}, &current))
	require.NotEmpty(t, current.Status.Conditions)
	last := current.Status.Conditions[len(current.Status.Conditions)-1]
	require.Equal(t, aigv1a1.A2AConditionTypeNotAccepted, last.Type)
	require.Equal(t, metav1.ConditionFalse, last.Status)

	// No HTTPRoute generated.
	var main gwapiv1.HTTPRoute
	require.Error(t, fakeClient.Get(t.Context(), client.ObjectKey{Name: internalapi.A2AMainHTTPRoutePrefix + "r3", Namespace: "default"}, &main))
}

// TestRewriteAgentCardURLs verifies the top-level url and every supportedInterfaces[].url are
// rewritten to the public base, and the card is unchanged when the base is empty.
func TestRewriteAgentCardURLs(t *testing.T) {
	card := []byte(`{"url":"http://agent.ns.svc:8080/agent","supportedInterfaces":[{"binding":"HTTP+JSON","url":"http://agent.ns.svc:8080/agent"},{"binding":"HTTP+JSON","url":"http://legacy:8080/agent"}]}`)

	out, err := rewriteAgentCardURLs(card, "https://aigw.example.com/agent")
	require.NoError(t, err)
	require.JSONEq(t, `{"url":"https://aigw.example.com/agent","supportedInterfaces":[{"binding":"HTTP+JSON","url":"https://aigw.example.com/agent"},{"binding":"HTTP+JSON","url":"https://aigw.example.com/agent"}]}`, string(out))

	// Empty base leaves the card unchanged.
	unchanged, err := rewriteAgentCardURLs(card, "")
	require.NoError(t, err)
	require.Equal(t, card, unchanged)
}

// TestA2ARouteHelperNames pins the naming helpers the extension server and SecurityPolicy
// targeting rely on.
func TestA2ARouteHelperNames(t *testing.T) {
	route := &aigv1a1.A2ARoute{ObjectMeta: metav1.ObjectMeta{Name: "my-agent-route", Namespace: "default"}}
	require.Equal(t, "default/my-agent-route", a2aRouteHeaderValue(route))
	require.Equal(t, gwapiv1.ObjectName(internalapi.A2ACardConfigMapPrefix+"my-agent-route"), a2aCardFilterName("my-agent-route"))
	require.Equal(t, internalapi.A2ACardConfigMapPrefix+"my-agent-route", a2aCardConfigMapName("my-agent-route"))
}

// --- test helpers ---

func requireNewFakeClientForA2A(t *testing.T) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(Scheme).
		WithStatusSubresource(&aigv1a1.A2ARoute{}).
		Build()
}

func requireAccepted(t *testing.T, route *aigv1a1.A2ARoute) {
	t.Helper()
	require.NotEmpty(t, route.Status.Conditions)
	last := route.Status.Conditions[len(route.Status.Conditions)-1]
	require.Equal(t, aigv1a1.A2AConditionTypeAccepted, last.Type)
	require.Equal(t, metav1.ConditionTrue, last.Status)
}

func requireConditionAbsent(t *testing.T, route *aigv1a1.A2ARoute, conditionType string) {
	t.Helper()
	for _, cond := range route.Status.Conditions {
		require.NotEqual(t, conditionType, cond.Type, "unexpected condition %q", conditionType)
	}
}

func requireA2ARouteHeader(t *testing.T, rule gwapiv1.HTTPRouteRule, wantValue string) {
	t.Helper()
	require.Len(t, rule.Filters, 1)
	require.Equal(t, gwapiv1.HTTPRouteFilterRequestHeaderModifier, rule.Filters[0].Type)
	require.NotNil(t, rule.Filters[0].RequestHeaderModifier)
	require.Len(t, rule.Filters[0].RequestHeaderModifier.Set, 1)
	require.Equal(t, gwapiv1.HTTPHeaderName(internalapi.A2ARouteHeader), rule.Filters[0].RequestHeaderModifier.Set[0].Name)
	require.Equal(t, wantValue, rule.Filters[0].RequestHeaderModifier.Set[0].Value)
}

// TestFetchAgentCard_EGBackend pins that the AgentCard is fetched from the Envoy Gateway
// Backend CR's FQDN endpoint (not a corev1 Service) and its URLs are rewritten to the public base.
func TestFetchAgentCard_EGBackend(t *testing.T) {
	fakeClient := requireNewFakeClientForA2A(t)
	c := NewA2ARouteController(fakeClient, fakekube.NewClientset(), ctrl.Log, make(chan event.GenericEvent, 1))

	// Serve a card on the well-known canonical path.
	cardJSON := `{"name":"agent","url":"http://agent.default.svc.cluster.local/a2a","supportedInterfaces":[{"url":"http://agent.default.svc.cluster.local/a2a"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/.well-known/agent-card.json", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(cardJSON))
	}))
	defer srv.Close()
	// httptest serves at http://127.0.0.1:<port>. The Backend FQDN splits host and port;
	// the connector rebuilds http://<host>:<port> so the fetch hits the test server.
	parsed, err := url.Parse(srv.URL)
	require.NoError(t, err)
	agentHost := parsed.Hostname()
	agentPort, err := strconv.Atoi(parsed.Port())
	require.NoError(t, err)

	require.NoError(t, fakeClient.Create(t.Context(), &egv1a1.Backend{
		ObjectMeta: metav1.ObjectMeta{Name: "external-agent", Namespace: "default"},
		Spec: egv1a1.BackendSpec{Endpoints: []egv1a1.BackendEndpoint{
			// FQDN points at the httptest server so the fetch performs a real request.
			{FQDN: &egv1a1.FQDNEndpoint{Hostname: agentHost, Port: int32(agentPort)}},
		}},
	}))

	route := &aigv1a1.A2ARoute{
		ObjectMeta: metav1.ObjectMeta{Name: "r3", Namespace: "default"},
		Spec: aigv1a1.A2ARouteSpec{
			ParentRefs: []gwapiv1.ParentReference{{Name: "mygw"}},
			BackendRefs: []gwapiv1.BackendObjectReference{
				{Group: ptr.To(gwapiv1.Group(egv1a1.GroupName)), Kind: ptr.To(gwapiv1.Kind(egv1a1.KindBackend)), Name: "external-agent"},
			},
			AgentCard: &aigv1a1.AgentCardConfig{Serve: ptr.To(true), PublicURL: ptr.To("https://aigw.example.com/a2a")},
		},
	}
	card, err := c.fetchAgentCard(t.Context(), route)
	require.NoError(t, err)

	var rewritten map[string]any
	require.NoError(t, json.Unmarshal(card, &rewritten))
	require.Equal(t, "https://aigw.example.com/a2a", rewritten["url"])
	si := rewritten["supportedInterfaces"].([]any)[0].(map[string]any)
	require.Equal(t, "https://aigw.example.com/a2a", si["url"])
}

// TestFetchAgentCard_RejectsNonBackendRef verifies a non-Backend backendRef fails card fetching
// (and, via requireA2ABackendRef, is rejected at reconcile).
func TestFetchAgentCard_RejectsNonBackendRef(t *testing.T) {
	fakeClient := requireNewFakeClientForA2A(t)
	c := NewA2ARouteController(fakeClient, fakekube.NewClientset(), ctrl.Log, make(chan event.GenericEvent, 1))

	// A Service ref (nil group, kind Service) is not permitted.
	serviceRef := &gwapiv1.BackendObjectReference{Kind: ptr.To(gwapiv1.Kind("Service")), Name: "my-agent"}
	require.Error(t, requireA2ABackendRef(serviceRef))

	// A Backend ref with no FQDN endpoint errors card fetch via a2aBackendConnector.
	require.NoError(t, fakeClient.Create(t.Context(), &egv1a1.Backend{
		ObjectMeta: metav1.ObjectMeta{Name: "no-fqdn", Namespace: "default"},
		// No endpoints → no FQDN → connector resolution fails.
	}))
	route := &aigv1a1.A2ARoute{
		ObjectMeta: metav1.ObjectMeta{Name: "r4", Namespace: "default"},
		Spec: aigv1a1.A2ARouteSpec{
			BackendRefs: []gwapiv1.BackendObjectReference{
				{Group: ptr.To(gwapiv1.Group(egv1a1.GroupName)), Kind: ptr.To(gwapiv1.Kind(egv1a1.KindBackend)), Name: "no-fqdn"},
			},
			AgentCard: &aigv1a1.AgentCardConfig{Serve: ptr.To(true)},
		},
	}
	_, err := c.fetchAgentCard(t.Context(), route)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no FQDN endpoint")
}
