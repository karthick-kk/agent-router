// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlutil "sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	aigv1a1 "github.com/envoyproxy/ai-gateway/api/v1alpha1"
	"github.com/envoyproxy/ai-gateway/internal/internalapi"
)

const (
	defaultA2APath               = "/a2a"
	defaultA2ACardPath           = "/.well-known/agent-card.json"
	legacyA2ACardPath            = "/.well-known/agent.json"
	defaultA2AMaxRequestBodySize = "1Mi"

	// a2aCardBodyKey is the ConfigMap key the Envoy Gateway DirectResponse filter reads when
	// body.type is ValueRef (falls back to the first value if absent).
	a2aCardBodyKey = "response.body"

	// a2aCardRefreshInterval is how often a successfully fetched AgentCard is re-fetched.
	a2aCardRefreshInterval = 15 * time.Minute
	// a2aCardRetryInterval is how quickly a failed card fetch is retried.
	a2aCardRetryInterval = 30 * time.Second

	// a2aCardRuleName / a2aRPCRuleName are the generated HTTPRoute rule names. The extension
	// server and SecurityPolicy sectionName targeting rely on the stable "rpc" name.
	a2aCardRuleName = "agent-card"
	a2aRPCRuleName  = "rpc"

	a2aCardContentType = "application/json"
)

// A2ARouteController implements [reconcile.TypedReconciler].
//
// It handles the A2ARoute resource and generates the HTTPRoute (plus the AgentCard
// HTTPRouteFilter and ConfigMap) that the extension server turns into the A2A backend
// listener data plane.
//
// Exported for testing purposes.
type A2ARouteController struct {
	client client.Client
	kube   kubernetes.Interface
	logger logr.Logger
	// gatewayEventChan is a channel to send events to the gateway controller.
	gatewayEventChan chan event.GenericEvent
}

// NewA2ARouteController creates a new reconcile.TypedReconciler[reconcile.Request] for the A2ARoute resource.
func NewA2ARouteController(
	client client.Client, kube kubernetes.Interface, logger logr.Logger,
	gatewayEventChan chan event.GenericEvent,
) *A2ARouteController {
	return &A2ARouteController{
		client:           client,
		kube:             kube,
		logger:           logger,
		gatewayEventChan: gatewayEventChan,
	}
}

// Reconcile implements [reconcile.TypedReconciler].
func (c *A2ARouteController) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	c.logger.Info("Reconciling A2ARoute", "namespace", req.Namespace, "name", req.Name)

	var a2aRoute aigv1a1.A2ARoute
	if err := c.client.Get(ctx, req.NamespacedName, &a2aRoute); err != nil {
		if client.IgnoreNotFound(err) == nil {
			c.logger.Info("Deleting A2ARoute",
				"namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	cardFetchFailed := true
	if cardReady, err := c.syncA2ARoute(ctx, &a2aRoute); err != nil {
		c.logger.Error(err, "failed to sync A2ARoute")
		c.updateA2ARouteStatus(ctx, &a2aRoute, aigv1a1.A2AConditionTypeNotAccepted, err.Error(), false)
		return ctrl.Result{}, err
	} else {
		cardFetchFailed = !cardReady
	}
	c.updateA2ARouteStatus(ctx, &a2aRoute, aigv1a1.A2AConditionTypeAccepted, "A2A route reconciled successfully", !cardFetchFailed && c.cardServingEnabled(&a2aRoute))

	// Re-fetch quickly while the card fetch fails, otherwise on the normal interval.
	interval := a2aCardRefreshInterval
	if cardFetchFailed {
		interval = a2aCardRetryInterval
	}
	if c.cardServingEnabled(&a2aRoute) {
		return reconcile.Result{RequeueAfter: interval}, nil
	}
	return reconcile.Result{}, nil
}

func (c *A2ARouteController) cardServingEnabled(route *aigv1a1.A2ARoute) bool {
	cfg := route.Spec.AgentCard
	return cfg == nil || ptr.Deref(cfg.Serve, true)
}

// syncA2ARoute holds the reconcile logic so error handling and status updates stay in one
// place. It returns cardReady so the caller can set the CardReady condition and requeue
// quickly on fetch failure.
func (c *A2ARouteController) syncA2ARoute(ctx context.Context, route *aigv1a1.A2ARoute) (bool, error) {
	// On deletion, propagate to the referenced Gateways. The generated HTTPRoute,
	// HTTPRouteFilter, and card ConfigMap are controller-owned, so garbage collection
	// removes them without explicit cleanup.
	if handleFinalizer(ctx, c.client, c.logger, route, c.onA2ARouteDeleted) {
		return false, nil
	}

	c.logger.Info("Syncing A2ARoute", "namespace", route.Namespace, "name", route.Name)

	cardReady, err := c.syncAgentCard(ctx, route)
	if err != nil {
		// A card fetch failure is not fatal: the route is served (pass-through when no card
		// was ever fetched) and the CardReady condition reflects the failure.
		c.logger.Error(err, "failed to fetch AgentCard, continuing with last-known or pass-through card")
	}

	mainHTTPRouteName := internalapi.A2AMainHTTPRoutePrefix + route.Name
	httpRoute, existing, err := c.getOrNewA2AHTTPRoute(ctx, route, mainHTTPRouteName)
	if err != nil {
		return false, fmt.Errorf("failed to get or create HTTPRoute: %w", err)
	}
	if err = c.newA2AMainHTTPRoute(ctx, httpRoute, route, cardReady); err != nil {
		return false, fmt.Errorf("failed to construct a new HTTPRoute: %w", err)
	}
	if err = c.createOrUpdateA2AHTTPRoute(ctx, httpRoute, existing); err != nil {
		return false, fmt.Errorf("failed to create or update HTTPRoute: %w", err)
	}

	if err = c.syncGateways(ctx, route); err != nil {
		return false, fmt.Errorf("failed to sync gw pods: %w", err)
	}
	return cardReady, nil
}

// onA2ARouteDeleted is the finalizer callback for the A2ARoute resource.
func (c *A2ARouteController) onA2ARouteDeleted(ctx context.Context, route *aigv1a1.A2ARoute) error {
	return c.syncGateways(ctx, route)
}

func (c *A2ARouteController) createOrUpdateA2AHTTPRoute(ctx context.Context, httpRoute *gwapiv1.HTTPRoute, update bool) error {
	if update {
		c.logger.Info("Updating HTTPRoute", "namespace", httpRoute.Namespace, "name", httpRoute.Name)
		if err := c.client.Update(ctx, httpRoute); err != nil {
			return fmt.Errorf("failed to update HTTPRoute: %w", err)
		}
	} else {
		c.logger.Info("Creating HTTPRoute", "namespace", httpRoute.Namespace, "name", httpRoute.Name)
		if err := c.client.Create(ctx, httpRoute); err != nil {
			return fmt.Errorf("failed to create HTTPRoute: %w", err)
		}
	}
	return nil
}

func (c *A2ARouteController) getOrNewA2AHTTPRoute(ctx context.Context, route *aigv1a1.A2ARoute, routeName string) (*gwapiv1.HTTPRoute, bool, error) {
	httpRoute := &gwapiv1.HTTPRoute{}
	err := c.client.Get(ctx, client.ObjectKey{Name: routeName, Namespace: route.Namespace}, httpRoute)
	existing := err == nil
	if apierrors.IsNotFound(err) {
		httpRoute = &gwapiv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:        routeName,
				Namespace:   route.Namespace,
				Labels:      make(map[string]string),
				Annotations: make(map[string]string),
			},
			Spec: gwapiv1.HTTPRouteSpec{},
		}
		for k, v := range route.Labels {
			httpRoute.Labels[k] = v
		}
		for k, v := range route.Annotations {
			httpRoute.Annotations[k] = v
		}
		if err := ctrlutil.SetControllerReference(route, httpRoute, c.client.Scheme()); err != nil {
			return nil, false, fmt.Errorf("failed to set controller reference for HTTPRoute: %w", err)
		}
	} else if err != nil {
		return nil, false, fmt.Errorf("failed to get HTTPRoute: %w", err)
	}
	return httpRoute, existing, nil
}

// newA2AMainHTTPRoute updates the main HTTPRoute with the A2ARoute. The route carries two
// named rules:
//
//   - "agent-card": GET on the well-known card paths. Served by a DirectResponse
//     HTTPRouteFilter (body = rewritten card from the card ConfigMap) when card serving is
//     enabled and a card has been fetched; otherwise it passes through to the agent backend.
//     The card GET never reaches the a2a filter on the backend listener.
//   - "rpc": POST on the route path, forwarded to the agent backend. The extension server
//     rewrites this rule's cluster to the A2A backend listener and moves the SecurityPolicy
//     RBAC per-route config there so authz evaluates after the a2a filter.
func (c *A2ARouteController) newA2AMainHTTPRoute(ctx context.Context, dst *gwapiv1.HTTPRoute, route *aigv1a1.A2ARoute, cardReady bool) error {
	servingPath := ptr.Deref(route.Spec.Path, defaultA2APath)
	backendRefs := make([]gwapiv1.HTTPBackendRef, 0, len(route.Spec.BackendRefs))
	for i := range route.Spec.BackendRefs {
		ref := &route.Spec.BackendRefs[i]
		if ns := ref.Namespace; ns != nil && *ns != gwapiv1.Namespace(route.Namespace) {
			return fmt.Errorf("cross-namespace backend reference is not supported: backend %s/%s in A2ARoute %s/%s",
				*ns, ref.Name, route.Namespace, route.Name)
		}
		if err := requireA2ABackendRef(ref); err != nil {
			return err
		}
		backendRefs = append(backendRefs, gwapiv1.HTTPBackendRef{BackendRef: gwapiv1.BackendRef{BackendObjectReference: *ref}})
	}

	// rpc rule: POST <path> -> agent backend, with streaming-aware timeouts.
	streaming := ptr.Deref(route.Spec.Streaming, true)
	rpcRule := gwapiv1.HTTPRouteRule{
		Name: ptr.To(gwapiv1.SectionName(a2aRPCRuleName)),
		Matches: []gwapiv1.HTTPRouteMatch{
			{
				Method: ptr.To(gwapiv1.HTTPMethodPost),
				Path: &gwapiv1.HTTPPathMatch{
					Type:  ptr.To(gwapiv1.PathMatchPathPrefix),
					Value: ptr.To(servingPath),
				},
			},
		},
		BackendRefs: backendRefs,
	}
	if streaming {
		// Envoy zeroes both the route and idle timeouts for request timeout 0s, so SSE
		// streams are not cut by the 15s default (verified on the EG fork).
		rpcRule.Timeouts = &gwapiv1.HTTPRouteTimeouts{
			Request: ptr.To(gwapiv1.Duration("0s")),
		}
	} else {
		rpcRule.Timeouts = &gwapiv1.HTTPRouteTimeouts{
			Request:        ptr.To(gwapiv1.Duration("30m")),
			BackendRequest: ptr.To(gwapiv1.Duration("30m")),
		}
	}
	// Set the A2A route identity header on the rpc rule. The extension server uses the
	// presence of this header in the generated xDS route to identify the A2A rpc route
	// (as opposed to the agent-card rule) without depending on rule ordering, mirroring
	// how MCPRoute tags its route with MCPRouteHeader.
	rpcRule.Filters = []gwapiv1.HTTPRouteFilter{
		{
			Type: gwapiv1.HTTPRouteFilterRequestHeaderModifier,
			RequestHeaderModifier: &gwapiv1.HTTPHeaderFilter{
				Set: []gwapiv1.HTTPHeader{
					{
						Name:  internalapi.A2ARouteHeader,
						Value: a2aRouteHeaderValue(route),
					},
				},
			},
		},
	}

	// agent-card rule: GET on the canonical and legacy well-known card paths.
	cardPaths := []string{
		strings.TrimSuffix(servingPath, "/") + defaultA2ACardPath,
		strings.TrimSuffix(servingPath, "/") + legacyA2ACardPath,
	}
	cardMatches := make([]gwapiv1.HTTPRouteMatch, 0, len(cardPaths))
	for _, p := range cardPaths {
		cardMatches = append(cardMatches, gwapiv1.HTTPRouteMatch{
			Method: ptr.To(gwapiv1.HTTPMethodGet),
			Path:   &gwapiv1.HTTPPathMatch{Type: ptr.To(gwapiv1.PathMatchExact), Value: ptr.To(p)},
		})
	}
	cardRule := gwapiv1.HTTPRouteRule{
		Name:    ptr.To(gwapiv1.SectionName(a2aCardRuleName)),
		Matches: cardMatches,
	}
	serveCard := c.cardServingEnabled(route) && cardReady
	if serveCard {
		// The gateway serves the rewritten card from the card ConfigMap.
		cardRule.Filters = []gwapiv1.HTTPRouteFilter{
			{
				Type: gwapiv1.HTTPRouteFilterExtensionRef,
				ExtensionRef: &gwapiv1.LocalObjectReference{
					Group: gwapiv1.Group("gateway.envoyproxy.io"),
					Kind:  gwapiv1.Kind("HTTPRouteFilter"),
					Name:  a2aCardFilterName(route.Name),
				},
			},
		}
	} else {
		// Passthrough card rule (card serving disabled, or no card fetched yet): the card
		// is fetched from the agent backend. The GET never reaches the a2a filter on the
		// backend listener, so it is unaffected by the filter's body handling.
		cardRule.BackendRefs = backendRefs
	}
	dst.Spec.Rules = []gwapiv1.HTTPRouteRule{cardRule, rpcRule}

	if err := c.ensureA2ACardFilterAndConfigMap(ctx, route, serveCard); err != nil {
		return fmt.Errorf("failed to ensure AgentCard HTTPRouteFilter/ConfigMap: %w", err)
	}

	// Copy the A2ARoute's metadata onto the generated HTTPRoute.
	dst.Spec.ParentRefs = route.Spec.ParentRefs
	dst.Spec.Hostnames = route.Spec.Hostnames
	return nil
}

// a2aRouteHeaderValue is the value of internalapi.A2ARouteHeader: "<namespace>/<name>".
// It identifies the owning A2ARoute on the rpc rule; the extension server matches it to
// find the A2A rpc route in the generated xDS.
func a2aRouteHeaderValue(route *aigv1a1.A2ARoute) string {
	return route.Namespace + "/" + route.Name
}

func a2aCardFilterName(routeName string) gwapiv1.ObjectName {
	return gwapiv1.ObjectName(internalapi.A2ACardConfigMapPrefix + routeName)
}

func a2aCardConfigMapName(routeName string) string {
	return internalapi.A2ACardConfigMapPrefix + routeName
}

// ensureA2ACardFilterAndConfigMap creates or updates the DirectResponse HTTPRouteFilter that
// serves the rewritten AgentCard, and deletes it when card serving is no longer active. The
// card ConfigMap itself is created by syncAgentCard.
func (c *A2ARouteController) ensureA2ACardFilterAndConfigMap(ctx context.Context, route *aigv1a1.A2ARoute, serveCard bool) error {
	filter := &egv1a1.HTTPRouteFilter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      string(a2aCardFilterName(route.Name)),
			Namespace: route.Namespace,
		},
	}
	existing := c.client.Get(ctx, client.ObjectKey{Name: filter.Name, Namespace: filter.Namespace}, filter) == nil
	if !serveCard {
		if existing {
			c.logger.Info("Deleting AgentCard HTTPRouteFilter (card serving inactive)", "namespace", route.Namespace, "name", filter.Name)
			if err := c.client.Delete(ctx, filter); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("failed to delete HTTPRouteFilter %s: %w", filter.Name, err)
			}
		}
		return nil
	}
	filter.Spec = egv1a1.HTTPRouteFilterSpec{
		DirectResponse: &egv1a1.HTTPDirectResponseFilter{
			ContentType: ptr.To(a2aCardContentType),
			Body: &egv1a1.CustomResponseBody{
				Type: ptr.To(egv1a1.ResponseValueTypeValueRef),
				ValueRef: &gwapiv1.LocalObjectReference{
					Kind: gwapiv1.Kind("ConfigMap"),
					Name: gwapiv1.ObjectName(a2aCardConfigMapName(route.Name)),
				},
			},
			StatusCode: ptr.To(int(200)),
		},
	}
	if err := ctrlutil.SetControllerReference(route, filter, c.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference for HTTPRouteFilter: %w", err)
	}
	if existing {
		if err := c.client.Update(ctx, filter); err != nil {
			return fmt.Errorf("failed to update HTTPRouteFilter: %w", err)
		}
	} else {
		if err := c.client.Create(ctx, filter); err != nil {
			return fmt.Errorf("failed to create HTTPRouteFilter: %w", err)
		}
	}
	return nil
}

// syncAgentCard fetches the AgentCard from the agent backend, rewrites its endpoint URLs to
// the public gateway base, and stores the JSON in the card ConfigMap. It keeps
// the last-known card on fetch failure. It returns true when a card is available to serve
// (either freshly fetched or a last-known one).
func (c *A2ARouteController) syncAgentCard(ctx context.Context, route *aigv1a1.A2ARoute) (bool, error) {
	if !c.cardServingEnabled(route) {
		return false, nil
	}
	card, err := c.fetchAgentCard(ctx, route)
	if err != nil {
		// Keep the last-known card (if any) and report CardReady=False via the return value.
		existing := &corev1.ConfigMap{}
		getErr := c.client.Get(ctx, client.ObjectKey{Name: a2aCardConfigMapName(route.Name), Namespace: route.Namespace}, existing)
		if getErr == nil {
			c.logger.Info("AgentCard fetch failed, keeping last-known card", "namespace", route.Namespace, "name", route.Name)
			return true, err
		}
		return false, err
	}

	cardMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      a2aCardConfigMapName(route.Name),
			Namespace: route.Namespace,
		},
		Data: map[string]string{a2aCardBodyKey: string(card)},
	}
	if err := ctrlutil.SetControllerReference(route, cardMap, c.client.Scheme()); err != nil {
		return false, fmt.Errorf("failed to set controller reference for card ConfigMap: %w", err)
	}
	existing := &corev1.ConfigMap{}
	getErr := c.client.Get(ctx, client.ObjectKey{Name: cardMap.Name, Namespace: cardMap.Namespace}, existing)
	if getErr == nil {
		cardMap.ResourceVersion = existing.ResourceVersion
		if err := c.client.Update(ctx, cardMap); err != nil {
			return false, fmt.Errorf("failed to update card ConfigMap: %w", err)
		}
	} else if apierrors.IsNotFound(getErr) {
		if err := c.client.Create(ctx, cardMap); err != nil {
			return false, fmt.Errorf("failed to create card ConfigMap: %w", err)
		}
	} else {
		return false, fmt.Errorf("failed to get card ConfigMap: %w", getErr)
	}
	return true, nil
}

// fetchAgentCard fetches the AgentCard JSON from the agent backend (an Envoy Gateway Backend CR),
// rewriting its `url` and every `supportedInterfaces[].url` to the public gateway base. The
// canonical well-known path is tried first; the legacy agent.json path is the fallback.
// Only the Backend's first FQDN endpoint is used; multi-endpoint fan-out is not supported.
func (c *A2ARouteController) fetchAgentCard(ctx context.Context, route *aigv1a1.A2ARoute) ([]byte, error) {
	if len(route.Spec.BackendRefs) != 1 {
		return nil, fmt.Errorf("expected exactly one backendRef, got %d", len(route.Spec.BackendRefs))
	}
	if err := requireA2ABackendRef(&route.Spec.BackendRefs[0]); err != nil {
		return nil, err
	}
	ref := &route.Spec.BackendRefs[0]
	connector, err := c.a2aBackendConnector(ctx, route, ref)
	if err != nil {
		return nil, err
	}
	cardCfg := route.Spec.AgentCard
	cardPath := defaultA2ACardPath
	if cardCfg != nil && cardCfg.Path != nil {
		cardPath = *cardCfg.Path
	}
	legacyPath := ""
	if strings.HasSuffix(cardPath, "agent-card.json") {
		legacyPath = strings.TrimSuffix(cardPath, "agent-card.json") + "agent.json"
	}

	client := &http.Client{Timeout: 10 * time.Second}
	body, err := httpGetPath(ctx, client, connector, cardPath)
	if err != nil && legacyPath != "" && isHTTPStatusError(err, http.StatusNotFound) {
		body, err = httpGetPath(ctx, client, connector, legacyPath)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch AgentCard from %s%s: %w", connector, cardPath, err)
	}
	return rewriteAgentCardURLs(body, c.publicBase(route))
}

// a2aBackendConnector resolves the in-cluster base URL of an A2A backend referenced by an Envoy
// Gateway Backend CR (kind Backend, group gateway.envoyproxy.io). The connector is taken from the
// Backend CR's first FQDN endpoint, mirroring how MCPRoute Backend refs carry no port (the port
// lives on the endpoint).
func (c *A2ARouteController) a2aBackendConnector(ctx context.Context, route *aigv1a1.A2ARoute, ref *gwapiv1.BackendObjectReference) (string, error) {
	var backend egv1a1.Backend
	if err := c.client.Get(ctx, client.ObjectKey{Name: string(ref.Name), Namespace: route.Namespace}, &backend); err != nil {
		return "", fmt.Errorf("failed to get A2A backend %s/%s: %w", route.Namespace, ref.Name, err)
	}
	for _, ep := range backend.Spec.Endpoints {
		if ep.FQDN != nil {
			return fmt.Sprintf("http://%s:%d", ep.FQDN.Hostname, ep.FQDN.Port), nil
		}
	}
	return "", fmt.Errorf("A2A backend %s/%s has no FQDN endpoint to fetch the AgentCard from", route.Namespace, ref.Name)
}

// requireA2ABackendRef validates that a backendRef names an Envoy Gateway Backend (kind Backend,
// group gateway.envoyproxy.io) in the A2ARoute's own namespace. A2ARoutes reference backends the
// same way MCPRoute does (an EG Backend, in-cluster or external), not a corev1 Service.
func requireA2ABackendRef(ref *gwapiv1.BackendObjectReference) error {
	if ref.Group == nil || string(*ref.Group) != egv1a1.GroupName {
		return fmt.Errorf("backendRef group must be gateway.envoyproxy.io, got %s", groupDeref(ref.Group))
	}
	if ref.Kind == nil || string(*ref.Kind) != egv1a1.KindBackend {
		return fmt.Errorf("backendRef kind must be Backend, got %s", kindDeref(ref.Kind))
	}
	return nil
}

func groupDeref(g *gwapiv1.Group) string {
	if g == nil {
		return ""
	}
	return string(*g)
}

func kindDeref(k *gwapiv1.Kind) string {
	if k == nil {
		return "Service"
	}
	return string(*k)
}

// publicBase returns the public base URL the AgentCard endpoints are rewritten to: the
// explicit AgentCard.PublicURL, or https://<first hostname><path> when derived. It returns
// an empty string when it cannot be derived (no hostnames and no explicit URL), in which
// case the caller must not rewrite.
func (c *A2ARouteController) publicBase(route *aigv1a1.A2ARoute) string {
	cardCfg := route.Spec.AgentCard
	if cardCfg != nil && cardCfg.PublicURL != nil {
		return strings.TrimSuffix(*cardCfg.PublicURL, "/")
	}
	if len(route.Spec.Hostnames) > 0 {
		path := ptr.Deref(route.Spec.Path, defaultA2APath)
		return fmt.Sprintf("https://%s%s", string(route.Spec.Hostnames[0]), strings.TrimSuffix(path, "/"))
	}
	c.logger.Info("A2ARoute has no hostnames or explicit AgentCard publicUrl; card endpoints are not rewritten")
	return ""
}

func httpGetPath(ctx context.Context, client *http.Client, base, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // cards are small; cap at 4MiB
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &httpStatusError{status: resp.StatusCode}
	}
	return body, nil
}

type httpStatusError struct{ status int }

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("unexpected HTTP status %d", e.status)
}

func isHTTPStatusError(err error, status int) bool {
	if e, ok := err.(*httpStatusError); ok {
		return e.status == status
	}
	return false
}

// rewriteAgentCardURLs rewrites the top-level `url` and every `supportedInterfaces[].url`
// to the public base. A nil/empty base returns the card unchanged.
func rewriteAgentCardURLs(card []byte, publicBase string) ([]byte, error) {
	if publicBase == "" {
		return card, nil
	}
	var m map[string]any
	if err := json.Unmarshal(card, &m); err != nil {
		return nil, fmt.Errorf("AgentCard is not valid JSON: %w", err)
	}
	m["url"] = publicBase
	if sis, ok := m["supportedInterfaces"].([]any); ok {
		for _, si := range sis {
			if m2, ok := si.(map[string]any); ok {
				m2["url"] = publicBase
			}
		}
	}
	return json.Marshal(m)
}

// syncGateways synchronizes the gateways referenced by the A2ARoute by sending events to the gateway controller.
func (c *A2ARouteController) syncGateways(ctx context.Context, route *aigv1a1.A2ARoute) error {
	for _, p := range route.Spec.ParentRefs {
		gwNamespace := route.Namespace
		if p.Namespace != nil {
			gwNamespace = string(*p.Namespace)
		}
		var gw gwapiv1.Gateway
		if err := c.client.Get(ctx, client.ObjectKey{Name: string(p.Name), Namespace: gwNamespace}, &gw); err != nil {
			if apierrors.IsNotFound(err) {
				c.logger.Info("Gateway not found", "namespace", gwNamespace, "name", p.Name)
				return fmt.Errorf("gateway %s/%s not found: %w", gwNamespace, p.Name, err)
			}
			return fmt.Errorf("failed to get Gateway %s/%s: %w", gwNamespace, p.Name, err)
		}
		c.logger.Info("Syncing Gateway", "namespace", gw.Namespace, "name", gw.Name)
		c.gatewayEventChan <- event.GenericEvent{Object: &gw}
	}
	return nil
}

// updateA2ARouteStatus updates the status of the A2ARoute. The accepted condition is
// appended last because the Status printer column shows the last condition type.
func (c *A2ARouteController) updateA2ARouteStatus(ctx context.Context, route *aigv1a1.A2ARoute, conditionType, message string, cardReady bool) {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := c.client.Get(ctx, client.ObjectKey{Name: route.Name, Namespace: route.Namespace}, route); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}

		var conditions []metav1.Condition
		if c.cardServingEnabled(route) {
			status := metav1.ConditionFalse
			msg := "AgentCard is not available"
			if cardReady {
				status = metav1.ConditionTrue
				msg = "AgentCard is fetched and served by the gateway"
			}
			conditions = append(conditions, metav1.Condition{
				Type:               aigv1a1.A2AConditionTypeCardReady,
				Status:             status,
				Reason:             "CardSync",
				Message:            msg,
				LastTransitionTime: metav1.Now(),
			})
		}
		conditions = append(conditions, newConditions(conditionType, message)...)
		route.Status.Conditions = conditions
		return c.client.Status().Update(ctx, route)
	})
	if err != nil {
		c.logger.Error(err, "failed to update A2ARoute status")
	}
}
