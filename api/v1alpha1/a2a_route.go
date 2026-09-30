// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// A2ARoute defines how to route A2A (Agent2Agent) requests to a backend agent.
//
// Unlike MCPRoute (which aggregates many MCP servers behind an in-process proxy),
// an A2ARoute routes to a single backend agent referenced by an Envoy Gateway
// Backend CR (FQDN endpoint, in-cluster or external). The gateway serves the
// agent's AgentCard (with its URL rewritten to the public gateway) and forwards
// JSON-RPC task calls and SSE streams to the agent, classified and authorized by
// Envoy's native envoy.filters.http.a2a filter.
//
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.conditions[-1:].type`
type A2ARoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Spec defines the details of the A2ARoute.
	Spec A2ARouteSpec `json:"spec,omitempty"`
	// Status defines the status details of the A2ARoute.
	Status A2ARouteStatus `json:"status,omitempty"`
}

// A2ARouteList contains a list of A2ARoute.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
type A2ARouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []A2ARoute `json:"items"`
}

// A2ARouteSpec details the A2ARoute configuration.
type A2ARouteSpec struct {
	// ParentRefs are the names of the Gateway resources this A2ARoute attaches to.
	// Cross namespace references are not supported. Currently, each reference's Kind must be Gateway.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self.all(match, match.kind == 'Gateway')", message="only Gateway is supported"
	ParentRefs []gwapiv1.ParentReference `json:"parentRefs"`

	// Hostnames is a list of hostnames matched against the HTTP Host header to select this A2ARoute.
	// Equivalent to the Hostnames field in the Gateway API HTTPRouteSpec: when specified, the
	// generated HTTPRoute carries these hostnames so the A2A route lands in the per-host virtual
	// host instead of the wildcard vhost. The public URL of the served AgentCard is derived from
	// the first hostname plus Path unless AgentCard.PublicURL overrides it.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	Hostnames []gwapiv1.Hostname `json:"hostnames,omitempty"`

	// Path is the HTTP endpoint prefix that serves A2A requests.
	// The JSON-RPC endpoint is POST <Path>; the AgentCard is served at
	// <Path>/.well-known/agent-card.json (with a legacy <Path>/.well-known/agent.json fallback).
	// If not specified, the default is "/a2a".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=/a2a
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Path *string `json:"path,omitempty"`

	// BackendRefs is the single backend agent reference for this A2ARoute.
	// The reference must name an Envoy Gateway Backend CR (kind: Backend,
	// group: gateway.envoyproxy.io) whose FQDN endpoint points at the agent
	// (in-cluster or external), mirroring how MCPRoute references its backends.
	// Phase 1 supports exactly one backend (no capability-based fan-out).
	// Cross-namespace references are not supported, as for MCPRoute: the backend
	// must live in the A2ARoute's namespace.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=1
	BackendRefs []gwapiv1.BackendObjectReference `json:"backendRefs"`

	// Streaming enables SSE streaming pass-through for message/stream (SendStreamingMessage).
	// When true (the default), the generated route disables the request timeout so a long-lived
	// stream is not cut by Envoy's 15s default. When false, the route is bounded to a 30m request
	// timeout instead.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=true
	// +optional
	Streaming *bool `json:"streaming,omitempty"`

	// MaxRequestBodySize is the maximum A2A JSON-RPC request body size, mapped to the a2a filter's
	// max_request_body_size. The native filter default (8KiB) is too small for real A2A payloads,
	// so this defaults to 1Mi. Values above the filter maximum (10MiB) are rejected by Envoy.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:="1Mi"
	// +kubebuilder:validation:MaxLength=16
	// +optional
	MaxRequestBodySize *string `json:"maxRequestBodySize,omitempty"`

	// RejectNonA2A maps to the a2a filter's traffic_mode: true selects REJECT (a request that is
	// not valid A2A JSON-RPC is rejected with 400), false selects PASS_THROUGH. Defaults to true.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=true
	// +optional
	RejectNonA2A *bool `json:"rejectNonA2A,omitempty"`

	// AgentCard configures gateway-served AgentCard with URL rewriting.
	//
	// +kubebuilder:validation:Optional
	// +optional
	AgentCard *AgentCardConfig `json:"agentCard,omitempty"`
}

// AgentCardConfig configures gateway-served AgentCard with URL rewriting.
type AgentCardConfig struct {
	// Serve controls whether the gateway serves the (rewritten) AgentCard via a directResponse.
	// When true (the default), the controller fetches the card from the backend, rewrites its url
	// and supportedInterfaces[].url to the public gateway base, and serves it. When false, the card
	// request is passed through to the backend.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=true
	// +optional
	Serve *bool `json:"serve,omitempty"`

	// Path is the backend path from which the AgentCard is fetched. The canonical A2A well-known
	// path is /.well-known/agent-card.json; the legacy agent.json is tried as a fallback.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=/.well-known/agent-card.json
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Path *string `json:"path,omitempty"`

	// PublicURL is an explicit public base URL to rewrite the AgentCard's endpoints to. If
	// unspecified, it is derived from the first Hostname plus the route Path.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=uri
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	PublicURL *string `json:"publicUrl,omitempty"`
}

// A2ARouteStatus contains the conditions by the reconciliation result.
type A2ARouteStatus struct {
	// Conditions is the list of conditions by the reconciliation result.
	//
	// Known .status.conditions.type are: "Accepted", "NotAccepted", "CardReady".
	// Programmed and ResolvedRefs are reserved for the standard Gateway API conditions.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

const (
	// A2AConditionTypeAccepted is set when the A2ARoute reconciles successfully.
	A2AConditionTypeAccepted = "Accepted"
	// A2AConditionTypeNotAccepted is set when the A2ARoute fails to reconcile.
	A2AConditionTypeNotAccepted = "NotAccepted"
	// A2AConditionTypeCardReady is set when the AgentCard has been fetched from the backend and
	// is available to serve. False when the fetch is failing or has not yet succeeded.
	A2AConditionTypeCardReady = "CardReady"
	// A2AConditionTypeProgrammed is reserved for the standard Gateway API "Programmed" condition.
	A2AConditionTypeProgrammed = "Programmed"
	// A2AConditionTypeResolvedRefs is reserved for the standard Gateway API "ResolvedRefs" condition.
	A2AConditionTypeResolvedRefs = "ResolvedRefs"
)
