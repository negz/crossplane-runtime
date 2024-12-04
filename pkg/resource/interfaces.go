/*
Copyright 2019 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package resource

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

// A Conditioned may have conditions set or retrieved. Conditions are typically
// indicate the status of both a resource and its reconciliation process.
type Conditioned interface {
	SetConditions(c ...xpv1.Condition)
	GetCondition(ct xpv1.ConditionType) xpv1.Condition
}

// A ManagedResourceReferencer may reference a concrete managed resource.
type ManagedResourceReferencer interface {
	SetResourceReference(r *corev1.ObjectReference)
	GetResourceReference() *corev1.ObjectReference
}

// A LocalConnectionSecretWriterTo may write a connection secret to its own
// namespace.
type LocalConnectionSecretWriterTo interface {
	SetWriteConnectionSecretToReference(r *xpv1.LocalSecretReference)
	GetWriteConnectionSecretToReference() *xpv1.LocalSecretReference
}

// A ConnectionSecretWriterTo may write a connection secret to an arbitrary
// namespace.
type ConnectionSecretWriterTo interface {
	SetWriteConnectionSecretToReference(r *xpv1.SecretReference)
	GetWriteConnectionSecretToReference() *xpv1.SecretReference
}

// A ConnectionDetailsPublisherTo may write a connection details secret to a
// secret store.
type ConnectionDetailsPublisherTo interface {
	SetPublishConnectionDetailsTo(r *xpv1.PublishConnectionDetailsTo)
	GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo
}

// TODO(negz): SetManagementPolicies should take variadic args.

// A Manageable resource may specify a ManagementPolicies.
type Manageable interface {
	SetManagementPolicies(p xpv1.ManagementPolicies)
	GetManagementPolicies() xpv1.ManagementPolicies
}

// A ProviderConfigReferencer may reference a provider config resource.
type ProviderConfigReferencer interface {
	GetProviderConfigReference() *xpv1.Reference
	SetProviderConfigReference(p *xpv1.Reference)
}

// A RequiredProviderConfigReferencer may reference a provider config resource.
// Unlike ProviderConfigReferencer, the reference is required (i.e. not nil).
type RequiredProviderConfigReferencer interface {
	GetProviderConfigReference() xpv1.Reference
	SetProviderConfigReference(p xpv1.Reference)
}

// A RequiredTypedResourceReferencer can reference a resource.
type RequiredTypedResourceReferencer interface {
	SetResourceReference(r xpv1.TypedReference)
	GetResourceReference() xpv1.TypedReference
}

// A Finalizer manages the finalizers on the resource.
type Finalizer interface {
	AddFinalizer(ctx context.Context, obj Object) error
	RemoveFinalizer(ctx context.Context, obj Object) error
}

// A UserCounter can count how many users it has.
type UserCounter interface {
	SetUsers(i int64)
	GetUsers() int64
}

// A ConnectionDetailsPublishedTimer can record the last time its connection
// details were published.
type ConnectionDetailsPublishedTimer interface {
	SetConnectionDetailsLastPublishedTime(t *metav1.Time)
	GetConnectionDetailsLastPublishedTime() *metav1.Time
}

// ReconciliationObserver can track data observed by resource reconciler.
type ReconciliationObserver interface {
	SetObservedGeneration(generation int64)
	GetObservedGeneration() int64
}

// An Object is a Kubernetes object.
type Object interface {
	metav1.Object
	runtime.Object
}

// A Managed is a Kubernetes object representing a concrete managed
// resource (e.g. a CloudSQL instance).
type Managed interface {
	Object

	ProviderConfigReferencer
	ConnectionDetailsPublisherTo
	Manageable

	Conditioned
}

// A ManagedList is a list of managed resources.
type ManagedList interface {
	client.ObjectList

	// GetItems returns the list of managed resources.
	GetItems() []Managed
}

// A ProviderConfig configures a Crossplane provider.
type ProviderConfig interface {
	Object

	UserCounter
	Conditioned
}

// A ProviderConfigUsage indicates a usage of a Crossplane provider config.
type ProviderConfigUsage interface {
	Object

	RequiredProviderConfigReferencer
	RequiredTypedResourceReferencer
}

// A ProviderConfigUsageList is a list of provider config usages.
type ProviderConfigUsageList interface {
	client.ObjectList

	// GetItems returns the list of provider config usages.
	GetItems() []ProviderConfigUsage
}
