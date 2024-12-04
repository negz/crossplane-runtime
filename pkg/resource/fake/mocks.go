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

// Package fake provides fake Crossplane resources for use in tests.
//
//nolint:musttag // We only use JSON to round-trip convert these mocks.
package fake

import (
	"encoding/json"
	"reflect"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

// Conditioned is a mock that implements Conditioned interface.
type Conditioned struct{ Conditions []xpv1.Condition }

// SetConditions sets the Conditions.
func (m *Conditioned) SetConditions(c ...xpv1.Condition) { m.Conditions = c }

// GetCondition get the Condition with the given ConditionType.
func (m *Conditioned) GetCondition(ct xpv1.ConditionType) xpv1.Condition {
	return xpv1.Condition{Type: ct, Status: corev1.ConditionUnknown}
}

// ManagedResourceReferencer is a mock that implements ManagedResourceReferencer interface.
type ManagedResourceReferencer struct{ Ref *corev1.ObjectReference }

// SetResourceReference sets the ResourceReference.
func (m *ManagedResourceReferencer) SetResourceReference(r *corev1.ObjectReference) { m.Ref = r }

// GetResourceReference gets the ResourceReference.
func (m *ManagedResourceReferencer) GetResourceReference() *corev1.ObjectReference { return m.Ref }

// ProviderConfigReferencer is a mock that implements ProviderConfigReferencer interface.
type ProviderConfigReferencer struct{ Ref *xpv1.Reference }

// SetProviderConfigReference sets the ProviderConfigReference.
func (m *ProviderConfigReferencer) SetProviderConfigReference(p *xpv1.Reference) { m.Ref = p }

// GetProviderConfigReference gets the ProviderConfigReference.
func (m *ProviderConfigReferencer) GetProviderConfigReference() *xpv1.Reference { return m.Ref }

// RequiredProviderConfigReferencer is a mock that implements the
// RequiredProviderConfigReferencer interface.
type RequiredProviderConfigReferencer struct{ Ref xpv1.Reference }

// SetProviderConfigReference sets the ProviderConfigReference.
func (m *RequiredProviderConfigReferencer) SetProviderConfigReference(p xpv1.Reference) {
	m.Ref = p
}

// GetProviderConfigReference gets the ProviderConfigReference.
func (m *RequiredProviderConfigReferencer) GetProviderConfigReference() xpv1.Reference {
	return m.Ref
}

// RequiredTypedResourceReferencer is a mock that implements the
// RequiredTypedResourceReferencer interface.
type RequiredTypedResourceReferencer struct{ Ref xpv1.TypedReference }

// SetResourceReference sets the ResourceReference.
func (m *RequiredTypedResourceReferencer) SetResourceReference(p xpv1.TypedReference) {
	m.Ref = p
}

// GetResourceReference gets the ResourceReference.
func (m *RequiredTypedResourceReferencer) GetResourceReference() xpv1.TypedReference {
	return m.Ref
}

// ConnectionDetailsPublisherTo is a mock that implements ConnectionDetailsPublisherTo interface.
type ConnectionDetailsPublisherTo struct {
	To *xpv1.PublishConnectionDetailsTo
}

// SetPublishConnectionDetailsTo sets the PublishConnectionDetailsTo.
func (m *ConnectionDetailsPublisherTo) SetPublishConnectionDetailsTo(to *xpv1.PublishConnectionDetailsTo) {
	m.To = to
}

// GetPublishConnectionDetailsTo gets the PublishConnectionDetailsTo.
func (m *ConnectionDetailsPublisherTo) GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo {
	return m.To
}

// Manageable implements the Manageable interface.
type Manageable struct{ Policy xpv1.ManagementPolicies }

// SetManagementPolicies sets the ManagementPolicies.
func (m *Manageable) SetManagementPolicies(p xpv1.ManagementPolicies) { m.Policy = p }

// GetManagementPolicies gets the ManagementPolicies.
func (m *Manageable) GetManagementPolicies() xpv1.ManagementPolicies { return m.Policy }

// ConnectionDetailsLastPublishedTimer is a mock that implements the
// ConnectionDetailsLastPublishedTimer interface.
type ConnectionDetailsLastPublishedTimer struct {
	// NOTE: runtime.DefaultUnstructuredConverter.ToUnstructured
	// cannot currently handle if `Time` is nil here.
	// The `omitempty` json tag is a workaround that
	// prevents a panic.
	Time *metav1.Time `json:"lastPublishedTime,omitempty"`
}

// SetConnectionDetailsLastPublishedTime sets the published time.
func (c *ConnectionDetailsLastPublishedTimer) SetConnectionDetailsLastPublishedTime(t *metav1.Time) {
	c.Time = t
}

// GetConnectionDetailsLastPublishedTime gets the published time.
func (c *ConnectionDetailsLastPublishedTimer) GetConnectionDetailsLastPublishedTime() *metav1.Time {
	return c.Time
}

// UserCounter is a mock that satisfies UserCounter
// interface.
type UserCounter struct{ Users int64 }

// SetUsers sets the count of users.
func (m *UserCounter) SetUsers(i int64) {
	m.Users = i
}

// GetUsers gets the count of users.
func (m *UserCounter) GetUsers() int64 {
	return m.Users
}

// Object is a mock that implements Object interface.
type Object struct {
	metav1.ObjectMeta
	runtime.Object
}

// GetObjectKind returns schema.ObjectKind.
func (o *Object) GetObjectKind() schema.ObjectKind {
	return schema.EmptyObjectKind
}

// DeepCopyObject returns a copy of the object as runtime.Object.
func (o *Object) DeepCopyObject() runtime.Object {
	out := &Object{}
	j, err := json.Marshal(o)
	if err != nil {
		panic(err)
	}
	_ = json.Unmarshal(j, out)
	return out
}

// Managed is a mock that implements Managed interface.
type Managed struct {
	metav1.ObjectMeta
	ProviderConfigReferencer
	ConnectionDetailsPublisherTo
	Manageable
	xpv1.ConditionedStatus
}

// GetObjectKind returns schema.ObjectKind.
func (m *Managed) GetObjectKind() schema.ObjectKind {
	return schema.EmptyObjectKind
}

// DeepCopyObject returns a copy of the object as runtime.Object.
func (m *Managed) DeepCopyObject() runtime.Object {
	out := &Managed{}
	j, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	_ = json.Unmarshal(j, out)
	return out
}

// Manager is a mock object that satisfies manager.Manager interface.
type Manager struct {
	manager.Manager

	Cache      cache.Cache
	Client     client.Client
	Scheme     *runtime.Scheme
	Config     *rest.Config
	RESTMapper meta.RESTMapper
	Logger     logr.Logger
}

// Elected returns a closed channel.
func (m *Manager) Elected() <-chan struct{} {
	e := make(chan struct{})
	close(e)
	return e
}

// GetCache returns the cache.
func (m *Manager) GetCache() cache.Cache { return m.Cache }

// GetClient returns the client.
func (m *Manager) GetClient() client.Client { return m.Client }

// GetScheme returns the scheme.
func (m *Manager) GetScheme() *runtime.Scheme { return m.Scheme }

// GetConfig returns the config.
func (m *Manager) GetConfig() *rest.Config { return m.Config }

// GetRESTMapper returns the REST mapper.
func (m *Manager) GetRESTMapper() meta.RESTMapper { return m.RESTMapper }

// GetLogger returns the logger.
func (m *Manager) GetLogger() logr.Logger { return m.Logger }

// GV returns a mock schema.GroupVersion.
var GV = schema.GroupVersion{Group: "g", Version: "v"} //nolint:gochecknoglobals // We treat this as a constant.

// GVK returns the mock GVK of the given object.
func GVK(o runtime.Object) schema.GroupVersionKind {
	return GV.WithKind(reflect.TypeOf(o).Elem().Name())
}

// SchemeWith returns a scheme with list of `runtime.Object`s registered.
func SchemeWith(o ...runtime.Object) *runtime.Scheme {
	s := runtime.NewScheme()
	s.AddKnownTypes(GV, o...)
	return s
}

// MockConnectionSecretOwner is a mock object that satisfies ConnectionSecretOwner
// interface.
type MockConnectionSecretOwner struct {
	runtime.Object
	metav1.ObjectMeta

	To       *xpv1.PublishConnectionDetailsTo
	WriterTo *xpv1.SecretReference
}

// GetPublishConnectionDetailsTo returns the publish connection details to reference.
func (m *MockConnectionSecretOwner) GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo {
	return m.To
}

// SetPublishConnectionDetailsTo sets the publish connection details to reference.
func (m *MockConnectionSecretOwner) SetPublishConnectionDetailsTo(t *xpv1.PublishConnectionDetailsTo) {
	m.To = t
}

// GetWriteConnectionSecretToReference returns the connection secret reference.
func (m *MockConnectionSecretOwner) GetWriteConnectionSecretToReference() *xpv1.SecretReference {
	return m.WriterTo
}

// SetWriteConnectionSecretToReference sets the connection secret reference.
func (m *MockConnectionSecretOwner) SetWriteConnectionSecretToReference(r *xpv1.SecretReference) {
	m.WriterTo = r
}

// GetObjectKind returns schema.ObjectKind.
func (m *MockConnectionSecretOwner) GetObjectKind() schema.ObjectKind {
	return schema.EmptyObjectKind
}

// DeepCopyObject returns a copy of the object as runtime.Object.
func (m *MockConnectionSecretOwner) DeepCopyObject() runtime.Object {
	out := &MockConnectionSecretOwner{}
	j, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	_ = json.Unmarshal(j, out)
	return out
}

// MockLocalConnectionSecretOwner is a mock object that satisfies LocalConnectionSecretOwner
// interface.
type MockLocalConnectionSecretOwner struct {
	runtime.Object
	metav1.ObjectMeta

	Ref *xpv1.LocalSecretReference
	To  *xpv1.PublishConnectionDetailsTo
}

// GetWriteConnectionSecretToReference returns the connection secret reference.
func (m *MockLocalConnectionSecretOwner) GetWriteConnectionSecretToReference() *xpv1.LocalSecretReference {
	return m.Ref
}

// SetWriteConnectionSecretToReference sets the connection secret reference.
func (m *MockLocalConnectionSecretOwner) SetWriteConnectionSecretToReference(r *xpv1.LocalSecretReference) {
	m.Ref = r
}

// SetPublishConnectionDetailsTo sets the publish connectionDetails to.
func (m *MockLocalConnectionSecretOwner) SetPublishConnectionDetailsTo(r *xpv1.PublishConnectionDetailsTo) {
	m.To = r
}

// GetPublishConnectionDetailsTo returns the publish connectionDetails to.
func (m *MockLocalConnectionSecretOwner) GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo {
	return m.To
}

// GetObjectKind returns schema.ObjectKind.
func (m *MockLocalConnectionSecretOwner) GetObjectKind() schema.ObjectKind {
	return schema.EmptyObjectKind
}

// DeepCopyObject returns a copy of the object as runtime.Object.
func (m *MockLocalConnectionSecretOwner) DeepCopyObject() runtime.Object {
	out := &MockLocalConnectionSecretOwner{}
	j, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	_ = json.Unmarshal(j, out)
	return out
}

// ProviderConfig is a mock implementation of the ProviderConfig interface.
type ProviderConfig struct {
	metav1.ObjectMeta

	UserCounter
	xpv1.ConditionedStatus
}

// GetObjectKind returns schema.ObjectKind.
func (p *ProviderConfig) GetObjectKind() schema.ObjectKind {
	return schema.EmptyObjectKind
}

// DeepCopyObject returns a copy of the object as runtime.Object.
func (p *ProviderConfig) DeepCopyObject() runtime.Object {
	out := &ProviderConfig{}
	j, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	_ = json.Unmarshal(j, out)
	return out
}

// ProviderConfigUsage is a mock implementation of the ProviderConfigUsage
// interface.
type ProviderConfigUsage struct {
	metav1.ObjectMeta

	RequiredProviderConfigReferencer
	RequiredTypedResourceReferencer
}

// GetObjectKind returns schema.ObjectKind.
func (p *ProviderConfigUsage) GetObjectKind() schema.ObjectKind {
	return schema.EmptyObjectKind
}

// DeepCopyObject returns a copy of the object as runtime.Object.
func (p *ProviderConfigUsage) DeepCopyObject() runtime.Object {
	out := &ProviderConfigUsage{}
	j, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	_ = json.Unmarshal(j, out)
	return out
}
