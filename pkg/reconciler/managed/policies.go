/*
Copyright 2023 The Crossplane Authors.

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

package managed

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/sets"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

// ManagementPoliciesResolver is used to perform management policy checks
// based on the management policy and if the management policy feature is enabled.
type ManagementPoliciesResolver struct {
	supportedPolicies  []sets.Set[xpv1.ManagementAction]
	managementPolicies sets.Set[xpv1.ManagementAction]
}

// A ManagementPoliciesResolverOption configures a ManagementPoliciesResolver.
type ManagementPoliciesResolverOption func(*ManagementPoliciesResolver)

// WithSupportedManagementPolicies sets the supported management policies.
func WithSupportedManagementPolicies(supportedManagementPolicies []sets.Set[xpv1.ManagementAction]) ManagementPoliciesResolverOption {
	return func(r *ManagementPoliciesResolver) {
		r.supportedPolicies = supportedManagementPolicies
	}
}

func defaultSupportedManagementPolicies() []sets.Set[xpv1.ManagementAction] {
	return []sets.Set[xpv1.ManagementAction]{
		// Default (all), the standard behaviour of crossplane in which all
		// reconciler actions are done.
		sets.New[xpv1.ManagementAction](xpv1.ManagementActionAll),
		// All actions explicitly set, the same as default.
		sets.New[xpv1.ManagementAction](xpv1.ManagementActionObserve, xpv1.ManagementActionCreate, xpv1.ManagementActionUpdate, xpv1.ManagementActionLateInitialize, xpv1.ManagementActionDelete),
		// ObserveOnly, just observe action is done, the external resource is
		// considered as read-only.
		sets.New[xpv1.ManagementAction](xpv1.ManagementActionObserve),
		// Pause, no action is being done. Alternative to setting the pause
		// annotation.
		sets.New[xpv1.ManagementAction](),
		// No LateInitialize filling in the spec.forProvider, allowing some
		// external resource fields to be managed externally.
		sets.New[xpv1.ManagementAction](xpv1.ManagementActionObserve, xpv1.ManagementActionCreate, xpv1.ManagementActionUpdate, xpv1.ManagementActionDelete),
		// No Delete, the external resource is not deleted when the managed
		// resource is deleted.
		sets.New[xpv1.ManagementAction](xpv1.ManagementActionObserve, xpv1.ManagementActionCreate, xpv1.ManagementActionUpdate, xpv1.ManagementActionLateInitialize),
		// No Delete and no LateInitialize, the external resource is not deleted
		// when the managed resource is deleted and the spec.forProvider is not
		// late initialized.
		sets.New[xpv1.ManagementAction](xpv1.ManagementActionObserve, xpv1.ManagementActionCreate, xpv1.ManagementActionUpdate),
		// No Update, the external resource is not updated when the managed
		// resource is updated. Useful for immutable external resources.
		sets.New[xpv1.ManagementAction](xpv1.ManagementActionObserve, xpv1.ManagementActionCreate, xpv1.ManagementActionDelete, xpv1.ManagementActionLateInitialize),
		// No Update and no Delete, the external resource is not updated
		// when the managed resource is updated and the external resource
		// is not deleted when the managed resource is deleted.
		sets.New[xpv1.ManagementAction](xpv1.ManagementActionObserve, xpv1.ManagementActionCreate, xpv1.ManagementActionLateInitialize),
		// No Update and no LateInitialize, the external resource is not updated
		// when the managed resource is updated and the spec.forProvider is not
		// late initialized.
		sets.New[xpv1.ManagementAction](xpv1.ManagementActionObserve, xpv1.ManagementActionCreate, xpv1.ManagementActionDelete),
		// No Update, no Delete and no LateInitialize, the external resource is
		// not updated when the managed resource is updated, the external resource
		// is not deleted when the managed resource is deleted and the
		// spec.forProvider is not late initialized.
		sets.New[xpv1.ManagementAction](xpv1.ManagementActionObserve, xpv1.ManagementActionCreate),
		// Like ObserveOnly, but the external resource is deleted when the
		// managed resource is deleted.
		sets.New[xpv1.ManagementAction](xpv1.ManagementActionObserve, xpv1.ManagementActionDelete),
		// No Crate and no Delete. Just update/patch the external resource.
		// Useful when the same external resource is managed by multiple
		// managed resources.
		sets.New[xpv1.ManagementAction](xpv1.ManagementActionObserve, xpv1.ManagementActionUpdate),
	}
}

// NewManagementPoliciesResolver returns an ManagementPolicyChecker based
// on the management policies and if the management policies feature
// is enabled.
func NewManagementPoliciesResolver(pols xpv1.ManagementPolicies, o ...ManagementPoliciesResolverOption) ManagementPoliciesChecker {
	r := &ManagementPoliciesResolver{
		supportedPolicies:  defaultSupportedManagementPolicies(),
		managementPolicies: sets.New[xpv1.ManagementAction](pols...),
	}

	for _, ro := range o {
		ro(r)
	}

	return r
}

// Validate checks if the management policy is valid.
// If the management policy feature is disabled, but uses a non-default value,
// it returns an error.
// If the management policy feature is enabled, but uses a non-supported value,
// it returns an error.
func (m *ManagementPoliciesResolver) Validate() error {
	// check if the policy is a non-supported combination
	for _, p := range m.supportedPolicies {
		if p.Equal(m.managementPolicies) {
			return nil
		}
	}
	return fmt.Errorf(errFmtManagementPolicyNotSupported, m.managementPolicies.UnsortedList())
}

// IsPaused returns true if the management policy is empty.
func (m *ManagementPoliciesResolver) IsPaused() bool {
	return m.managementPolicies.Len() == 0
}

// ShouldCreate returns true if the Create action is allowed.
func (m *ManagementPoliciesResolver) ShouldCreate() bool {
	return m.managementPolicies.HasAny(xpv1.ManagementActionCreate, xpv1.ManagementActionAll)
}

// ShouldUpdate returns true if the Update action is allowed.
func (m *ManagementPoliciesResolver) ShouldUpdate() bool {
	return m.managementPolicies.HasAny(xpv1.ManagementActionUpdate, xpv1.ManagementActionAll)
}

// ShouldLateInitialize returns true if the LateInitialize action is allowed.
func (m *ManagementPoliciesResolver) ShouldLateInitialize() bool {
	return m.managementPolicies.HasAny(xpv1.ManagementActionLateInitialize, xpv1.ManagementActionAll)
}

// ShouldOnlyObserve returns true if the Observe action is allowed and all
// other actions are not allowed.
func (m *ManagementPoliciesResolver) ShouldOnlyObserve() bool {
	return m.managementPolicies.Equal(sets.New(xpv1.ManagementActionObserve))
}

// ShouldDelete returns true if the Delete action is allowed.
func (m *ManagementPoliciesResolver) ShouldDelete() bool {
	return m.managementPolicies.HasAny(xpv1.ManagementActionDelete, xpv1.ManagementActionAll)
}
