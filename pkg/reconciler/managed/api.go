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

package managed

import (
	"context"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane/crossplane-runtime/pkg/errors"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
)

// Error strings.
const (
	errCreateOrUpdateSecret      = "cannot create or update connection secret"
	errUpdateManaged             = "cannot update managed resource"
	errPatchManaged              = "cannot patch the managed resource via server-side apply"
	errMarshalExisting           = "cannot marshal the existing object into JSON"
	errMarshalResolved           = "cannot marshal the object with the resolved references into JSON"
	errPreparePatch              = "cannot prepare the JSON merge patch for the resolved object"
	errUpdateManagedStatus       = "cannot update managed resource status"
	errResolveReferences         = "cannot resolve references"
	errUpdateCriticalAnnotations = "cannot update critical annotations"
)

// NameAsExternalName writes the name of the managed resource to
// the external name annotation field in order to be used as name of
// the external resource in provider.
type NameAsExternalName struct{ client client.Client }

// NewNameAsExternalName returns a new NameAsExternalName.
func NewNameAsExternalName(c client.Client) *NameAsExternalName {
	return &NameAsExternalName{client: c}
}

// Initialize the given managed resource.
func (a *NameAsExternalName) Initialize(ctx context.Context, mg resource.Managed) error {
	if meta.GetExternalName(mg) != "" {
		return nil
	}
	meta.SetExternalName(mg, mg.GetName())
	return errors.Wrap(a.client.Update(ctx, mg), errUpdateManaged)
}

// A RetryingCriticalAnnotationUpdater is a CriticalAnnotationUpdater that
// retries annotation updates in the face of API server errors.
type RetryingCriticalAnnotationUpdater struct {
	client client.Client
}

// NewRetryingCriticalAnnotationUpdater returns a CriticalAnnotationUpdater that
// retries annotation updates in the face of API server errors.
func NewRetryingCriticalAnnotationUpdater(c client.Client) *RetryingCriticalAnnotationUpdater {
	return &RetryingCriticalAnnotationUpdater{client: c}
}

// UpdateCriticalAnnotations updates (i.e. persists) the annotations of the
// supplied Object. It retries in the face of any API server error several times
// in order to ensure annotations that contain critical state are persisted.
// Pending changes to the supplied Object's spec, status, or other metadata
// might get reset to their current state according to the API server, e.g. in
// case of a conflict error.
func (u *RetryingCriticalAnnotationUpdater) UpdateCriticalAnnotations(ctx context.Context, o client.Object) error {
	a := o.GetAnnotations()
	err := retry.OnError(retry.DefaultRetry, func(err error) bool {
		return !errors.Is(err, context.Canceled)
	}, func() error {
		err := u.client.Update(ctx, o)
		if kerrors.IsConflict(err) {
			if getErr := u.client.Get(ctx, client.ObjectKeyFromObject(o), o); getErr != nil {
				return getErr
			}
			meta.AddAnnotations(o, a)
		}
		return err
	})
	return errors.Wrap(err, errUpdateCriticalAnnotations)
}
