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
	"testing"

	"github.com/google/go-cmp/cmp"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane/crossplane-runtime/pkg/errors"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/resource/fake"
	"github.com/crossplane/crossplane-runtime/pkg/test"
)

var _ Initializer = &NameAsExternalName{}

func TestNameAsExternalName(t *testing.T) {
	type args struct {
		ctx context.Context
		mg  resource.Managed
	}

	type want struct {
		err error
		mg  resource.Managed
	}

	errBoom := errors.New("boom")
	testExternalName := "my-" +
		"external-name"

	cases := map[string]struct {
		client client.Client
		args   args
		want   want
	}{
		"UpdateManagedError": {
			client: &test.MockClient{MockUpdate: test.NewMockUpdateFn(errBoom)},
			args: args{
				ctx: context.Background(),
				mg:  &fake.Managed{ObjectMeta: metav1.ObjectMeta{Name: testExternalName}},
			},
			want: want{
				err: errors.Wrap(errBoom, errUpdateManaged),
				mg: &fake.Managed{ObjectMeta: metav1.ObjectMeta{
					Name:        testExternalName,
					Annotations: map[string]string{meta.AnnotationKeyExternalName: testExternalName},
				}},
			},
		},
		"UpdateSuccessful": {
			client: &test.MockClient{MockUpdate: test.NewMockUpdateFn(nil)},
			args: args{
				ctx: context.Background(),
				mg:  &fake.Managed{ObjectMeta: metav1.ObjectMeta{Name: testExternalName}},
			},
			want: want{
				err: nil,
				mg: &fake.Managed{ObjectMeta: metav1.ObjectMeta{
					Name:        testExternalName,
					Annotations: map[string]string{meta.AnnotationKeyExternalName: testExternalName},
				}},
			},
		},
		"UpdateNotNeeded": {
			args: args{
				ctx: context.Background(),
				mg: &fake.Managed{ObjectMeta: metav1.ObjectMeta{
					Name:        testExternalName,
					Annotations: map[string]string{meta.AnnotationKeyExternalName: "some-name"},
				}},
			},
			want: want{
				err: nil,
				mg: &fake.Managed{ObjectMeta: metav1.ObjectMeta{
					Name:        testExternalName,
					Annotations: map[string]string{meta.AnnotationKeyExternalName: "some-name"},
				}},
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			api := NewNameAsExternalName(tc.client)
			err := api.Initialize(tc.args.ctx, tc.args.mg)
			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("api.Initialize(...): -want error, +got error:\n%s", diff)
			}
			if diff := cmp.Diff(tc.want.mg, tc.args.mg, test.EquateConditions()); diff != "" {
				t.Errorf("api.Initialize(...) Managed: -want, +got:\n%s", diff)
			}
		})
	}
}

func TestRetryingCriticalAnnotationUpdater(t *testing.T) {
	errBoom := errors.New("boom")

	type args struct {
		ctx context.Context
		o   client.Object
	}
	type want struct {
		err error
		o   client.Object
	}

	setLabels := func(obj client.Object) error {
		obj.SetLabels(map[string]string{"getcalled": "true"})
		return nil
	}
	objectReturnedByGet := &fake.Managed{}
	setLabels(objectReturnedByGet)

	cases := map[string]struct {
		reason string
		c      *test.MockClient
		args   args
		want   want
	}{
		"UpdateConflictGetError": {
			reason: "We should return any error we encounter getting the supplied object",
			c: &test.MockClient{
				MockGet: test.NewMockGetFn(errBoom, setLabels),
				MockUpdate: test.NewMockUpdateFn(kerrors.NewConflict(schema.GroupResource{
					Group:    "foo.com",
					Resource: "bars",
				}, "abc", errBoom)),
			},
			args: args{
				o: &fake.Managed{},
			},
			want: want{
				err: errors.Wrap(errBoom, errUpdateCriticalAnnotations),
				o:   objectReturnedByGet,
			},
		},
		"UpdateError": {
			reason: "We should return any error we encounter updating the supplied object",
			c: &test.MockClient{
				MockGet:    test.NewMockGetFn(nil, setLabels),
				MockUpdate: test.NewMockUpdateFn(errBoom),
			},
			args: args{
				o: &fake.Managed{},
			},
			want: want{
				err: errors.Wrap(errBoom, errUpdateCriticalAnnotations),
				o:   &fake.Managed{},
			},
		},
		"SuccessfulGetAfterAConflict": {
			reason: "A successful get after a conflict should not hide the conflict error and prevent retries",
			c: &test.MockClient{
				MockGet: test.NewMockGetFn(nil, setLabels),
				MockUpdate: test.NewMockUpdateFn(kerrors.NewConflict(schema.GroupResource{
					Group:    "foo.com",
					Resource: "bars",
				}, "abc", errBoom)),
			},
			args: args{
				o: &fake.Managed{},
			},
			want: want{
				err: errors.Wrap(kerrors.NewConflict(schema.GroupResource{
					Group:    "foo.com",
					Resource: "bars",
				}, "abc", errBoom), errUpdateCriticalAnnotations),
				o: objectReturnedByGet,
			},
		},
		"Success": {
			reason: "We should return without error if we successfully update our annotations",
			c: &test.MockClient{
				MockGet:    test.NewMockGetFn(nil, setLabels),
				MockUpdate: test.NewMockUpdateFn(errBoom),
			},
			args: args{
				o: &fake.Managed{},
			},
			want: want{
				err: errors.Wrap(errBoom, errUpdateCriticalAnnotations),
				o:   &fake.Managed{},
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			u := NewRetryingCriticalAnnotationUpdater(tc.c)
			got := u.UpdateCriticalAnnotations(tc.args.ctx, tc.args.o)
			if diff := cmp.Diff(tc.want.err, got, test.EquateErrors()); diff != "" {
				t.Errorf("\n%s\nu.UpdateCriticalAnnotations(...): -want, +got:\n%s", tc.reason, diff)
			}
			if diff := cmp.Diff(tc.want.o, tc.args.o); diff != "" {
				t.Errorf("\n%s\nu.UpdateCriticalAnnotations(...): -want, +got:\n%s", tc.reason, diff)
			}
		})
	}
}
