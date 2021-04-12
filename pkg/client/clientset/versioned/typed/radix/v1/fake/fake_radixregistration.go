/*
Copyright The Kubernetes Authors.

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

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	radixv1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeRadixRegistrations implements RadixRegistrationInterface
type FakeRadixRegistrations struct {
	Fake *FakeRadixV1
}

var radixregistrationsResource = schema.GroupVersionResource{Group: "radix.equinor.com", Version: "v1", Resource: "radixregistrations"}

var radixregistrationsKind = schema.GroupVersionKind{Group: "radix.equinor.com", Version: "v1", Kind: "RadixRegistration"}

// Get takes name of the radixRegistration, and returns the corresponding radixRegistration object, and an error if there is any.
func (c *FakeRadixRegistrations) Get(ctx context.Context, name string, options v1.GetOptions) (result *radixv1.RadixRegistration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(radixregistrationsResource, name), &radixv1.RadixRegistration{})
	if obj == nil {
		return nil, err
	}
	return obj.(*radixv1.RadixRegistration), err
}

// List takes label and field selectors, and returns the list of RadixRegistrations that match those selectors.
func (c *FakeRadixRegistrations) List(ctx context.Context, opts v1.ListOptions) (result *radixv1.RadixRegistrationList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(radixregistrationsResource, radixregistrationsKind, opts), &radixv1.RadixRegistrationList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &radixv1.RadixRegistrationList{ListMeta: obj.(*radixv1.RadixRegistrationList).ListMeta}
	for _, item := range obj.(*radixv1.RadixRegistrationList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested radixRegistrations.
func (c *FakeRadixRegistrations) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(radixregistrationsResource, opts))
}

// Create takes the representation of a radixRegistration and creates it.  Returns the server's representation of the radixRegistration, and an error, if there is any.
func (c *FakeRadixRegistrations) Create(ctx context.Context, radixRegistration *radixv1.RadixRegistration, opts v1.CreateOptions) (result *radixv1.RadixRegistration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(radixregistrationsResource, radixRegistration), &radixv1.RadixRegistration{})
	if obj == nil {
		return nil, err
	}
	return obj.(*radixv1.RadixRegistration), err
}

// Update takes the representation of a radixRegistration and updates it. Returns the server's representation of the radixRegistration, and an error, if there is any.
func (c *FakeRadixRegistrations) Update(ctx context.Context, radixRegistration *radixv1.RadixRegistration, opts v1.UpdateOptions) (result *radixv1.RadixRegistration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(radixregistrationsResource, radixRegistration), &radixv1.RadixRegistration{})
	if obj == nil {
		return nil, err
	}
	return obj.(*radixv1.RadixRegistration), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeRadixRegistrations) UpdateStatus(ctx context.Context, radixRegistration *radixv1.RadixRegistration, opts v1.UpdateOptions) (*radixv1.RadixRegistration, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(radixregistrationsResource, "status", radixRegistration), &radixv1.RadixRegistration{})
	if obj == nil {
		return nil, err
	}
	return obj.(*radixv1.RadixRegistration), err
}

// Delete takes name of the radixRegistration and deletes it. Returns an error if one occurs.
func (c *FakeRadixRegistrations) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteAction(radixregistrationsResource, name), &radixv1.RadixRegistration{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeRadixRegistrations) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(radixregistrationsResource, listOpts)

	_, err := c.Fake.Invokes(action, &radixv1.RadixRegistrationList{})
	return err
}

// Patch applies the patch and returns the patched radixRegistration.
func (c *FakeRadixRegistrations) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *radixv1.RadixRegistration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(radixregistrationsResource, name, pt, data, subresources...), &radixv1.RadixRegistration{})
	if obj == nil {
		return nil, err
	}
	return obj.(*radixv1.RadixRegistration), err
}
