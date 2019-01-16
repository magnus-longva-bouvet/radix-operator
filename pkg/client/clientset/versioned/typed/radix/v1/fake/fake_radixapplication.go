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
	radix_v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeRadixApplications implements RadixApplicationInterface
type FakeRadixApplications struct {
	Fake *FakeRadixV1
	ns   string
}

var radixapplicationsResource = schema.GroupVersionResource{Group: "radix.equinor.com", Version: "v1", Resource: "radixapplications"}

var radixapplicationsKind = schema.GroupVersionKind{Group: "radix.equinor.com", Version: "v1", Kind: "RadixApplication"}

// Get takes name of the radixApplication, and returns the corresponding radixApplication object, and an error if there is any.
func (c *FakeRadixApplications) Get(name string, options v1.GetOptions) (result *radix_v1.RadixApplication, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(radixapplicationsResource, c.ns, name), &radix_v1.RadixApplication{})

	if obj == nil {
		return nil, err
	}
	return obj.(*radix_v1.RadixApplication), err
}

// List takes label and field selectors, and returns the list of RadixApplications that match those selectors.
func (c *FakeRadixApplications) List(opts v1.ListOptions) (result *radix_v1.RadixApplicationList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(radixapplicationsResource, radixapplicationsKind, c.ns, opts), &radix_v1.RadixApplicationList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &radix_v1.RadixApplicationList{ListMeta: obj.(*radix_v1.RadixApplicationList).ListMeta}
	for _, item := range obj.(*radix_v1.RadixApplicationList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested radixApplications.
func (c *FakeRadixApplications) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(radixapplicationsResource, c.ns, opts))

}

// Create takes the representation of a radixApplication and creates it.  Returns the server's representation of the radixApplication, and an error, if there is any.
func (c *FakeRadixApplications) Create(radixApplication *radix_v1.RadixApplication) (result *radix_v1.RadixApplication, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(radixapplicationsResource, c.ns, radixApplication), &radix_v1.RadixApplication{})

	if obj == nil {
		return nil, err
	}
	return obj.(*radix_v1.RadixApplication), err
}

// Update takes the representation of a radixApplication and updates it. Returns the server's representation of the radixApplication, and an error, if there is any.
func (c *FakeRadixApplications) Update(radixApplication *radix_v1.RadixApplication) (result *radix_v1.RadixApplication, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(radixapplicationsResource, c.ns, radixApplication), &radix_v1.RadixApplication{})

	if obj == nil {
		return nil, err
	}
	return obj.(*radix_v1.RadixApplication), err
}

// Delete takes name of the radixApplication and deletes it. Returns an error if one occurs.
func (c *FakeRadixApplications) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(radixapplicationsResource, c.ns, name), &radix_v1.RadixApplication{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeRadixApplications) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(radixapplicationsResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &radix_v1.RadixApplicationList{})
	return err
}

// Patch applies the patch and returns the patched radixApplication.
func (c *FakeRadixApplications) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *radix_v1.RadixApplication, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(radixapplicationsResource, c.ns, name, data, subresources...), &radix_v1.RadixApplication{})

	if obj == nil {
		return nil, err
	}
	return obj.(*radix_v1.RadixApplication), err
}
