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
	radixv1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeRadixDeployments implements RadixDeploymentInterface
type FakeRadixDeployments struct {
	Fake *FakeRadixV1
	ns   string
}

var radixdeploymentsResource = schema.GroupVersionResource{Group: "radix.equinor.com", Version: "v1", Resource: "radixdeployments"}

var radixdeploymentsKind = schema.GroupVersionKind{Group: "radix.equinor.com", Version: "v1", Kind: "RadixDeployment"}

// Get takes name of the radixDeployment, and returns the corresponding radixDeployment object, and an error if there is any.
func (c *FakeRadixDeployments) Get(name string, options v1.GetOptions) (result *radixv1.RadixDeployment, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(radixdeploymentsResource, c.ns, name), &radixv1.RadixDeployment{})

	if obj == nil {
		return nil, err
	}
	return obj.(*radixv1.RadixDeployment), err
}

// List takes label and field selectors, and returns the list of RadixDeployments that match those selectors.
func (c *FakeRadixDeployments) List(opts v1.ListOptions) (result *radixv1.RadixDeploymentList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(radixdeploymentsResource, radixdeploymentsKind, c.ns, opts), &radixv1.RadixDeploymentList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &radixv1.RadixDeploymentList{ListMeta: obj.(*radixv1.RadixDeploymentList).ListMeta}
	for _, item := range obj.(*radixv1.RadixDeploymentList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested radixDeployments.
func (c *FakeRadixDeployments) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(radixdeploymentsResource, c.ns, opts))

}

// Create takes the representation of a radixDeployment and creates it.  Returns the server's representation of the radixDeployment, and an error, if there is any.
func (c *FakeRadixDeployments) Create(radixDeployment *radixv1.RadixDeployment) (result *radixv1.RadixDeployment, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(radixdeploymentsResource, c.ns, radixDeployment), &radixv1.RadixDeployment{})

	if obj == nil {
		return nil, err
	}
	return obj.(*radixv1.RadixDeployment), err
}

// Update takes the representation of a radixDeployment and updates it. Returns the server's representation of the radixDeployment, and an error, if there is any.
func (c *FakeRadixDeployments) Update(radixDeployment *radixv1.RadixDeployment) (result *radixv1.RadixDeployment, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(radixdeploymentsResource, c.ns, radixDeployment), &radixv1.RadixDeployment{})

	if obj == nil {
		return nil, err
	}
	return obj.(*radixv1.RadixDeployment), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeRadixDeployments) UpdateStatus(radixDeployment *radixv1.RadixDeployment) (*radixv1.RadixDeployment, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(radixdeploymentsResource, "status", c.ns, radixDeployment), &radixv1.RadixDeployment{})

	if obj == nil {
		return nil, err
	}
	return obj.(*radixv1.RadixDeployment), err
}

// Delete takes name of the radixDeployment and deletes it. Returns an error if one occurs.
func (c *FakeRadixDeployments) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(radixdeploymentsResource, c.ns, name), &radixv1.RadixDeployment{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeRadixDeployments) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(radixdeploymentsResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &radixv1.RadixDeploymentList{})
	return err
}

// Patch applies the patch and returns the patched radixDeployment.
func (c *FakeRadixDeployments) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *radixv1.RadixDeployment, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(radixdeploymentsResource, c.ns, name, pt, data, subresources...), &radixv1.RadixDeployment{})

	if obj == nil {
		return nil, err
	}
	return obj.(*radixv1.RadixDeployment), err
}
