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

// FakeRadixJobs implements RadixJobInterface
type FakeRadixJobs struct {
	Fake *FakeRadixV1
	ns   string
}

var radixjobsResource = schema.GroupVersionResource{Group: "radix.equinor.com", Version: "v1", Resource: "radixjobs"}

var radixjobsKind = schema.GroupVersionKind{Group: "radix.equinor.com", Version: "v1", Kind: "RadixJob"}

// Get takes name of the radixJob, and returns the corresponding radixJob object, and an error if there is any.
func (c *FakeRadixJobs) Get(name string, options v1.GetOptions) (result *radixv1.RadixJob, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(radixjobsResource, c.ns, name), &radixv1.RadixJob{})

	if obj == nil {
		return nil, err
	}
	return obj.(*radixv1.RadixJob), err
}

// List takes label and field selectors, and returns the list of RadixJobs that match those selectors.
func (c *FakeRadixJobs) List(opts v1.ListOptions) (result *radixv1.RadixJobList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(radixjobsResource, radixjobsKind, c.ns, opts), &radixv1.RadixJobList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &radixv1.RadixJobList{ListMeta: obj.(*radixv1.RadixJobList).ListMeta}
	for _, item := range obj.(*radixv1.RadixJobList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested radixJobs.
func (c *FakeRadixJobs) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(radixjobsResource, c.ns, opts))

}

// Create takes the representation of a radixJob and creates it.  Returns the server's representation of the radixJob, and an error, if there is any.
func (c *FakeRadixJobs) Create(radixJob *radixv1.RadixJob) (result *radixv1.RadixJob, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(radixjobsResource, c.ns, radixJob), &radixv1.RadixJob{})

	if obj == nil {
		return nil, err
	}
	return obj.(*radixv1.RadixJob), err
}

// Update takes the representation of a radixJob and updates it. Returns the server's representation of the radixJob, and an error, if there is any.
func (c *FakeRadixJobs) Update(radixJob *radixv1.RadixJob) (result *radixv1.RadixJob, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(radixjobsResource, c.ns, radixJob), &radixv1.RadixJob{})

	if obj == nil {
		return nil, err
	}
	return obj.(*radixv1.RadixJob), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeRadixJobs) UpdateStatus(radixJob *radixv1.RadixJob) (*radixv1.RadixJob, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(radixjobsResource, "status", c.ns, radixJob), &radixv1.RadixJob{})

	if obj == nil {
		return nil, err
	}
	return obj.(*radixv1.RadixJob), err
}

// Delete takes name of the radixJob and deletes it. Returns an error if one occurs.
func (c *FakeRadixJobs) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(radixjobsResource, c.ns, name), &radixv1.RadixJob{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeRadixJobs) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(radixjobsResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &radixv1.RadixJobList{})
	return err
}

// Patch applies the patch and returns the patched radixJob.
func (c *FakeRadixJobs) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *radixv1.RadixJob, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(radixjobsResource, c.ns, name, pt, data, subresources...), &radixv1.RadixJob{})

	if obj == nil {
		return nil, err
	}
	return obj.(*radixv1.RadixJob), err
}
