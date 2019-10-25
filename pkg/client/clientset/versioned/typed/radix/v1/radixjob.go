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

package v1

import (
	"time"

	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	scheme "github.com/equinor/radix-operator/pkg/client/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// RadixJobsGetter has a method to return a RadixJobInterface.
// A group's client should implement this interface.
type RadixJobsGetter interface {
	RadixJobs(namespace string) RadixJobInterface
}

// RadixJobInterface has methods to work with RadixJob resources.
type RadixJobInterface interface {
	Create(*v1.RadixJob) (*v1.RadixJob, error)
	Update(*v1.RadixJob) (*v1.RadixJob, error)
	UpdateStatus(*v1.RadixJob) (*v1.RadixJob, error)
	Delete(name string, options *metav1.DeleteOptions) error
	DeleteCollection(options *metav1.DeleteOptions, listOptions metav1.ListOptions) error
	Get(name string, options metav1.GetOptions) (*v1.RadixJob, error)
	List(opts metav1.ListOptions) (*v1.RadixJobList, error)
	Watch(opts metav1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1.RadixJob, err error)
	RadixJobExpansion
}

// radixJobs implements RadixJobInterface
type radixJobs struct {
	client rest.Interface
	ns     string
}

// newRadixJobs returns a RadixJobs
func newRadixJobs(c *RadixV1Client, namespace string) *radixJobs {
	return &radixJobs{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the radixJob, and returns the corresponding radixJob object, and an error if there is any.
func (c *radixJobs) Get(name string, options metav1.GetOptions) (result *v1.RadixJob, err error) {
	result = &v1.RadixJob{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("radixjobs").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of RadixJobs that match those selectors.
func (c *radixJobs) List(opts metav1.ListOptions) (result *v1.RadixJobList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1.RadixJobList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("radixjobs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested radixJobs.
func (c *radixJobs) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("radixjobs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch()
}

// Create takes the representation of a radixJob and creates it.  Returns the server's representation of the radixJob, and an error, if there is any.
func (c *radixJobs) Create(radixJob *v1.RadixJob) (result *v1.RadixJob, err error) {
	result = &v1.RadixJob{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("radixjobs").
		Body(radixJob).
		Do().
		Into(result)
	return
}

// Update takes the representation of a radixJob and updates it. Returns the server's representation of the radixJob, and an error, if there is any.
func (c *radixJobs) Update(radixJob *v1.RadixJob) (result *v1.RadixJob, err error) {
	result = &v1.RadixJob{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("radixjobs").
		Name(radixJob.Name).
		Body(radixJob).
		Do().
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().

func (c *radixJobs) UpdateStatus(radixJob *v1.RadixJob) (result *v1.RadixJob, err error) {
	result = &v1.RadixJob{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("radixjobs").
		Name(radixJob.Name).
		SubResource("status").
		Body(radixJob).
		Do().
		Into(result)
	return
}

// Delete takes name of the radixJob and deletes it. Returns an error if one occurs.
func (c *radixJobs) Delete(name string, options *metav1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("radixjobs").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *radixJobs) DeleteCollection(options *metav1.DeleteOptions, listOptions metav1.ListOptions) error {
	var timeout time.Duration
	if listOptions.TimeoutSeconds != nil {
		timeout = time.Duration(*listOptions.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("radixjobs").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Timeout(timeout).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched radixJob.
func (c *radixJobs) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1.RadixJob, err error) {
	result = &v1.RadixJob{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("radixjobs").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
