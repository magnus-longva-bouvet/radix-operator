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

// RadixDeploymentsGetter has a method to return a RadixDeploymentInterface.
// A group's client should implement this interface.
type RadixDeploymentsGetter interface {
	RadixDeployments(namespace string) RadixDeploymentInterface
}

// RadixDeploymentInterface has methods to work with RadixDeployment resources.
type RadixDeploymentInterface interface {
	Create(*v1.RadixDeployment) (*v1.RadixDeployment, error)
	Update(*v1.RadixDeployment) (*v1.RadixDeployment, error)
	UpdateStatus(*v1.RadixDeployment) (*v1.RadixDeployment, error)
	Delete(name string, options *metav1.DeleteOptions) error
	DeleteCollection(options *metav1.DeleteOptions, listOptions metav1.ListOptions) error
	Get(name string, options metav1.GetOptions) (*v1.RadixDeployment, error)
	List(opts metav1.ListOptions) (*v1.RadixDeploymentList, error)
	Watch(opts metav1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1.RadixDeployment, err error)
	RadixDeploymentExpansion
}

// radixDeployments implements RadixDeploymentInterface
type radixDeployments struct {
	client rest.Interface
	ns     string
}

// newRadixDeployments returns a RadixDeployments
func newRadixDeployments(c *RadixV1Client, namespace string) *radixDeployments {
	return &radixDeployments{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the radixDeployment, and returns the corresponding radixDeployment object, and an error if there is any.
func (c *radixDeployments) Get(name string, options metav1.GetOptions) (result *v1.RadixDeployment, err error) {
	result = &v1.RadixDeployment{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("radixdeployments").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of RadixDeployments that match those selectors.
func (c *radixDeployments) List(opts metav1.ListOptions) (result *v1.RadixDeploymentList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1.RadixDeploymentList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("radixdeployments").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested radixDeployments.
func (c *radixDeployments) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("radixdeployments").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch()
}

// Create takes the representation of a radixDeployment and creates it.  Returns the server's representation of the radixDeployment, and an error, if there is any.
func (c *radixDeployments) Create(radixDeployment *v1.RadixDeployment) (result *v1.RadixDeployment, err error) {
	result = &v1.RadixDeployment{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("radixdeployments").
		Body(radixDeployment).
		Do().
		Into(result)
	return
}

// Update takes the representation of a radixDeployment and updates it. Returns the server's representation of the radixDeployment, and an error, if there is any.
func (c *radixDeployments) Update(radixDeployment *v1.RadixDeployment) (result *v1.RadixDeployment, err error) {
	result = &v1.RadixDeployment{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("radixdeployments").
		Name(radixDeployment.Name).
		Body(radixDeployment).
		Do().
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().

func (c *radixDeployments) UpdateStatus(radixDeployment *v1.RadixDeployment) (result *v1.RadixDeployment, err error) {
	result = &v1.RadixDeployment{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("radixdeployments").
		Name(radixDeployment.Name).
		SubResource("status").
		Body(radixDeployment).
		Do().
		Into(result)
	return
}

// Delete takes name of the radixDeployment and deletes it. Returns an error if one occurs.
func (c *radixDeployments) Delete(name string, options *metav1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("radixdeployments").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *radixDeployments) DeleteCollection(options *metav1.DeleteOptions, listOptions metav1.ListOptions) error {
	var timeout time.Duration
	if listOptions.TimeoutSeconds != nil {
		timeout = time.Duration(*listOptions.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("radixdeployments").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Timeout(timeout).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched radixDeployment.
func (c *radixDeployments) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1.RadixDeployment, err error) {
	result = &v1.RadixDeployment{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("radixdeployments").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
