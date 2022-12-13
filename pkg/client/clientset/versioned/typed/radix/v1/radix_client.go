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
	"net/http"

	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	"github.com/equinor/radix-operator/pkg/client/clientset/versioned/scheme"
	rest "k8s.io/client-go/rest"
)

type RadixV1Interface interface {
	RESTClient() rest.Interface
	RadixAlertsGetter
	RadixApplicationsGetter
	RadixDeploymentsGetter
	RadixEnvironmentsGetter
	RadixJobsGetter
	RadixRegistrationsGetter
	RadixScheduledJobsGetter
}

// RadixV1Client is used to interact with features provided by the radix.equinor.com group.
type RadixV1Client struct {
	restClient rest.Interface
}

func (c *RadixV1Client) RadixAlerts(namespace string) RadixAlertInterface {
	return newRadixAlerts(c, namespace)
}

func (c *RadixV1Client) RadixApplications(namespace string) RadixApplicationInterface {
	return newRadixApplications(c, namespace)
}

func (c *RadixV1Client) RadixDeployments(namespace string) RadixDeploymentInterface {
	return newRadixDeployments(c, namespace)
}

func (c *RadixV1Client) RadixEnvironments() RadixEnvironmentInterface {
	return newRadixEnvironments(c)
}

func (c *RadixV1Client) RadixJobs(namespace string) RadixJobInterface {
	return newRadixJobs(c, namespace)
}

func (c *RadixV1Client) RadixRegistrations() RadixRegistrationInterface {
	return newRadixRegistrations(c)
}

func (c *RadixV1Client) RadixScheduledJobs(namespace string) RadixScheduledJobInterface {
	return newRadixScheduledJobs(c, namespace)
}

// NewForConfig creates a new RadixV1Client for the given config.
// NewForConfig is equivalent to NewForConfigAndClient(c, httpClient),
// where httpClient was generated with rest.HTTPClientFor(c).
func NewForConfig(c *rest.Config) (*RadixV1Client, error) {
	config := *c
	if err := setConfigDefaults(&config); err != nil {
		return nil, err
	}
	httpClient, err := rest.HTTPClientFor(&config)
	if err != nil {
		return nil, err
	}
	return NewForConfigAndClient(&config, httpClient)
}

// NewForConfigAndClient creates a new RadixV1Client for the given config and http client.
// Note the http client provided takes precedence over the configured transport values.
func NewForConfigAndClient(c *rest.Config, h *http.Client) (*RadixV1Client, error) {
	config := *c
	if err := setConfigDefaults(&config); err != nil {
		return nil, err
	}
	client, err := rest.RESTClientForConfigAndClient(&config, h)
	if err != nil {
		return nil, err
	}
	return &RadixV1Client{client}, nil
}

// NewForConfigOrDie creates a new RadixV1Client for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *RadixV1Client {
	client, err := NewForConfig(c)
	if err != nil {
		panic(err)
	}
	return client
}

// New creates a new RadixV1Client for the given RESTClient.
func New(c rest.Interface) *RadixV1Client {
	return &RadixV1Client{c}
}

func setConfigDefaults(config *rest.Config) error {
	gv := v1.SchemeGroupVersion
	config.GroupVersion = &gv
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()

	if config.UserAgent == "" {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}

	return nil
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *RadixV1Client) RESTClient() rest.Interface {
	if c == nil {
		return nil
	}
	return c.restClient
}
