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

// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// RadixDeploymentLister helps list RadixDeployments.
type RadixDeploymentLister interface {
	// List lists all RadixDeployments in the indexer.
	List(selector labels.Selector) (ret []*v1.RadixDeployment, err error)
	// RadixDeployments returns an object that can list and get RadixDeployments.
	RadixDeployments(namespace string) RadixDeploymentNamespaceLister
	RadixDeploymentListerExpansion
}

// radixDeploymentLister implements the RadixDeploymentLister interface.
type radixDeploymentLister struct {
	indexer cache.Indexer
}

// NewRadixDeploymentLister returns a new RadixDeploymentLister.
func NewRadixDeploymentLister(indexer cache.Indexer) RadixDeploymentLister {
	return &radixDeploymentLister{indexer: indexer}
}

// List lists all RadixDeployments in the indexer.
func (s *radixDeploymentLister) List(selector labels.Selector) (ret []*v1.RadixDeployment, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.RadixDeployment))
	})
	return ret, err
}

// RadixDeployments returns an object that can list and get RadixDeployments.
func (s *radixDeploymentLister) RadixDeployments(namespace string) RadixDeploymentNamespaceLister {
	return radixDeploymentNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// RadixDeploymentNamespaceLister helps list and get RadixDeployments.
type RadixDeploymentNamespaceLister interface {
	// List lists all RadixDeployments in the indexer for a given namespace.
	List(selector labels.Selector) (ret []*v1.RadixDeployment, err error)
	// Get retrieves the RadixDeployment from the indexer for a given namespace and name.
	Get(name string) (*v1.RadixDeployment, error)
	RadixDeploymentNamespaceListerExpansion
}

// radixDeploymentNamespaceLister implements the RadixDeploymentNamespaceLister
// interface.
type radixDeploymentNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all RadixDeployments in the indexer for a given namespace.
func (s radixDeploymentNamespaceLister) List(selector labels.Selector) (ret []*v1.RadixDeployment, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.RadixDeployment))
	})
	return ret, err
}

// Get retrieves the RadixDeployment from the indexer for a given namespace and name.
func (s radixDeploymentNamespaceLister) Get(name string) (*v1.RadixDeployment, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.Resource("radixdeployment"), name)
	}
	return obj.(*v1.RadixDeployment), nil
}
