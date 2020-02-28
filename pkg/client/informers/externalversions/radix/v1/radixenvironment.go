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

// Code generated by informer-gen. DO NOT EDIT.

package v1

import (
	time "time"

	radixv1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	versioned "github.com/equinor/radix-operator/pkg/client/clientset/versioned"
	internalinterfaces "github.com/equinor/radix-operator/pkg/client/informers/externalversions/internalinterfaces"
	v1 "github.com/equinor/radix-operator/pkg/client/listers/radix/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// RadixEnvironmentInformer provides access to a shared informer and lister for
// RadixEnvironments.
type RadixEnvironmentInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.RadixEnvironmentLister
}

type radixEnvironmentInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewRadixEnvironmentInformer constructs a new informer for RadixEnvironment type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewRadixEnvironmentInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredRadixEnvironmentInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredRadixEnvironmentInformer constructs a new informer for RadixEnvironment type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredRadixEnvironmentInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.RadixV1().RadixEnvironments().List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.RadixV1().RadixEnvironments().Watch(options)
			},
		},
		&radixv1.RadixEnvironment{},
		resyncPeriod,
		indexers,
	)
}

func (f *radixEnvironmentInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredRadixEnvironmentInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *radixEnvironmentInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&radixv1.RadixEnvironment{}, f.defaultInformer)
}

func (f *radixEnvironmentInformer) Lister() v1.RadixEnvironmentLister {
	return v1.NewRadixEnvironmentLister(f.Informer().GetIndexer())
}
