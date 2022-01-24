// Code generated by MockGen. DO NOT EDIT.
// Source: ./pkg/apis/deployment/deploymentfactory.go

// Package deployment is a generated GoMock package.
package deployment

import (
	reflect "reflect"

	kube "github.com/equinor/radix-operator/pkg/apis/kube"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	versioned "github.com/equinor/radix-operator/pkg/client/clientset/versioned"
	gomock "github.com/golang/mock/gomock"
	versioned0 "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned"
	kubernetes "k8s.io/client-go/kubernetes"
)

// MockDeploymentSyncerFactory is a mock of DeploymentSyncerFactory interface.
type MockDeploymentSyncerFactory struct {
	ctrl     *gomock.Controller
	recorder *MockDeploymentSyncerFactoryMockRecorder
}

// MockDeploymentSyncerFactoryMockRecorder is the mock recorder for MockDeploymentSyncerFactory.
type MockDeploymentSyncerFactoryMockRecorder struct {
	mock *MockDeploymentSyncerFactory
}

// NewMockDeploymentSyncerFactory creates a new mock instance.
func NewMockDeploymentSyncerFactory(ctrl *gomock.Controller) *MockDeploymentSyncerFactory {
	mock := &MockDeploymentSyncerFactory{ctrl: ctrl}
	mock.recorder = &MockDeploymentSyncerFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDeploymentSyncerFactory) EXPECT() *MockDeploymentSyncerFactoryMockRecorder {
	return m.recorder
}

// CreateDeploymentSyncer mocks base method.
func (m *MockDeploymentSyncerFactory) CreateDeploymentSyncer(kubeclient kubernetes.Interface, kubeutil *kube.Kube, radixclient versioned.Interface, prometheusperatorclient versioned0.Interface, registration *v1.RadixRegistration, radixDeployment *v1.RadixDeployment, forceRunAsNonRoot bool, tenantId string, ingressAnnotationProviders []IngressAnnotationProvider, auxResourceManagers []AuxiliaryResourceManager) DeploymentSyncer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateDeploymentSyncer", kubeclient, kubeutil, radixclient, prometheusperatorclient, registration, radixDeployment, forceRunAsNonRoot, tenantId, ingressAnnotationProviders, auxResourceManagers)
	ret0, _ := ret[0].(DeploymentSyncer)
	return ret0
}

// CreateDeploymentSyncer indicates an expected call of CreateDeploymentSyncer.
func (mr *MockDeploymentSyncerFactoryMockRecorder) CreateDeploymentSyncer(kubeclient, kubeutil, radixclient, prometheusperatorclient, registration, radixDeployment, forceRunAsNonRoot, tenantId, ingressAnnotationProviders, auxResourceManagers interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateDeploymentSyncer", reflect.TypeOf((*MockDeploymentSyncerFactory)(nil).CreateDeploymentSyncer), kubeclient, kubeutil, radixclient, prometheusperatorclient, registration, radixDeployment, forceRunAsNonRoot, tenantId, ingressAnnotationProviders, auxResourceManagers)
}
