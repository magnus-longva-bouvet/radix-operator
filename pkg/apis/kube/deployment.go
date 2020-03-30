package kube

import (
	"encoding/json"
	"fmt"

	"github.com/equinor/radix-operator/pkg/apis/utils/slice"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
)

// ApplyDeployment Create or update deployment in provided namespace
func (kube *Kube) ApplyDeployment(namespace string, deployment *appsv1.Deployment) error {
	log.Debugf("Creating Deployment object %s in namespace %s", deployment.Name, namespace)

	oldDeployment, err := kube.getDeployment(namespace, deployment.GetName())
	if err != nil && errors.IsNotFound(err) {
		createdDeployment, err := kube.kubeClient.AppsV1().Deployments(namespace).Create(deployment)
		if err != nil {
			return fmt.Errorf("Failed to create Deployment object: %v", err)
		}

		log.Debugf("Created Deployment: %s in namespace %s", createdDeployment.Name, namespace)
		return nil
	}

	log.Debugf("Deployment object %s already exists in namespace %s, updating the object now", deployment.GetName(), namespace)

	newDeployment := oldDeployment.DeepCopy()
	newDeployment.ObjectMeta.Labels = deployment.ObjectMeta.Labels
	newDeployment.ObjectMeta.Annotations = deployment.ObjectMeta.Annotations
	newDeployment.ObjectMeta.OwnerReferences = deployment.ObjectMeta.OwnerReferences
	newDeployment.Spec = deployment.Spec

	oldDeploymentJSON, err := json.Marshal(oldDeployment)
	if err != nil {
		return fmt.Errorf("Failed to marshal old deployment object: %v", err)
	}

	newDeploymentJSON, err := json.Marshal(newDeployment)
	if err != nil {
		return fmt.Errorf("Failed to marshal new deployment object: %v", err)
	}

	patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldDeploymentJSON, newDeploymentJSON, appsv1.Deployment{})
	if err != nil {
		return fmt.Errorf("Failed to create two way merge patch deployment objects: %v", err)
	}

	if !isEmptyPatch(patchBytes) {
		patchedDeployment, err := kube.kubeClient.AppsV1().Deployments(namespace).Patch(deployment.GetName(), types.StrategicMergePatchType, patchBytes)
		if err != nil {
			return fmt.Errorf("Failed to patch deployment object: %v", err)
		}
		log.Debugf("Patched deployment: %s in namespace %s", patchedDeployment.Name, namespace)
	} else {
		log.Debugf("No need to patch deployment: %s ", deployment.GetName())
	}

	return nil
}

// ListDeployments List deployments
func (kube *Kube) ListDeployments(namespace string) ([]*appsv1.Deployment, error) {
	var deployments []*appsv1.Deployment
	var err error

	if kube.DeploymentLister != nil {
		deployments, err = kube.DeploymentLister.Deployments(namespace).List(labels.NewSelector())
		if err != nil {
			return nil, err
		}
	} else {
		list, err := kube.kubeClient.AppsV1().Deployments(namespace).List(metav1.ListOptions{})
		if err != nil {
			return nil, err
		}

		deployments = slice.PointersOf(list.Items).([]*appsv1.Deployment)
	}

	return deployments, nil
}

func (kube *Kube) getDeployment(namespace, name string) (*appsv1.Deployment, error) {
	var deployment *appsv1.Deployment
	var err error

	if kube.DeploymentLister != nil {
		deployment, err = kube.DeploymentLister.Deployments(namespace).Get(name)
		if err != nil {
			return nil, err
		}
	} else {
		deployment, err = kube.kubeClient.AppsV1().Deployments(namespace).Get(name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
	}

	return deployment, nil
}
