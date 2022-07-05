package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/equinor/radix-common/utils/slice"
	log "github.com/sirupsen/logrus"
	v12 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
)

// ListPodDisruptionBudgets lists PodDisruptionBudgets
func (kubeutil *Kube) ListPodDisruptionBudgets(namespace string) ([]*v12.PodDisruptionBudget, error) {
	list, err := kubeutil.kubeClient.PolicyV1().PodDisruptionBudgets(namespace).List(context.TODO(), metav1.ListOptions{})

	if err != nil {
		return nil, err
	}
	pdbs := slice.PointersOf(list.Items).([]*v12.PodDisruptionBudget)
	return pdbs, nil
}

// MergePodDisruptionBudgets returns patch bytes between two PDBs
func MergePodDisruptionBudgets(existingPdb *v12.PodDisruptionBudget, generatedPdb *v12.PodDisruptionBudget) ([]byte, error) {
	// TODO: function is quite generic. Make type-independent abstraction?
	newPdb := existingPdb.DeepCopy()
	newPdb.ObjectMeta.Labels = generatedPdb.ObjectMeta.Labels
	newPdb.ObjectMeta.Annotations = generatedPdb.ObjectMeta.Annotations
	newPdb.ObjectMeta.OwnerReferences = generatedPdb.ObjectMeta.OwnerReferences
	newPdb.Spec = generatedPdb.Spec

	oldPdbJSON, err := json.Marshal(existingPdb)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal old PDB object: %v", err)
	}

	newPdbJSON, err := json.Marshal(newPdb)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal new PDB object: %v", err)
	}

	patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldPdbJSON, newPdbJSON, v12.PodDisruptionBudget{})
	if err != nil {
		return nil, fmt.Errorf("failed to create two way merge PDB objects: %v", err)
	}

	return patchBytes, nil
}

// UpdatePodDisruptionBudget will update PodDisruptionBudgets in provided namespace
func (kubeutil *Kube) UpdatePodDisruptionBudget(namespace string, pdb *v12.PodDisruptionBudget) error {
	pdbName := pdb.Name
	existingPdb, getPdbErr := kubeutil.kubeClient.PolicyV1().PodDisruptionBudgets(namespace).Get(context.TODO(), pdbName, metav1.GetOptions{})
	if getPdbErr != nil {
		return getPdbErr
	}

	patchBytes, err := MergePodDisruptionBudgets(existingPdb, pdb)
	if err != nil {
		return err
	}

	if !IsEmptyPatch(patchBytes) {
		_, err := kubeutil.kubeClient.PolicyV1().PodDisruptionBudgets(namespace).Patch(context.TODO(), pdbName, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("failed to patch PDB object: %v", err)
		}
	} else {
		log.Debugf("no need to patch PDB: %s ", pdbName)
	}
	return nil
}
