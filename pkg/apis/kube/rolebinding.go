package kube

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/equinor/radix-operator/pkg/apis/defaults/k8s"
	"github.com/equinor/radix-operator/pkg/apis/utils/slice"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
)

// GetRoleBindingGroups Get subjects for list of ad groups
func GetRoleBindingGroups(groups []string) []rbacv1.Subject {
	subjects := []rbacv1.Subject{}
	for _, group := range groups {
		subjects = append(subjects, rbacv1.Subject{
			Kind:     k8s.KindGroup,
			Name:     group,
			APIGroup: k8s.RbacApiGroup,
		})
	}
	return subjects
}

// GetRolebindingToRole Get role binding object
func GetRolebindingToRole(appName, roleName string, groups []string) *rbacv1.RoleBinding {
	return GetRolebindingToRoleWithLabels(roleName, groups, map[string]string{
		RadixAppLabel: appName,
	})
}

// GetRolebindingToRoleWithLabels Get role binding object
func GetRolebindingToRoleWithLabels(roleName string, groups []string, labels map[string]string) *rbacv1.RoleBinding {
	subjects := GetRoleBindingGroups(groups)
	return getRoleBindingForSubjects(roleName, k8s.KindRole, subjects, labels)
}

// GetRolebindingToRoleWithLabelsForSubjects Get rolebinding object with subjects as input
func GetRolebindingToRoleWithLabelsForSubjects(roleName string, subjects []rbacv1.Subject, labels map[string]string) *rbacv1.RoleBinding {
	return getRoleBindingForSubjects(roleName, k8s.KindRole, subjects, labels)
}

// GetRolebindingToClusterRole Get role binding object
func GetRolebindingToClusterRole(appName, roleName string, groups []string) *rbacv1.RoleBinding {
	return GetRolebindingToClusterRoleWithLabels(roleName, groups, map[string]string{
		RadixAppLabel: appName,
	})
}

// GetRolebindingToClusterRoleForSubjects Get role binding object for list of subjects
func GetRolebindingToClusterRoleForSubjects(appName, roleName string, subjects []rbacv1.Subject) *rbacv1.RoleBinding {
	return GetRolebindingToClusterRoleForSubjectsWithLabels(roleName, subjects, map[string]string{
		RadixAppLabel: appName,
	})
}

// GetRolebindingToClusterRoleForSubjectsWithLabels Get role binding object for list of subjects with labels set
func GetRolebindingToClusterRoleForSubjectsWithLabels(roleName string, subjects []rbacv1.Subject, labels map[string]string) *rbacv1.RoleBinding {
	return getRoleBindingForSubjects(roleName, k8s.KindClusterRole, subjects, labels)
}

// GetRolebindingToClusterRoleWithLabels Get role binding object
func GetRolebindingToClusterRoleWithLabels(roleName string, groups []string, labels map[string]string) *rbacv1.RoleBinding {
	subjects := GetRoleBindingGroups(groups)
	return getRoleBindingForSubjects(roleName, k8s.KindClusterRole, subjects, labels)
}

// GetRolebindingToRoleForSubjectsWithLabels Get role binding object for list of subjects with labels set
func GetRolebindingToRoleForSubjectsWithLabels(appName, roleName string, subjects []rbacv1.Subject, labels map[string]string) *rbacv1.RoleBinding {
	return getRoleBindingForSubjects(roleName, k8s.KindRole, subjects, labels)
}

// GetRolebindingToRoleForServiceAccountWithLabels Get role binding object
func GetRolebindingToRoleForServiceAccountWithLabels(roleName, serviceAccountName, serviceAccountNamespace string, labels map[string]string) *rbacv1.RoleBinding {
	subjects := []rbacv1.Subject{
		{
			Kind:      k8s.KindServiceAccount,
			Name:      serviceAccountName,
			Namespace: serviceAccountNamespace,
		}}

	return getRoleBindingForSubjects(roleName, k8s.KindRole, subjects, labels)
}

// GetRolebindingToClusterRoleForServiceAccountWithLabels Get role binding object
func GetRolebindingToClusterRoleForServiceAccountWithLabels(roleName, serviceAccountName, serviceAccountNamespace string, labels map[string]string) *rbacv1.RoleBinding {
	subjects := []rbacv1.Subject{
		{
			Kind:      k8s.KindServiceAccount,
			Name:      serviceAccountName,
			Namespace: serviceAccountNamespace,
		}}

	return getRoleBindingForSubjects(roleName, k8s.KindClusterRole, subjects, labels)
}

func getRoleBindingForSubjects(roleName, kind string, subjects []rbacv1.Subject, labels map[string]string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: k8s.RbacApiVersion,
			Kind:       k8s.KindRoleBinding,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   roleName,
			Labels: labels,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: k8s.RbacApiGroup,
			Kind:     kind,
			Name:     roleName,
		},
		Subjects: subjects,
	}
}

// ApplyRoleBinding Creates or updates role
func (kubeutil *Kube) ApplyRoleBinding(namespace string, role *rbacv1.RoleBinding) error {
	logger.Debugf("Apply role binding %s", role.Name)
	oldRoleBinding, err := kubeutil.GetRoleBinding(namespace, role.GetName())
	if err != nil && errors.IsNotFound(err) {
		createdRoleBinding, err := kubeutil.kubeClient.RbacV1().RoleBindings(namespace).Create(context.TODO(), role, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create role binding object: %v", err)
		}

		log.Debugf("Created role binding: %s in namespace %s", createdRoleBinding.Name, namespace)
		return nil

	} else if err != nil {
		return fmt.Errorf("failed to get role binding object: %v", err)
	}

	log.Debugf("Role binding object %s already exists in namespace %s, updating the object now", role.GetName(), namespace)

	newRoleBinding := oldRoleBinding.DeepCopy()
	newRoleBinding.ObjectMeta.OwnerReferences = role.ObjectMeta.OwnerReferences
	newRoleBinding.ObjectMeta.Labels = role.Labels
	newRoleBinding.Subjects = role.Subjects

	oldRoleBindingJSON, err := json.Marshal(oldRoleBinding)
	if err != nil {
		return fmt.Errorf("failed to marshal old role binding object: %v", err)
	}

	newRoleBindingJSON, err := json.Marshal(newRoleBinding)
	if err != nil {
		return fmt.Errorf("failed to marshal new role binding object: %v", err)
	}

	patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldRoleBindingJSON, newRoleBindingJSON, rbacv1.RoleBinding{})
	if err != nil {
		return fmt.Errorf("failed to create two way merge patch role binding objects: %v", err)
	}

	if !IsEmptyPatch(patchBytes) {
		patchedRoleBinding, err := kubeutil.kubeClient.RbacV1().RoleBindings(namespace).Patch(context.TODO(), role.GetName(), types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("failed to patch role binding object: %v", err)
		}
		log.Debugf("Patched role binding: %s in namespace %s", patchedRoleBinding.Name, namespace)
	} else {
		log.Debugf("No need to patch role binding: %s ", role.GetName())
	}

	return nil
}

// ApplyClusterRoleBinding Creates or updates cluster-role-binding
func (kubeutil *Kube) ApplyClusterRoleBinding(clusterrolebinding *rbacv1.ClusterRoleBinding) error {
	logger = logger.WithFields(log.Fields{"clusterRoleBinding": clusterrolebinding.ObjectMeta.Name})
	logger.Debugf("Apply clusterrolebinding %s", clusterrolebinding.Name)
	oldClusterRoleBinding, err := kubeutil.getClusterRoleBinding(clusterrolebinding.Name)
	if err != nil && errors.IsNotFound(err) {
		createdClusterRoleBinding, err := kubeutil.kubeClient.RbacV1().ClusterRoleBindings().Create(context.TODO(), clusterrolebinding, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create cluster role binding object: %v", err)
		}

		log.Debugf("Created cluster role binding: %s", createdClusterRoleBinding.Name)
		return nil

	} else if err != nil {
		return fmt.Errorf("failed to get cluster role binding object: %v", err)
	}

	log.Debugf("Role binding object %s already exists, updating the object now", clusterrolebinding.GetName())

	newClusterRoleBinding := oldClusterRoleBinding.DeepCopy()
	newClusterRoleBinding.ObjectMeta.OwnerReferences = clusterrolebinding.OwnerReferences
	newClusterRoleBinding.ObjectMeta.Labels = clusterrolebinding.Labels
	newClusterRoleBinding.Subjects = clusterrolebinding.Subjects

	oldClusterRoleBindingJSON, err := json.Marshal(oldClusterRoleBinding)
	if err != nil {
		return fmt.Errorf("failed to marshal old cluster role binding object: %v", err)
	}

	newClusterRoleBindingJSON, err := json.Marshal(newClusterRoleBinding)
	if err != nil {
		return fmt.Errorf("failed to marshal new cluster role binding object: %v", err)
	}

	patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldClusterRoleBindingJSON, newClusterRoleBindingJSON, rbacv1.ClusterRoleBinding{})
	if err != nil {
		return fmt.Errorf("failed to create two way merge patch cluster role binding objects: %v", err)
	}

	if !IsEmptyPatch(patchBytes) {
		patchedClusterRoleBinding, err := kubeutil.kubeClient.RbacV1().ClusterRoleBindings().Patch(context.TODO(), clusterrolebinding.GetName(), types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("failed to patch cluster role binding object: %v", err)
		}
		log.Debugf("Patched cluster role binding: %s ", patchedClusterRoleBinding.Name)
	} else {
		log.Debugf("No need to patch cluster role binding: %s ", clusterrolebinding.GetName())
	}

	return nil
}

// ApplyClusterRoleToServiceAccount Creates cluster-role-binding as a link between role and service account
func (kubeutil *Kube) ApplyClusterRoleToServiceAccount(roleName string, serviceAccount *corev1.ServiceAccount, ownerReference []metav1.OwnerReference) error {
	rolebinding := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: k8s.RbacApiVersion,
			Kind:       k8s.KindClusterRoleBinding,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("%s-%s", serviceAccount.Namespace, serviceAccount.Name),
			OwnerReferences: ownerReference,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: k8s.RbacApiGroup,
			Kind:     k8s.KindClusterRole,
			Name:     roleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      k8s.KindServiceAccount,
				Name:      serviceAccount.Name,
				Namespace: serviceAccount.Namespace,
			},
		},
	}
	return kubeutil.ApplyClusterRoleBinding(rolebinding)
}

// GetRoleBinding Gets rolebinding
func (kubeutil *Kube) GetRoleBinding(namespace, name string) (*rbacv1.RoleBinding, error) {
	var role *rbacv1.RoleBinding
	var err error

	if kubeutil.RoleBindingLister != nil {
		role, err = kubeutil.RoleBindingLister.RoleBindings(namespace).Get(name)
		if err != nil {
			return nil, err
		}
	} else {
		role, err = kubeutil.kubeClient.RbacV1().RoleBindings(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
	}

	return role, nil
}

// ListRoleBindings Lists role bindings from cache or from cluster
func (kubeutil *Kube) ListRoleBindings(namespace string) ([]*rbacv1.RoleBinding, error) {
	return kubeutil.ListRoleBindingsWithSelector(namespace, "")
}

// ListRoleBindingsWithSelector Lists role bindings from cache or from cluster using a selector
func (kubeutil *Kube) ListRoleBindingsWithSelector(namespace string, labelSelectorString string) ([]*rbacv1.RoleBinding, error) {
	var roleBindings []*rbacv1.RoleBinding

	if kubeutil.RoleBindingLister != nil {
		selector, err := labels.Parse(labelSelectorString)
		if err != nil {
			return nil, err
		}

		roleBindings, err = kubeutil.RoleBindingLister.RoleBindings(namespace).List(selector)
		if err != nil {
			return nil, err
		}
	} else {
		listOptions := metav1.ListOptions{
			LabelSelector: labelSelectorString,
		}

		list, err := kubeutil.kubeClient.RbacV1().RoleBindings(namespace).List(context.TODO(), listOptions)
		if err != nil {
			return nil, err
		}

		roleBindings = slice.PointersOf(list.Items).([]*rbacv1.RoleBinding)
	}

	return roleBindings, nil
}

// ListClusterRoleBindings List cluster roles
func (kubeutil *Kube) ListClusterRoleBindings(namespace string) ([]*rbacv1.ClusterRoleBinding, error) {
	var clusterRoleBindings []*rbacv1.ClusterRoleBinding
	var err error

	if kubeutil.ClusterRoleBindingLister != nil {
		clusterRoleBindings, err = kubeutil.ClusterRoleBindingLister.List(labels.NewSelector())
		if err != nil {
			return nil, err
		}
	} else {
		list, err := kubeutil.kubeClient.RbacV1().ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return nil, err
		}

		clusterRoleBindings = slice.PointersOf(list.Items).([]*rbacv1.ClusterRoleBinding)
	}

	return clusterRoleBindings, nil
}

// DeleteClusterRoleBinding Deletes a clusterrolebinding
func (kubeutil *Kube) DeleteClusterRoleBinding(name string) error {
	_, err := kubeutil.getClusterRoleBinding(name)
	if err != nil && errors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get clusterrolebinding object: %v", err)
	}
	err = kubeutil.kubeClient.RbacV1().ClusterRoleBindings().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete clusterrolebinding object: %v", err)
	}
	return nil
}

// DeleteRoleBinding Deletes a rolebinding in a namespace
func (kubeutil *Kube) DeleteRoleBinding(namespace, name string) error {
	_, err := kubeutil.GetRoleBinding(namespace, name)
	if err != nil && errors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get rolebinding object: %v", err)
	}
	err = kubeutil.kubeClient.RbacV1().RoleBindings(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete rolebinding object: %v", err)
	}
	return nil
}

func (kubeutil *Kube) getClusterRoleBinding(name string) (*rbacv1.ClusterRoleBinding, error) {
	var clusterRoleBinding *rbacv1.ClusterRoleBinding
	var err error

	if kubeutil.ClusterRoleBindingLister != nil {
		clusterRoleBinding, err = kubeutil.ClusterRoleBindingLister.Get(name)
		if err != nil {
			return nil, err
		}
	} else {
		clusterRoleBinding, err = kubeutil.kubeClient.RbacV1().ClusterRoleBindings().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
	}

	return clusterRoleBinding, nil
}
