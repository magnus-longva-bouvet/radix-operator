package kube

import (
	"encoding/json"
	"fmt"

	"github.com/equinor/radix-operator/pkg/apis/utils/slice"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	auth "k8s.io/api/rbac/v1"
	"k8s.io/api/rbac/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	labelHelpers "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
)

// GetRoleBindingGroups Get subjects for list of ad groups
func GetRoleBindingGroups(groups []string) []auth.Subject {
	subjects := []auth.Subject{}
	for _, group := range groups {
		subjects = append(subjects, auth.Subject{
			Kind:     "Group",
			Name:     group,
			APIGroup: "rbac.authorization.k8s.io",
		})
	}
	return subjects
}

// GetRolebindingToRole Get role binding object
func GetRolebindingToRole(appName, roleName string, groups []string) *auth.RoleBinding {
	return GetRolebindingToRoleWithLabels(roleName, groups, map[string]string{
		RadixAppLabel: appName,
	})
}

// GetRolebindingToRoleWithLabels Get role binding object
func GetRolebindingToRoleWithLabels(roleName string, groups []string, labels map[string]string) *auth.RoleBinding {
	return getRoleBindingForGroups(roleName, "Role", groups, labels)
}

// GetRolebindingToClusterRole Get role binding object
func GetRolebindingToClusterRole(appName, roleName string, groups []string) *auth.RoleBinding {
	return GetRolebindingToClusterRoleWithLabels(roleName, groups, map[string]string{
		RadixAppLabel: appName,
	})
}

// GetRolebindingToClusterRoleWithLabels Get role binding object
func GetRolebindingToClusterRoleWithLabels(roleName string, groups []string, labels map[string]string) *auth.RoleBinding {
	return getRoleBindingForGroups(roleName, "ClusterRole", groups, labels)
}

// GetRolebindingToRoleForServiceAccountWithLabels Get role binding object
func GetRolebindingToRoleForServiceAccountWithLabels(roleName, serviceAccountName, serviceAccountNamespace string, labels map[string]string) *auth.RoleBinding {
	return getRoleBindingForServiceAccount(roleName, "Role", serviceAccountName, serviceAccountNamespace, labels)
}

// GetRolebindingToClusterRoleForServiceAccountWithLabels Get role binding object
func GetRolebindingToClusterRoleForServiceAccountWithLabels(roleName, serviceAccountName, serviceAccountNamespace string, labels map[string]string) *auth.RoleBinding {
	return getRoleBindingForServiceAccount(roleName, "ClusterRole", serviceAccountName, serviceAccountNamespace, labels)
}

func getRoleBindingForGroups(roleName, kind string, groups []string, labels map[string]string) *auth.RoleBinding {
	subjects := GetRoleBindingGroups(groups)
	return &auth.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "RoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   roleName,
			Labels: labels,
		},
		RoleRef: auth.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     kind,
			Name:     roleName,
		},
		Subjects: subjects,
	}
}

func getRoleBindingForServiceAccount(roleName, kind, serviceAccountName, serviceAccountNamespace string, labels map[string]string) *auth.RoleBinding {
	return &auth.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "RoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   roleName,
			Labels: labels,
		},
		RoleRef: auth.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     kind,
			Name:     roleName,
		},
		Subjects: []auth.Subject{
			auth.Subject{
				Kind:      "ServiceAccount",
				Name:      serviceAccountName,
				Namespace: serviceAccountNamespace,
			},
		},
	}
}

// ApplyRoleBinding Creates or updates role
func (k *Kube) ApplyRoleBinding(namespace string, role *auth.RoleBinding) error {
	logger.Debugf("Apply role binding %s", role.Name)
	oldRoleBinding, err := k.getRoleBinding(namespace, role.GetName())
	if err != nil && errors.IsNotFound(err) {
		createdRoleBinding, err := k.kubeClient.RbacV1().RoleBindings(namespace).Create(role)
		if err != nil {
			return fmt.Errorf("Failed to create role binding object: %v", err)
		}

		log.Debugf("Created role binding: %s in namespace %s", createdRoleBinding.Name, namespace)
		return nil

	} else if err != nil {
		return fmt.Errorf("Failed to create role binding object: %v", err)
	}

	log.Debugf("Role binding object %s already exists in namespace %s, updating the object now", role.GetName(), namespace)

	newRoleBinding := oldRoleBinding.DeepCopy()
	newRoleBinding.ObjectMeta.OwnerReferences = role.ObjectMeta.OwnerReferences
	newRoleBinding.ObjectMeta.Labels = role.Labels
	newRoleBinding.Subjects = role.Subjects

	oldRoleBindingJSON, err := json.Marshal(oldRoleBinding)
	if err != nil {
		return fmt.Errorf("Failed to marshal old role binding object: %v", err)
	}

	newRoleBindingJSON, err := json.Marshal(newRoleBinding)
	if err != nil {
		return fmt.Errorf("Failed to marshal new role binding object: %v", err)
	}

	patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldRoleBindingJSON, newRoleBindingJSON, v1beta1.RoleBinding{})
	if err != nil {
		return fmt.Errorf("Failed to create two way merge patch role binding objects: %v", err)
	}

	if !isEmptyPatch(patchBytes) {
		patchedRoleBinding, err := k.kubeClient.RbacV1().RoleBindings(namespace).Patch(role.GetName(), types.StrategicMergePatchType, patchBytes)
		if err != nil {
			return fmt.Errorf("Failed to patch role binding object: %v", err)
		}
		log.Debugf("Patched role binding: %s in namespace %s", patchedRoleBinding.Name, namespace)
	} else {
		log.Debugf("No need to patch role binding: %s ", role.GetName())
	}

	return nil
}

// ApplyClusterRoleBinding Creates or updates cluster-role-binding
func (k *Kube) ApplyClusterRoleBinding(clusterrolebinding *auth.ClusterRoleBinding) error {
	logger = logger.WithFields(log.Fields{"clusterRoleBinding": clusterrolebinding.ObjectMeta.Name})

	logger.Debugf("Apply clusterrolebinding %s", clusterrolebinding.Name)

	_, err := k.kubeClient.RbacV1().ClusterRoleBindings().Create(clusterrolebinding)
	if errors.IsAlreadyExists(err) {
		logger.Debugf("ClusterRolebinding %s already exists, updating the object now", clusterrolebinding.Name)
		oldClusterRoleBinding, err := k.kubeClient.RbacV1().ClusterRoleBindings().Get(clusterrolebinding.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("Failed to get old clusterrole binding object: %v", err)
		}

		newClusterRoleBinding := oldClusterRoleBinding.DeepCopy()
		newClusterRoleBinding.ObjectMeta.OwnerReferences = clusterrolebinding.OwnerReferences
		newClusterRoleBinding.ObjectMeta.Labels = clusterrolebinding.Labels
		newClusterRoleBinding.Subjects = clusterrolebinding.Subjects

		oldClusterRoleBindingJSON, err := json.Marshal(oldClusterRoleBinding)
		if err != nil {
			return fmt.Errorf("Failed to marshal old clusterrole binding object: %v", err)
		}

		newClusterRoleBindingJSON, err := json.Marshal(newClusterRoleBinding)
		if err != nil {
			return fmt.Errorf("Failed to marshal new clusterrole binding object: %v", err)
		}

		patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldClusterRoleBindingJSON, newClusterRoleBindingJSON, auth.ClusterRoleBinding{})
		if err != nil {
			return fmt.Errorf("Failed to create two way merge patch clusterrole binding objects: %v", err)
		}

		if !isEmptyPatch(patchBytes) {
			patchedClusterRoleBinding, err := k.kubeClient.RbacV1().ClusterRoleBindings().Patch(clusterrolebinding.Name, types.StrategicMergePatchType, patchBytes)
			if err != nil {
				return fmt.Errorf("Failed to patch clusterrole binding object: %v", err)
			}

			log.Debugf("Patched clusterrole binding: %s ", patchedClusterRoleBinding.Name)
		} else {
			log.Debugf("No need to patch clusterrole binding: %s ", clusterrolebinding.Name)
		}

		return nil
	}

	if err != nil {
		logger.Errorf("Failed to create clusterRoleBinding: %v", err)
		return err
	}

	logger.Debugf("Created clusterRoleBinding %s", clusterrolebinding.Name)
	return nil
}

// ApplyClusterRoleToServiceAccount Creates cluster-role-binding as a link between role and service account
func (k *Kube) ApplyClusterRoleToServiceAccount(roleName string, serviceAccount *corev1.ServiceAccount, ownerReference []metav1.OwnerReference) error {
	rolebinding := &auth.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("%s-%s", serviceAccount.Namespace, serviceAccount.Name),
			OwnerReferences: ownerReference,
		},
		RoleRef: auth.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     roleName,
		},
		Subjects: []auth.Subject{
			auth.Subject{
				Kind:      "ServiceAccount",
				Name:      serviceAccount.Name,
				Namespace: serviceAccount.Namespace,
			},
		},
	}
	return k.ApplyClusterRoleBinding(rolebinding)
}

func (k *Kube) getRoleBinding(namespace, name string) (*auth.RoleBinding, error) {
	var role *auth.RoleBinding
	var err error

	if k.RoleBindingLister != nil {
		role, err = k.RoleBindingLister.RoleBindings(namespace).Get(name)
		if err != nil {
			return nil, err
		}
	} else {
		role, err = k.kubeClient.RbacV1().RoleBindings(namespace).Get(name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
	}

	return role, nil
}

// ListRoleBindings Lists role bindings from cache or from cluster
func (k *Kube) ListRoleBindings(namespace string) ([]*auth.RoleBinding, error) {
	return k.ListRoleBindingsWithSelector(namespace, nil)
}

// ListRoleBindingsWithSelector Lists role bindings from cache or from cluster using a selector
func (k *Kube) ListRoleBindingsWithSelector(namespace string, labelSelectorString *string) ([]*auth.RoleBinding, error) {
	var roleBindings []*auth.RoleBinding
	var err error

	if k.RoleBindingLister != nil {
		var selector labels.Selector
		if labelSelectorString != nil {
			labelSelector, err := labelHelpers.ParseToLabelSelector(*labelSelectorString)
			if err != nil {
				return nil, err
			}

			selector, err = labelHelpers.LabelSelectorAsSelector(labelSelector)
			if err != nil {
				return nil, err
			}

		} else {
			selector = labels.NewSelector()
		}

		roleBindings, err = k.RoleBindingLister.RoleBindings(namespace).List(selector)
		if err != nil {
			return nil, err
		}
	} else {
		listOptions := metav1.ListOptions{}
		if labelSelectorString != nil {
			listOptions.LabelSelector = *labelSelectorString
		}

		list, err := k.kubeClient.RbacV1().RoleBindings(namespace).List(listOptions)
		if err != nil {
			return nil, err
		}

		roleBindings = slice.PointersOf(list.Items).([]*auth.RoleBinding)
	}

	return roleBindings, nil
}
