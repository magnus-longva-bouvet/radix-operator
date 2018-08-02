package kube

import (
	"fmt"

	log "github.com/Sirupsen/logrus"
	radixv1 "github.com/statoil/radix-operator/pkg/apis/radix/v1"
	auth "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (k *Kube) CreateRoleBindings(app *radixv1.RadixApplication) error {
	for _, env := range app.Spec.Environments {
		for _, auth := range env.Authorization {
			err := k.CreateRoleBinding(app.Name, fmt.Sprintf("%s-%s", app.Name, env.Name), auth.Role, auth.Groups)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (k *Kube) CreateRoleBinding(appName, namespace, clusterrole string, groups []string) error {
	subjects := []auth.Subject{}
	for _, group := range groups {
		subjects = append(subjects, auth.Subject{
			Kind:     "Group",
			Name:     group,
			APIGroup: "rbac.authorization.k8s.io",
		})
	}

	rolebinding := &auth.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "RoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%s", appName, clusterrole),
			Labels: map[string]string{
				"radixApp": appName,
			},
		},
		RoleRef: auth.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterrole,
		},
		Subjects: subjects,
	}

	_, err := k.kubeClient.RbacV1().RoleBindings(namespace).Create(rolebinding)
	if errors.IsAlreadyExists(err) {
		log.Infof("Rolebinding %s already exists", rolebinding.Name)
		return nil
	}

	if err != nil {
		log.Errorf("Failed to create rolebinding in [%s] for %s: %v", namespace, appName, err)
		return err
	}

	log.Infof("Created rolebinding %s in %s", rolebinding.Name, namespace)
	return nil
}

// TODO
func (k *Kube) SetAccessOnRadixRegistration(registration *radixv1.RadixRegistration) error {
	appName := registration.Name
	groups := registration.Spec.AdGroups
	trueVar := true

	subjects := []auth.Subject{}
	for _, group := range groups {
		subjects = append(subjects, auth.Subject{
			Kind:     "Group",
			Name:     group,
			APIGroup: "rbac.authorization.k8s.io",
		})
	}

	role := &auth.Role{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "Role",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("operator-%s", appName),
			Labels: map[string]string{
				"radixReg": appName,
			},
			OwnerReferences: []metav1.OwnerReference{
				metav1.OwnerReference{
					APIVersion: "radix.equinor.com/v1", //need to hardcode these values for now - seems they are missing from the CRD in k8s 1.8
					Kind:       "RadixRegistration",
					Name:       fmt.Sprintf("operator-%s", appName),
					UID:        registration.UID,
					Controller: &trueVar,
				},
			},
		},
		Rules: []auth.PolicyRule{
			{
				APIGroups:     []string{"radix.equinor.com"},
				Resources:     []string{"radixregistrations"},
				ResourceNames: []string{appName},
				Verbs:         []string{"get", "update", "patch", "delete"},
			},
		},
	}

	rolebinding := &auth.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "RoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("operator-%s-binding", appName),
			Labels: map[string]string{
				"radixReg": appName,
			},
			OwnerReferences: []metav1.OwnerReference{
				metav1.OwnerReference{
					APIVersion: "radix.equinor.com/v1", //need to hardcode these values for now - seems they are missing from the CRD in k8s 1.8
					Kind:       "RadixRegistration",
					Name:       fmt.Sprintf("operator-%s-binding", appName),
					UID:        registration.UID,
					Controller: &trueVar,
				},
			},
		},
		RoleRef: auth.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     fmt.Sprintf("operator-%s", appName),
		},
		Subjects: subjects,
	}

	log.Infof("Creating role %s", role.Name)
	_, err := k.kubeClient.RbacV1().Roles("default").Create(role)
	if err != nil {
		log.Infof("Creating role %s failed: %v", role.Name, err)
		return nil
	}

	log.Infof("Creating rolebinding %s", rolebinding.Name)
	_, err = k.kubeClient.RbacV1().RoleBindings("default").Create(rolebinding)
	if err != nil {
		log.Infof("Creating rolebinding %s failed: %v", rolebinding.Name, err)
		return nil
	}

	return nil
}
