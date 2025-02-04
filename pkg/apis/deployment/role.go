package deployment

import (
	"context"
	"fmt"

	"github.com/equinor/radix-operator/pkg/apis/kube"
	radixv1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	auth "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func roleAppAdminSecrets(registration *radixv1.RadixRegistration, component radixv1.RadixCommonDeployComponent, secretNames []string) *auth.Role {
	roleName := fmt.Sprintf("radix-app-adm-%s", component.GetName())
	return kube.CreateManageSecretRole(registration.Name, roleName, secretNames, map[string]string{kube.RadixComponentLabel: component.GetName()})
}

func (deploy *Deployment) garbageCollectRolesNoLongerInSpecForComponent(component radixv1.RadixCommonDeployComponent) error {
	labelSelector := getLabelSelectorForComponent(component)
	roles, err := deploy.kubeutil.ListRolesWithSelector(deploy.radixDeployment.GetNamespace(), labelSelector)
	if err != nil {
		return err
	}

	if len(roles) > 0 {
		for _, role := range roles {
			err = deploy.kubeclient.RbacV1().Roles(deploy.radixDeployment.GetNamespace()).Delete(context.TODO(), role.Name, metav1.DeleteOptions{})
			if err != nil {
				return err
			}
		}
	}

	return nil
}
