package deployment

import (
	"github.com/equinor/radix-operator/pkg/apis/kube"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func (deploy *Deployment) createOrUpdateService(deployComponent v1.RadixCommonDeployComponent) error {
	namespace := deploy.radixDeployment.Namespace
	service := getServiceConfig(deployComponent.GetName(), deploy.radixDeployment, deployComponent.GetPorts())
	return deploy.kubeutil.ApplyService(namespace, service)
}

func (deploy *Deployment) garbageCollectServicesNoLongerInSpec() error {
	services, err := deploy.kubeutil.ListServices(deploy.radixDeployment.GetNamespace())

	for _, service := range services {
		garbageCollect := false
		componentName, ok := NewRadixComponentNameFromLabels(service)
		if !ok {
			continue
		}

		// Garbage collect if service is labelled radix-job-type=job-scheduler and not defined in RD jobs
		if jobType, ok := service.GetLabels()[kube.RadixJobTypeLabel]; ok && jobType == kube.RadixJobTypeJobSchedule {
			garbageCollect = !componentName.ExistInDeploymentSpecJobList(deploy.radixDeployment)
		} else {
			// Garbage collect service if not defined in RD components or jobs
			garbageCollect = !componentName.ExistInDeploymentSpec(deploy.radixDeployment)
		}

		if garbageCollect {
			err = deploy.kubeclient.CoreV1().Services(deploy.radixDeployment.GetNamespace()).Delete(service.Name, &metav1.DeleteOptions{})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func getServiceConfig(componentName string, radixDeployment *v1.RadixDeployment, componentPorts []v1.ComponentPort) *corev1.Service {
	ownerReference := getOwnerReferenceOfDeployment(radixDeployment)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: componentName,
			Labels: map[string]string{
				kube.RadixAppLabel:       radixDeployment.Spec.AppName,
				kube.RadixComponentLabel: componentName,
			},
			OwnerReferences: ownerReference,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				kube.RadixComponentLabel: componentName,
			},
		},
	}

	ports := buildServicePorts(componentPorts)
	service.Spec.Ports = ports

	return service
}

func buildServicePorts(componentPorts []v1.ComponentPort) []corev1.ServicePort {
	var ports []corev1.ServicePort
	for _, v := range componentPorts {
		servicePort := corev1.ServicePort{
			Name:       v.Name,
			Port:       int32(v.Port),
			Protocol:   corev1.ProtocolTCP,
			TargetPort: intstr.FromInt(int(v.Port)),
		}
		ports = append(ports, servicePort)
	}
	return ports
}
