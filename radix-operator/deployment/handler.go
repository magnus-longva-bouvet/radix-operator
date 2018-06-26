package deployment

import (
	"fmt"

	"encoding/json"

	log "github.com/Sirupsen/logrus"
	"github.com/statoil/radix-operator/pkg/apis/radix/v1"
	radixclient "github.com/statoil/radix-operator/pkg/client/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	v1beta1 "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/client-go/kubernetes"
)

type RadixDeployHandler struct {
	kubeclient  kubernetes.Interface
	radixclient radixclient.Interface
}

func NewDeployHandler(kubeclient kubernetes.Interface, radixclient radixclient.Interface) RadixDeployHandler {
	handler := RadixDeployHandler{
		kubeclient:  kubeclient,
		radixclient: radixclient,
	}

	return handler
}

// Init handles any handler initialization
func (t *RadixDeployHandler) Init() error {
	log.Info("RadixDeployHandler.Init")
	return nil
}

// ObjectCreated is called when an object is created
func (t *RadixDeployHandler) ObjectCreated(obj interface{}) error {
	log.Info("Deploy object created received.")
	radixDeploy, ok := obj.(*v1.RadixDeployment)
	if !ok {
		return fmt.Errorf("Provided object was not a valid Radix Deployment; instead was %v", obj)
	}

	log.Infof("Deploy name: %s", radixDeploy.Name)
	log.Infof("Application name: %s", radixDeploy.Spec.AppName)

	radixApplication, err := t.radixclient.RadixV1().RadixApplications(fmt.Sprintf("%s-app", radixDeploy.Spec.AppName)).Get(radixDeploy.Spec.AppName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Failed to get RadixApplication object: %v", err)
	} else {
		log.Infof("RadixApplication %s exists", radixApplication.Name)
	}

	appComponents := radixApplication.Spec.Components
	for _, v := range radixDeploy.Spec.Components {
		for _, w := range appComponents {
			if v.Name != w.Name {
				continue
			}

			// Deploy to current radixDeploy object's namespace
			radixDeployNamespace := radixDeploy.Namespace
			err := t.createDeployment(radixDeploy, v, w, radixDeployNamespace)
			if err != nil {
				return fmt.Errorf("Failed to create deployment: %v", err)
			}
			err = t.createService(radixDeploy, w, radixDeployNamespace)
			if err != nil {
				return fmt.Errorf("Failed to create service: %v", err)
			}
			if w.Public {
				err = t.createIngress(radixDeploy, w, radixDeployNamespace)
				if err != nil {
					return fmt.Errorf("Failed to create ingress: %v", err)
				}
			}
		}
	}
	return nil
}

// ObjectDeleted is called when an object is deleted
func (t *RadixDeployHandler) ObjectDeleted(key string) error {
	log.Info("RadixDeployment object deleted.")
	return nil
}

// ObjectUpdated is called when an object is updated
func (t *RadixDeployHandler) ObjectUpdated(objOld, objNew interface{}) error {
	log.Info("Deploy object updated received.")
	return nil
}

func (t *RadixDeployHandler) createDeployment(radixDeploy *v1.RadixDeployment, deployComponent v1.RadixDeployComponent, appComponent v1.RadixComponent, namespace string) error {
	deployment := getDeploymentConfig(appComponent.Name, radixDeploy.UID, deployComponent.Image, appComponent.Ports, appComponent.Replicas)
	log.Infof("Creating Deployment object %s in namespace %s", appComponent.Name, namespace)
	createdDeployment, err := t.kubeclient.ExtensionsV1beta1().Deployments(namespace).Create(deployment)
	if errors.IsAlreadyExists(err) {
		log.Infof("Deployment object %s already exists in namespace %s, updating the object now", appComponent.Name, namespace)
		updatedDeployment, err := t.kubeclient.ExtensionsV1beta1().Deployments(namespace).Update(deployment)
		if err != nil {
			return fmt.Errorf("Failed to update Deployment object: %v", err)
		}
		log.Infof("Updated Deployment: %s in namespace %s", updatedDeployment.Name, namespace)
		return nil
	}
	if err != nil {
		return fmt.Errorf("Failed to create Deployment object: %v", err)
	}
	log.Infof("Created Deployment: %s in namespace %s", createdDeployment.Name, namespace)
	return nil
}

func (t *RadixDeployHandler) createService(radixDeploy *v1.RadixDeployment, appComponent v1.RadixComponent, namespace string) error {
	service := getServiceConfig(appComponent.Name, radixDeploy.UID, appComponent.Ports)
	log.Infof("Creating Service object %s in namespace %s", appComponent.Name, namespace)
	createdService, err := t.kubeclient.CoreV1().Services(namespace).Create(service)
	if errors.IsAlreadyExists(err) {
		log.Infof("Service object %s already exists in namespace %s, updating the object now", appComponent.Name, namespace)
		oldService, err := t.kubeclient.CoreV1().Services(namespace).Get(appComponent.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("Failed to get old Service object: %v", err)
		}
		newService := oldService.DeepCopy()
		ports := buildServicePorts(appComponent.Ports)
		newService.Spec.Ports = ports

		oldServiceJson, err := json.Marshal(oldService)
		if err != nil {
			return fmt.Errorf("Failed to marshal old Service object: %v", err)
		}

		newServiceJson, err := json.Marshal(newService)
		if err != nil {
			return fmt.Errorf("Failed to marshal new Service object: %v", err)
		}

		patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldServiceJson, newServiceJson, corev1.Service{})
		if err != nil {
			return fmt.Errorf("Failed to create two way merge patch Service objects: %v", err)
		}

		patchedService, err := t.kubeclient.CoreV1().Services(namespace).Patch(appComponent.Name, types.StrategicMergePatchType, patchBytes)
		if err != nil {
			return fmt.Errorf("Failed to patch Service object: %v", err)
		}
		log.Infof("Patched Service: %s in namespace %s", patchedService.Name, namespace)
		return nil
	}
	if err != nil {
		return fmt.Errorf("Failed to create Service object: %v", err)
	}
	log.Infof("Created Service: %s in namespace %s", createdService.Name, namespace)
	return nil
}

func (t *RadixDeployHandler) createIngress(radixDeploy *v1.RadixDeployment, appComponent v1.RadixComponent, namespace string) error {
	ingress := getIngressConfig(appComponent.Name, radixDeploy.Spec.AppName, namespace, radixDeploy.UID, appComponent.Ports)
	log.Infof("Creating Ingress object %s in namespace %s", appComponent.Name, namespace)
	createdIngress, err := t.kubeclient.ExtensionsV1beta1().Ingresses(namespace).Create(ingress)
	if errors.IsAlreadyExists(err) {
		log.Infof("Ingress object %s already exists in namespace %s, updating the object now", appComponent.Name, namespace)
		updatedIngress, err := t.kubeclient.ExtensionsV1beta1().Ingresses(namespace).Update(ingress)
		if err != nil {
			return fmt.Errorf("Failed to update Ingress object: %v", err)
		}
		log.Infof("Updated Ingress: %s in namespace %s", updatedIngress.Name, namespace)
		return nil
	}
	if err != nil {
		return fmt.Errorf("Failed to create Ingress object: %v", err)
	}
	log.Infof("Created Ingress: %s in namespace %s", createdIngress.Name, namespace)
	return nil
}

func getDeploymentConfig(componentName string, uid types.UID, image string, componentPorts []int, replicas int) *v1beta1.Deployment {
	trueVar := true
	deployment := &v1beta1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: componentName,
			Labels: map[string]string{
				"radixApp": componentName,
			},
			OwnerReferences: []metav1.OwnerReference{
				metav1.OwnerReference{
					APIVersion: "radix.equinor.com/v1", //need to hardcode these values for now - seems they are missing from the CRD in k8s 1.8
					Kind:       "RadixDeployment",
					Name:       componentName,
					UID:        uid,
					Controller: &trueVar,
				},
			},
		},
		Spec: v1beta1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"radixApp": componentName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"radixApp": componentName,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  componentName,
							Image: image,
						},
					},
					ImagePullSecrets: []corev1.LocalObjectReference{
						{
							Name: "radix-docker",
						},
					},
				},
			},
		},
	}

	var ports []corev1.ContainerPort
	for _, v := range componentPorts {
		containerPort := corev1.ContainerPort{
			ContainerPort: int32(v),
		}
		ports = append(ports, containerPort)
	}
	deployment.Spec.Template.Spec.Containers[0].Ports = ports

	if replicas > 0 {
		deployment.Spec.Replicas = int32Ptr(int32(replicas))
	}

	return deployment
}

func getServiceConfig(componentName string, uid types.UID, componentPorts []int) *corev1.Service {
	trueVar := true
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: componentName,
			Labels: map[string]string{
				"radixApp": componentName,
			},
			OwnerReferences: []metav1.OwnerReference{
				metav1.OwnerReference{
					APIVersion: "radix.equinor.com/v1", //need to hardcode these values for now - seems they are missing from the CRD in k8s 1.8
					Kind:       "RadixDeployment",
					Name:       componentName,
					UID:        uid,
					Controller: &trueVar,
				},
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"radixApp": componentName,
			},
		},
	}

	ports := buildServicePorts(componentPorts)
	service.Spec.Ports = ports

	return service
}

func getIngressConfig(componentName, appName, namespace string, uid types.UID, componentPorts []int) *v1beta1.Ingress {
	trueVar := true
	ingress := &v1beta1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name: componentName,
			Annotations: map[string]string{
				// "kubernetes.io/tls-acme":         "true",
				"kubernetes.io/ingress.class": "nginx",
			},
			Labels: map[string]string{
				"radixApp": appName,
			},
			OwnerReferences: []metav1.OwnerReference{
				metav1.OwnerReference{
					APIVersion: "radix.equinor.com/v1", //need to hardcode these values for now - seems they are missing from the CRD in k8s 1.8
					Kind:       "RadixDeployment",
					Name:       componentName,
					UID:        uid,
					Controller: &trueVar,
				},
			},
		},
		Spec: v1beta1.IngressSpec{
			// TLS: []v1beta1.IngressTLS{
			// 	{
			// 		SecretName: "domain-ssl-cert-key",
			// 	},
			// },
			TLS: []v1beta1.IngressTLS{
				{
					Hosts: []string{
						fmt.Sprintf("%s-%s.dev.radix.equinor.com", componentName, namespace),
					},
					SecretName: "domain-ssl-cert-key",
				},
			},
			Rules: []v1beta1.IngressRule{
				{
					Host: fmt.Sprintf("%s-%s.dev.radix.equinor.com", componentName, namespace),
					IngressRuleValue: v1beta1.IngressRuleValue{
						HTTP: &v1beta1.HTTPIngressRuleValue{
							Paths: []v1beta1.HTTPIngressPath{
								{
									Path: "/",
									Backend: v1beta1.IngressBackend{
										ServiceName: componentName,
										ServicePort: intstr.IntOrString{
											IntVal: int32(componentPorts[0]),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	return ingress
}

func buildServicePorts(componentPorts []int) []corev1.ServicePort {
	var ports []corev1.ServicePort
	for _, v := range componentPorts {
		servicePort := corev1.ServicePort{
			Port: int32(v),
		}
		ports = append(ports, servicePort)
	}
	return ports
}

func int32Ptr(i int32) *int32 {
	return &i
}
