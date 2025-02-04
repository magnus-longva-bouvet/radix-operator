package deployment

import (
	"context"
	"fmt"
	"reflect"

	radixutils "github.com/equinor/radix-common/utils"
	"github.com/equinor/radix-operator/pkg/apis/deployment"
	"github.com/equinor/radix-operator/pkg/apis/kube"
	"github.com/equinor/radix-operator/pkg/apis/metrics"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	radixclient "github.com/equinor/radix-operator/pkg/client/clientset/versioned"
	informers "github.com/equinor/radix-operator/pkg/client/informers/externalversions"
	"github.com/equinor/radix-operator/radix-operator/common"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
)

var logger *log.Entry

const (
	controllerAgentName = "deployment-controller"
	crType              = "RadixDeployments"
)

func init() {
	logger = log.WithFields(log.Fields{"radixOperatorComponent": controllerAgentName})
}

// NewController creates a new controller that handles RadixDeployments
func NewController(client kubernetes.Interface,
	radixClient radixclient.Interface,
	handler common.Handler,
	kubeInformerFactory kubeinformers.SharedInformerFactory,
	radixInformerFactory informers.SharedInformerFactory,
	waitForChildrenToSync bool,
	recorder record.EventRecorder) *common.Controller {

	deploymentInformer := radixInformerFactory.Radix().V1().RadixDeployments()
	serviceInformer := kubeInformerFactory.Core().V1().Services()
	registrationInformer := radixInformerFactory.Radix().V1().RadixRegistrations()

	controller := &common.Controller{
		Name:                  controllerAgentName,
		HandlerOf:             crType,
		KubeClient:            client,
		RadixClient:           radixClient,
		Informer:              deploymentInformer.Informer(),
		KubeInformerFactory:   kubeInformerFactory,
		WorkQueue:             workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), crType),
		Handler:               handler,
		Log:                   logger,
		WaitForChildrenToSync: waitForChildrenToSync,
		Recorder:              recorder,
		LockKeyAndIdentifier:  common.NamespacePartitionKey,
	}

	logger.Info("Setting up event handlers")
	deploymentInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(cur interface{}) {
			radixDeployment, _ := cur.(*v1.RadixDeployment)
			if deployment.IsRadixDeploymentInactive(radixDeployment) {
				logger.Debugf("Skip deployment object %s as it is inactive", radixDeployment.GetName())
				metrics.CustomResourceAddedButSkipped(crType)
				return
			}

			controller.Enqueue(cur)
			metrics.CustomResourceAdded(crType)
		},
		UpdateFunc: func(old, cur interface{}) {
			newRD := cur.(*v1.RadixDeployment)
			oldRD := old.(*v1.RadixDeployment)
			if deployment.IsRadixDeploymentInactive(newRD) {
				logger.Debugf("Skip deployment object %s as it is inactive", newRD.GetName())
				metrics.CustomResourceUpdatedButSkipped(crType)
				return
			}

			if deepEqual(oldRD, newRD) {
				logger.Debugf("Deployment object is equal to old for %s. Do nothing", newRD.GetName())
				metrics.CustomResourceUpdatedButSkipped(crType)
				return
			}

			controller.Enqueue(cur)
			metrics.CustomResourceUpdated(crType)
		},
		DeleteFunc: func(obj interface{}) {
			radixDeployment, converted := obj.(*v1.RadixDeployment)
			if !converted {
				logger.Errorf("RadixDeployment object cast failed during deleted event received.")
				return
			}
			key, err := cache.MetaNamespaceKeyFunc(radixDeployment)
			if err == nil {
				logger.Debugf("Deployment object deleted event received for %s. Do nothing", key)
			}
			metrics.CustomResourceDeleted(crType)
		},
	})

	// Only the service informer works with this, because it makes use of patch
	// if not it will end up in an endless loop (deployment, ingress etc.)
	serviceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			service := obj.(*corev1.Service)
			logger.Debugf("Service object added event received for %s. Do nothing", service.Name)
		},
		UpdateFunc: func(old, cur interface{}) {
			newService := cur.(*corev1.Service)
			oldService := old.(*corev1.Service)
			if newService.ResourceVersion == oldService.ResourceVersion {
				return
			}
			controller.HandleObject(cur, "RadixDeployment", getObject)
		},
		DeleteFunc: func(obj interface{}) {
			controller.HandleObject(obj, "RadixDeployment", getObject)
		},
	})

	registrationInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, cur interface{}) {
			newRr := cur.(*v1.RadixRegistration)
			oldRr := old.(*v1.RadixRegistration)
			if newRr.ResourceVersion == oldRr.ResourceVersion {
				return
			}

			// If neither ad group did change, nor the machine user, this
			// does not affect the deployment
			if radixutils.ArrayEqualElements(newRr.Spec.AdGroups, oldRr.Spec.AdGroups) &&
				newRr.Spec.MachineUser == oldRr.Spec.MachineUser {
				return
			}

			// Trigger sync of active RD, living in the namespaces of the app
			rds, err := radixClient.RadixV1().RadixDeployments(corev1.NamespaceAll).List(
				context.TODO(),
				metav1.ListOptions{
					LabelSelector: fmt.Sprintf("%s=%s", kube.RadixAppLabel, newRr.Name),
				})

			if err == nil && len(rds.Items) > 0 {
				// Will sync the active RD (there can only be one within each namespace)
				for _, rd := range rds.Items {
					if !deployment.IsRadixDeploymentInactive(&rd) {
						obj := &rd
						controller.Enqueue(obj)
					}
				}
			}
		},
	})

	return controller
}

func deepEqual(old, new *v1.RadixDeployment) bool {
	if !reflect.DeepEqual(new.Spec, old.Spec) ||
		!reflect.DeepEqual(new.ObjectMeta.Labels, old.ObjectMeta.Labels) ||
		!reflect.DeepEqual(new.ObjectMeta.Annotations, old.ObjectMeta.Annotations) {
		return false
	}

	return true
}

func getObject(radixClient radixclient.Interface, namespace, name string) (interface{}, error) {
	return radixClient.RadixV1().RadixDeployments(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}
