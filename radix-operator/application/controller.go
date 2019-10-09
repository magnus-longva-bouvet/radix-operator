package application

import (
	"github.com/equinor/radix-operator/pkg/apis/kube"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	radixclient "github.com/equinor/radix-operator/pkg/client/clientset/versioned"
	radixinformer "github.com/equinor/radix-operator/pkg/client/informers/externalversions/radix/v1"
	"github.com/equinor/radix-operator/radix-operator/common"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
)

// Controller Instance variables
type Controller struct {
	clientset   kubernetes.Interface
	radixclient radixclient.Interface
	queue       workqueue.RateLimitingInterface
	informer    cache.SharedIndexInformer
	handler     common.Handler
}

var logger *log.Entry

const (
	controllerAgentName = "application-controller"
	crType              = "RadixApplications"
)

func init() {
	logger = log.WithFields(log.Fields{"radixOperatorComponent": controllerAgentName})
}

// NewController creates a new controller that handles RadixApplications
func NewController(client kubernetes.Interface,
	radixClient radixclient.Interface, handler common.Handler,
	applicationInformer radixinformer.RadixApplicationInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	recorder record.EventRecorder) *common.Controller {

	controller := &common.Controller{
		Name:        controllerAgentName,
		KubeClient:  client,
		RadixClient: radixClient,
		Informer:    applicationInformer.Informer(),
		WorkQueue:   workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), crType),
		Handler:     handler,
		Log:         logger,
		Recorder:    recorder,
	}

	logger.Info("Setting up event handlers")
	applicationInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(cur interface{}) {
			controller.Enqueue(cur)
			controller.CustomResourceAdded(crType)
		},
		UpdateFunc: func(old, cur interface{}) {
			controller.Enqueue(cur)
		},
		DeleteFunc: func(obj interface{}) {
			radixApplication, _ := obj.(*v1.RadixApplication)
			key, err := cache.MetaNamespaceKeyFunc(radixApplication)
			if err == nil {
				logger.Debugf("Application object deleted event received for %s. Do nothing", key)
			}
			controller.CustomResourceDeleted(crType)
		},
	})

	namespaceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, cur interface{}) {
			newNs := cur.(*corev1.Namespace)
			oldNs := old.(*corev1.Namespace)
			if newNs.ResourceVersion == oldNs.ResourceVersion {
				return
			}

			if newNs.Annotations[kube.AdGroupsAnnotation] == oldNs.Annotations[kube.AdGroupsAnnotation] {
				return
			}

			// Trigger sync of RA, living in the namespace
			ra, err := radixClient.RadixV1().RadixApplications(newNs.Name).List(metav1.ListOptions{})
			if err == nil && len(ra.Items) == 1 {
				// Will sync the RA (there can only be one)
				var obj metav1.Object
				obj = &ra.Items[0]
				controller.Enqueue(obj)
			}
		},
	})

	return controller
}
