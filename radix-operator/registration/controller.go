package registration

import (
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	radixclient "github.com/equinor/radix-operator/pkg/client/clientset/versioned"
	radixinformer "github.com/equinor/radix-operator/pkg/client/informers/externalversions/radix/v1"
	"github.com/equinor/radix-operator/radix-operator/common"
	log "github.com/sirupsen/logrus"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

var logger *log.Entry

const controllerAgentName = "registration-controller"

func init() {
	logger = log.WithFields(log.Fields{"radixOperatorComponent": "registration-controller"})
}

//NewController creates a new controller that handles RadixRegistrations
func NewController(client kubernetes.Interface,
	radixClient radixclient.Interface, handler common.Handler,
	registrationInformer radixinformer.RadixRegistrationInformer,
	namespaceInformer coreinformers.NamespaceInformer) *common.Controller {

	recorder := common.NewEventRecorder(controllerAgentName, client.CoreV1().Events(""))

	controller := &common.Controller{
		Name:        controllerAgentName,
		KubeClient:  client,
		RadixClient: radixClient,
		Informer:    registrationInformer.Informer(),
		WorkQueue:   workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "RadixRegistrations"),
		Handler:     handler,
		Log:         logger,
		Recorder:    recorder,
	}

	klog.Info("Setting up event handlers")

	registrationInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.Enqueue,
		UpdateFunc: func(old, new interface{}) {
			controller.Enqueue(new)
		},
		DeleteFunc: func(obj interface{}) {
			radixRegistration, _ := obj.(*v1.RadixRegistration)
			key, err := cache.MetaNamespaceKeyFunc(radixRegistration)
			if err == nil {
				logger.Infof("Registration object deleted event received for %s. Do nothing", key)
			}
		},
	})

	return controller
}
