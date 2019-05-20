package common

import (
	"fmt"
	"time"

	radixclient "github.com/equinor/radix-operator/pkg/client/clientset/versioned"
	radixscheme "github.com/equinor/radix-operator/pkg/client/clientset/versioned/scheme"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
)

var (
	nrCrAdded = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "radix_operator_cr_added",
		Help: "The total number of radix custom resources added",
	}, []string{"cr_type"})
	nrCrDeleted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "radix_operator_cr_deleted",
		Help: "The total number of radix custom resources deleted",
	}, []string{"cr_type"})
	nrErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "radix_operator_errors",
		Help: "The total number of radix operator errors",
	}, []string{"err_type", "method"})
)

// GetOwner Function pointer to pass to retrieve owner
type GetOwner func(radixclient.Interface, string, string) (interface{}, error)

// Controller Instance variables
type Controller struct {
	Name        string
	KubeClient  kubernetes.Interface
	RadixClient radixclient.Interface
	WorkQueue   workqueue.RateLimitingInterface
	Informer    cache.SharedIndexInformer
	Handler     Handler
	Log         *log.Entry
	Recorder    record.EventRecorder
}

// NewEventRecorder Creates an event recorder for controller
func NewEventRecorder(controllerAgentName string, events typedcorev1.EventInterface, logger *log.Entry) record.EventRecorder {
	radixscheme.AddToScheme(scheme.Scheme)
	logger.Info("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(logger.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: events})
	return eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})
}

// Run starts the shared informer, which will be stopped when stopCh is closed.
func (c *Controller) Run(threadiness int, stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	defer c.WorkQueue.ShutDown()

	// Start the informer factories to begin populating the informer caches
	c.Log.Debugf("Starting %s", c.Name)

	// Wait for the caches to be synced before starting workers
	c.Log.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, c.hasSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	c.Log.Info("Starting workers")
	// Launch workers to process resources
	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	c.Log.Info("Started workers")
	<-stopCh
	c.Log.Info("Shutting down workers")

	return nil
}

func (c *Controller) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	obj, shutdown := c.WorkQueue.Get()

	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer c.WorkQueue.Done(obj)
		var key string
		var ok bool

		if key, ok = obj.(string); !ok {
			c.WorkQueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			nrErrors.With(prometheus.Labels{
				"method":   "work_queue",
				"err_type": "error_workqueue_type",
			}).Inc()
			return nil
		}

		if err := c.syncHandler(key); err != nil {
			c.WorkQueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}

		c.WorkQueue.Forget(obj)
		c.Log.Infof("Successfully synced '%s'", key)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		nrErrors.With(prometheus.Labels{"method": "process_next_work_item", "err_type": "unhandled"}).Inc()
		return true
	}

	return true
}

func (c *Controller) syncHandler(key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Invalid resource key: %s", key))
		nrErrors.With(prometheus.Labels{
			"method":   "split_meta_namespace_key",
			"err_type": "invalid_resource_key"},
		).Inc()
		return nil
	}

	err = c.Handler.Sync(namespace, name, c.Recorder)
	if err != nil {
		// DEBUG
		log.Errorf("Error while syncing: %v", err)

		utilruntime.HandleError(fmt.Errorf("Problems syncing: %s", key))
		nrErrors.With(prometheus.Labels{
			"method":   "c_handler_sync",
			"err_type": fmt.Sprintf("problems_sync_%s", key)},
		).Inc()
		return err
	}

	return nil
}

// Enqueue takes a resource and converts it into a namespace/name
// string which is then put onto the work queue
func (c *Controller) Enqueue(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		nrErrors.With(prometheus.Labels{
			"method":   "enqueue",
			"err_type": fmt.Sprintf("problems_sync_%s", key)},
		).Inc()
		return
	}
	c.WorkQueue.AddRateLimited(key)
}

// HandleObject ensures that when anything happens to object which any
// custom resouce is owner of, that custom resource is synced
func (c *Controller) HandleObject(obj interface{}, ownerKind string, getOwnerFn GetOwner) {
	var object metav1.Object
	var ok bool
	if object, ok = obj.(metav1.Object); !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object, invalid type"))
			nrErrors.With(prometheus.Labels{
				"method":   "handle_object",
				"err_type": "error_decoding_object",
			}).Inc()
			return
		}
		object, ok = tombstone.Obj.(metav1.Object)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object tombstone, invalid type"))
			nrErrors.With(prometheus.Labels{
				"method":   "handle_object",
				"err_type": "error_decoding_object_tombstone",
			}).Inc()
			return
		}
		c.Log.Infof("Recovered deleted object '%s' from tombstone", object.GetName())
	}
	c.Log.Infof("Processing object: %s", object.GetName())
	if ownerRef := metav1.GetControllerOf(object); ownerRef != nil {
		if ownerRef.Kind != ownerKind {
			return
		}

		obj, err := getOwnerFn(c.RadixClient, object.GetNamespace(), ownerRef.Name)
		if err != nil {
			c.Log.Infof("Ignoring orphaned object '%s' of %s '%s'", object.GetSelfLink(), ownerKind, ownerRef.Name)
			return
		}

		c.Enqueue(obj)
		return
	}
}

func (c *Controller) CustomResourceAdded(kind string) {
	nrCrAdded.With(prometheus.Labels{"cr_type": kind}).Inc()
}

func (c *Controller) CustomResourceDeleted(kind string) {
	nrCrDeleted.With(prometheus.Labels{"cr_type": kind}).Inc()
}

func (c *Controller) hasSynced() bool {
	return c.Informer.HasSynced()
}
