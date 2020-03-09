package environment

import (
	"fmt"

	"github.com/equinor/radix-operator/radix-operator/common"

	"github.com/equinor/radix-operator/pkg/apis/environment"
	"github.com/equinor/radix-operator/pkg/apis/kube"
	radixclient "github.com/equinor/radix-operator/pkg/client/clientset/versioned"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
)

const (
	// SuccessSynced is used as part of the Event 'reason' when a Environment is synced
	SuccessSynced = "Synced"

	// MessageResourceSynced is the message used for an Event fired when a Environment
	// is synced successfully
	MessageResourceSynced = "Radix Environment synced successfully"
)

// Handler Handler for radix environments
type Handler struct {
	kubeclient  kubernetes.Interface
	kubeutil    *kube.Kube
	radixclient radixclient.Interface
	hasSynced   common.HasSynced
}

// NewHandler creates a handler for managing RadixEnvironment resources
func NewHandler(
	kubeclient kubernetes.Interface,
	kubeutil *kube.Kube,
	radixclient radixclient.Interface,
	hasSynced common.HasSynced) Handler {

	handler := Handler{
		kubeclient:  kubeclient,
		kubeutil:    kubeutil,
		radixclient: radixclient,
		hasSynced:   hasSynced,
	}

	return handler
}

// Sync is called by kubernetes after the Controller Enqueues a work-item
// and collects components and determines whether state must be reconciled.
func (t *Handler) Sync(namespace, name string, eventRecorder record.EventRecorder) error {
	envConfig, err := t.radixclient.RadixV1().RadixEnvironments().Get(name, metav1.GetOptions{})
	if err != nil {
		// The Environment resource may no longer exist, in which case we stop
		// processing.
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("Radix environment '%s' in work queue no longer exists", name))
			return nil
		}

		return err
	}

	syncEnvironment := envConfig.DeepCopy()
	logger.Debugf("Sync environment %s", syncEnvironment.Name)

	radixRegistration, err := t.kubeutil.GetRegistration(envConfig.Spec.AppName)
	if err != nil {
		// The Registration resource may no longer exist, in which case we stop
		// processing.
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("Failed to get RadixRegistartion object: %v", err))
			return nil
		}

		return err
	}

	env, err := environment.NewEnvironment(t.kubeclient, t.kubeutil, t.radixclient, envConfig, radixRegistration)
	if err != nil {
		return err
	}

	err = env.OnSync()
	if err != nil {
		return err
	}

	t.hasSynced(true)
	eventRecorder.Event(syncEnvironment, core.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}
