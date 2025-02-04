package registration

import (
	"fmt"

	"github.com/equinor/radix-operator/radix-operator/common"

	"github.com/equinor/radix-operator/pkg/apis/application"
	"github.com/equinor/radix-operator/pkg/apis/kube"
	radixclient "github.com/equinor/radix-operator/pkg/client/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
)

const (
	// SuccessSynced is used as part of the Event 'reason' when a Registration is synced
	SuccessSynced = "Synced"

	// MessageResourceSynced is the message used for an Event fired when a Registration
	// is synced successfully
	MessageResourceSynced = "Radix Registration synced successfully"
)

// Handler Handler for radix registrations
type Handler struct {
	kubeclient  kubernetes.Interface
	kubeutil    *kube.Kube
	radixclient radixclient.Interface
	hasSynced   common.HasSynced

	// Function for granting access to machine user cannot be tested
	granter application.GranterFunction
}

//NewHandler creates a handler which deals with RadixRegistration resources
func NewHandler(
	kubeclient kubernetes.Interface,
	kubeutil *kube.Kube,
	radixclient radixclient.Interface,
	hasSynced common.HasSynced,
	granter application.GranterFunction) Handler {

	handler := Handler{
		kubeclient:  kubeclient,
		kubeutil:    kubeutil,
		radixclient: radixclient,
		hasSynced:   hasSynced,
		granter:     granter,
	}

	return handler
}

// Sync Is created on sync of resource
func (t *Handler) Sync(namespace, name string, eventRecorder record.EventRecorder) error {
	registration, err := t.kubeutil.GetRegistration(name)
	if err != nil {
		// The Registration resource may no longer exist, in which case we stop
		// processing.
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("radix registration %s in work queue no longer exists", name))
			return nil
		}

		return err
	}

	syncRegistration := registration.DeepCopy()
	logger.Debugf("Sync registration %s", syncRegistration.Name)
	application, _ := application.NewApplication(t.kubeclient, t.kubeutil, t.radixclient, syncRegistration)
	err = application.OnSyncWithGranterToMachineUserToken(t.granter)
	if err != nil {
		// Put back on queue.
		return err
	}

	t.hasSynced(true)
	eventRecorder.Event(syncRegistration, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}
